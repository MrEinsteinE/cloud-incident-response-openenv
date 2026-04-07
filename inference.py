"""
inference.py — Cloud Incident Response OpenEnv baseline inference script.

The LLM reasons from evidence. Fallback is a dumb safety net that scores low.
Override only blocks clearly invalid actions (wrong task submission, bad params).

STRUCTURED OUTPUT:
  [START] task=<task_name> env=cloud-incident-response model=<model_name>
  [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
  [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
"""

from __future__ import annotations

import json
import os
import sys
import time

import requests
import time as _time
_START_TIME = _time.time()
_MAX_RUNTIME = 1080

def _check_timeout():
    if _time.time() - _START_TIME > _MAX_RUNTIME:
        raise RuntimeError("Approaching 20min limit — stopping early")
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── Config ──────────────────────────────────────────────────────────────────
API_BASE_URL = os.environ.get("API_BASE_URL", "https://api.groq.com/openai/v1")
MODEL_NAME   = os.environ.get("MODEL_NAME",   "llama-3.1-8b-instant")
API_KEY = os.environ.get("HF_TOKEN") or os.environ.get("API_KEY") or ""
ENV_BASE_URL = os.environ.get("ENV_BASE_URL", "http://localhost:7860")
ENV_NAME = "cloud-incident-response"

if not API_KEY:
    print("[WARN] No API key set — LLM calls will fail.", file=sys.stderr)

_session = requests.Session()
_client = None


def _get_client():
    global _client
    if _client is None:
        from openai import OpenAI
        _client = OpenAI(api_key=API_KEY, base_url=API_BASE_URL)
    return _client


# ── Constants ───────────────────────────────────────────────────────────────
_TASK_SUBMIT = {
    "alert_classification":  "submit_severity",
    "root_cause_analysis":   "submit_root_cause",
    "remediation_planning":  "submit_resolution",
}

_DIAG_TYPES = frozenset({
    "query_logs", "check_metrics", "check_dependencies",
    "check_recent_deploys", "check_service_status",
})

_SUBMIT_TYPES = frozenset({
    "submit_severity", "submit_root_cause", "submit_resolution",
})

_REM_TYPES = frozenset({
    "restart_service", "rollback_deploy", "scale_service",
    "disable_feature_flag", "clear_cache", "execute_runbook_step",
})

_ALL_VALID = _DIAG_TYPES | _SUBMIT_TYPES | _REM_TYPES


SYSTEM_PROMPT = """\
You are an expert Site Reliability Engineer responding to a production incident.
Reply with exactly ONE JSON action object. No markdown, no explanation, no extra text.

VALID ACTIONS:
{"action_type":"query_logs","parameters":{"service":"<name>"}}
{"action_type":"check_metrics","parameters":{"service":"<name>"}}
{"action_type":"check_dependencies","parameters":{"service":"<name>"}}
{"action_type":"check_recent_deploys","parameters":{"service":"<name>"}}
{"action_type":"check_service_status","parameters":{"service":"<name>"}}
{"action_type":"restart_service","parameters":{"service":"<name>"}}
{"action_type":"rollback_deploy","parameters":{"service":"<name>","target_version":"previous"}}
{"action_type":"disable_feature_flag","parameters":{"flag":"<flag_name>"}}
{"action_type":"execute_runbook_step","parameters":{"runbook_action":"<action>"}}
{"action_type":"submit_severity","parameters":{"severity":"P1|P2|P3|P4","service":"<name>"}}
{"action_type":"submit_root_cause","parameters":{"service":"<name>","failure_mode":"<description>"}}
{"action_type":"submit_resolution","parameters":{"summary":"<3+ sentence summary>"}}

RULES:
- Service names MUST exactly match the KNOWN_SERVICES list.
- P1 = complete outage OR revenue > $1,000/min.  P2 = major degradation.
  P3 = minor/partial issue with graceful fallback.  P4 = informational.
- IMPORTANT: check_recent_deploys and check_dependencies require prior
  investigation. You MUST query_logs or check_metrics on a service BEFORE
  checking its deploys or dependencies. Otherwise you get limited data.
- Root cause = the upstream service that TRIGGERED the cascade. Often NOT
  in the alert's affected_services list.
- submit_resolution summary: 3+ sentences about what failed, what you did, status.
- Submit as soon as evidence is clear — do NOT waste steps.

STRATEGY:

alert_classification (max 3 steps):
  Query 1-2 services with logs/metrics, then submit_severity.
  Check revenue_impact and error_rate carefully. Not all high error rates are P1.

root_cause_analysis (max 10 steps):
  1. query_logs or check_metrics on 2-3 services to understand the blast radius
  2. THEN check_recent_deploys on services that look suspicious
  3. Look for the service whose deploy/change CAUSED the cascade
  4. Submit submit_root_cause with service and failure_mode

remediation_planning (max 15 steps):
  1. query_logs on affected services to confirm root cause
  2. Execute remediation actions in logical order
  3. Verify recovery with check_service_status
  4. Submit submit_resolution with detailed summary

CRITICAL: Each task has ONE correct submission action:
  alert_classification  -> submit_severity
  root_cause_analysis   -> submit_root_cause
  remediation_planning  -> submit_resolution"""


# ── Helpers ─────────────────────────────────────────────────────────────────

def _queried_svcs(queried_data: dict) -> set[str]:
    return {
        svc
        for at, svcs in queried_data.items()
        if at in _DIAG_TYPES and isinstance(svcs, dict)
        for svc in svcs
    }


def _extract_signals(queried_data: dict) -> list[str]:
    seen: set[str] = set()
    signals: list[str] = []

    def _add(msg: str) -> None:
        if msg not in seen:
            seen.add(msg)
            signals.append(msg)

    for action_type, services in queried_data.items():
        if not isinstance(services, dict):
            continue
        for svc, data in services.items():
            t = str(data).lower()
            if "out of memory" in t or "oom" in t:
                _add(f"OOM detected in {svc}")
            if "bgp" in t and ("withdrawal" in t or "withdrawn" in t):
                _add(f"BGP route issue in {svc}")
            if "pool" in t and ("exhaust" in t or "too many clients" in t):
                _add(f"Connection pool issue in {svc}")
            if "cache" in t and ("purge" in t or "invalidat" in t):
                _add(f"Cache purge in {svc}")
            if "unbounded" in t or "no limit" in t:
                _add(f"Unbounded query in {svc}")
            if "credential" in t or "password" in t or "authentication failed" in t:
                _add(f"Credential/auth issue in {svc}")
            if "requires deeper investigation" in t or "requires initial investigation" in t:
                _add(f"GATED: {svc} needs logs/metrics first before checking deploys")
            if action_type == "check_recent_deploys" and any(
                x in t for x in ("ago", "change", "update", "added", "deploy")
            ):
                if "requires" not in t:  # Don't show gated responses as signals
                    snippet = str(data)[:120].replace("\n", " ")
                    _add(f"Recent change in {svc}: {snippet}")
    return signals


def _first_obs_msg(obs: dict) -> str:
    alert = obs.get("alert", {})
    known = obs.get("known_services", [])
    affected = alert.get("affected_services", [])
    task_id = obs.get("task_id", "")
    non_aff = [s for s in known if s not in affected]

    lines = [
        "=== NEW INCIDENT ===",
        f"Task: {task_id}  |  Max steps: {obs.get('max_steps')}",
        f"Scenario: {obs.get('scenario_id', '')}",
        f"INCIDENT: {obs.get('incident_summary', '')}",
    ]

    if alert:
        lines.append("ALERT DETAILS:")
        if alert.get("title"):
            lines.append(f"  Title: {alert['title']}")
        if affected:
            lines.append(f"  Directly affected: {', '.join(affected)}")
        for s in alert.get("symptoms", []):
            lines.append(f"  - {s}")
        for k in ("error_rate", "duration_minutes", "revenue_impact_per_min"):
            if alert.get(k) is not None:
                lines.append(f"  {k}: {alert[k]}")

    lines.append(f"KNOWN_SERVICES: {json.dumps(known)}")

    if non_aff and task_id in ("root_cause_analysis", "remediation_planning"):
        lines.append(f"  Services NOT in alert (investigate these too): {json.dumps(non_aff)}")

    lines.append(f"AVAILABLE ACTIONS: {obs.get('available_actions', [])}")
    lines.append(f"REQUIRED SUBMISSION: {_TASK_SUBMIT.get(task_id, 'unknown')}")

    if task_id in ("root_cause_analysis", "remediation_planning"):
        lines.append("")
        lines.append("NOTE: check_recent_deploys requires prior investigation.")
        lines.append("You MUST query_logs or check_metrics on a service FIRST.")

    lines.append("")
    lines.append("Respond with your first action (JSON only):")
    return "\n".join(lines)


def _step_msg(obs: dict, prev_queried: dict) -> str:
    step = obs.get("step_count", 0)
    max_steps = obs.get("max_steps", 10)
    left = max_steps - step
    queried = obs.get("queried_data", {})
    task_id = obs.get("task_id", "")

    lines = [
        f"Step {step}/{max_steps} ({left} remaining) | "
        f"reward={obs.get('cumulative_reward', 0.0):.3f} | "
        f"feedback: {obs.get('feedback', '')}",
    ]

    new_data = []
    for action_type, services in queried.items():
        prev = prev_queried.get(action_type, {})
        if isinstance(services, dict):
            for svc, data in services.items():
                if svc not in prev:
                    d = str(data)
                    if len(d) > 500:
                        d = d[:500] + "..."
                    new_data.append(f"  [{action_type}][{svc}]: {d}")
    if new_data:
        lines.append("NEW DATA:")
        lines.extend(new_data)

    signals = _extract_signals(queried)
    if signals:
        lines.append("SIGNALS:")
        for sig in signals:
            lines.append(f"  *** {sig} ***")

    if left <= 3:
        lines.append(f"*** {left} steps left — submit {_TASK_SUBMIT.get(task_id, '')} soon ***")
    if left <= 1:
        lines.append(f"!!! LAST STEP — MUST {_TASK_SUBMIT.get(task_id, 'SUBMIT')} NOW !!!")

    lines.append("Next action (JSON only):")
    return "\n".join(lines)


def _parse(text: str) -> dict:
    text = text.strip()
    if text.startswith("`"):
        text = "\n".join(
            ln for ln in text.splitlines() if not ln.startswith("`")
        ).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        s = text.find("{")
        e = text.rfind("}") + 1
        if s != -1 and e > s:
            return json.loads(text[s:e])
        raise


def _fallback_submit(task_id: str, obs: dict) -> dict:
    alert = obs.get("alert", {})
    known = obs.get("known_services", [])

    if task_id == "alert_classification":
        rev = alert.get("revenue_impact_per_min", 0) or 0
        err = alert.get("error_rate", 0) or 0
        sev = ("P1" if (rev > 1000 or err > 0.9) else
               ("P2" if (rev > 100 or err > 0.3) else "P3"))
        svc = (alert.get("affected_services") or known or ["unknown"])[0]
        return {"action_type": "submit_severity",
                "parameters": {"severity": sev, "service": svc}}

    if task_id == "root_cause_analysis":
        svc = known[0] if known else "unknown"
        return {"action_type": "submit_root_cause",
                "parameters": {"service": svc,
                               "failure_mode": "service failure causing cascade"}}

    return {"action_type": "submit_resolution",
            "parameters": {"summary": (
                "The incident was investigated through log and metric analysis. "
                "Remediation actions were applied to restore service health. "
                "Systems are being monitored for recovery confirmation."
            )}}


def _smart_fallback(task_id: str, obs: dict, step: int, max_steps: int) -> dict:
    known = obs.get("known_services", [])
    queried = obs.get("queried_data", {})
    left = max_steps - step
    q_svcs = _queried_svcs(queried)

    if left <= 1:
        return _fallback_submit(task_id, obs)

    if task_id == "alert_classification" and q_svcs:
        return _fallback_submit(task_id, obs)

    # Query logs on unvisited services first
    for svc in known:
        if svc not in q_svcs:
            return {"action_type": "query_logs",
                    "parameters": {"service": svc}}

    # Then try check_recent_deploys (will now work since we queried logs)
    if task_id in ("root_cause_analysis", "remediation_planning"):
        deploy_queried = set(queried.get("check_recent_deploys", {}).keys())
        for svc in known:
            if svc not in deploy_queried:
                return {"action_type": "check_recent_deploys",
                        "parameters": {"service": svc}}

    return _fallback_submit(task_id, obs)


def _should_override(
    task_id: str, action: dict, obs: dict, step: int, max_steps: int
) -> bool:
    at = action.get("action_type", "")
    params = action.get("parameters", {})
    left = max_steps - step
    known = obs.get("known_services", [])

    if at not in _ALL_VALID:
        return True
    if left <= 0 and at not in _SUBMIT_TYPES:
        return True

    correct_submit = _TASK_SUBMIT.get(task_id)
    if at in _SUBMIT_TYPES and at != correct_submit:
        return True

    svc = (params.get("service") or "").strip()
    if (svc and known
            and at not in ("disable_feature_flag", "execute_runbook_step")
            and svc not in known):
        return True

    if at == "submit_severity":
        sev = (params.get("severity") or "").upper().strip()
        if sev not in ("P1", "P2", "P3", "P4"):
            return True

    if at == "submit_root_cause":
        svc = (params.get("service") or "").strip()
        mode = (params.get("failure_mode") or "").strip()
        if not svc or len(mode) < 5:
            return True

    if at == "submit_resolution":
        summary = (params.get("summary") or "").strip()
        if len(summary) < 30:
            return True

    if task_id == "alert_classification" and at in _REM_TYPES:
        return True

    return False


def _llm_call_with_retry(messages: list, max_retries: int = 1) -> str:
    """Call LLM with retry on rate limit errors."""
    for attempt in range(max_retries + 1):
        try:
            resp = _get_client().chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=0.0,
                max_tokens=300,
                stream=False,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:
            err_str = str(e).lower()
            if "rate_limit" in err_str or "429" in err_str:
                if attempt < max_retries:
                    # Parse wait time from error or use default
                    wait = 5 * (attempt + 1)
                    print(f"  [RATE LIMIT] waiting {wait}s (attempt {attempt + 1})",
                          file=sys.stderr)
                    time.sleep(wait)
                    continue
            if attempt == max_retries:
                print(f"  [WARN] LLM call failed: {e}", file=sys.stderr)
                return ""
    return ""


# ── Structured Output Helpers ───────────────────────────────────────────────

def _fmt_action(action: dict) -> str:
    """Format action as a compact string for [STEP] output."""
    at = action.get("action_type", "unknown")
    params = action.get("parameters", {})
    parts = []
    for k, v in params.items():
        if v is not None and v != "":
            parts.append(f"{k}={v}")
    if parts:
        return f"{at}({', '.join(parts)})"
    return at


def _fmt_error(error_val) -> str:
    """Format error for [STEP] output — return 'null' if no error."""
    if error_val is None or error_val == "" or error_val == "null":
        return "null"
    # Sanitize: remove newlines to keep [STEP] on a single line
    return str(error_val).replace("\n", " ").replace("\r", "")


# ── Episode Runner with Structured Output ───────────────────────────────────

def _run_episode_structured(task_id: str, scenario_index: int) -> tuple[float, int, list[float]]:
    """
    Run a single episode with required [START]/[STEP]/[END] structured stdout output.
    
    Returns: (score, steps_used, rewards_list)
    """
    rewards_list: list[float] = []
    steps_used = 0
    score = 0.0

    # ── [START] ──
    print(f"[START] task={task_id} env={ENV_NAME} model={MODEL_NAME}", flush=True)

    try:
        _check_timeout()

        # Reset environment
        r = _session.post(
            f"{ENV_BASE_URL}/reset",
            params={"task_id": task_id, "scenario_index": scenario_index},
            timeout=30,
        )
        r.raise_for_status()
        obs = r.json()

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": _first_obs_msg(obs)},
        ]

        prev_queried: dict = {}
        max_steps = obs.get("max_steps", 10)

        for step_i in range(max_steps):
            current_step = step_i + 1

            # Get LLM action
            raw = _llm_call_with_retry(messages)
            messages.append({"role": "assistant", "content": raw or "{}"})

            action = None
            try:
                if raw.strip():
                    action = _parse(raw)
            except Exception:
                pass

            if action is None:
                action = _smart_fallback(task_id, obs, current_step, max_steps)
                print(f"  [FALLBACK] step {current_step}: "
                      f"{action.get('action_type')}", file=sys.stderr)
            elif _should_override(task_id, action, obs, current_step, max_steps):
                old_at = action.get("action_type")
                action = _smart_fallback(task_id, obs, current_step, max_steps)
                print(f"  [OVERRIDE] step {current_step}: "
                      f"{old_at} -> {action.get('action_type')}", file=sys.stderr)

            # Execute step
            sr = _session.post(f"{ENV_BASE_URL}/step", json=action, timeout=30)
            sr.raise_for_status()
            result = sr.json()
            new_obs = result["observation"]

            step_reward = result["reward"]["value"]
            done = result["done"]
            error_raw = new_obs.get("last_action_error")

            rewards_list.append(step_reward)
            steps_used = current_step

            # ── [STEP] ──
            done_str = "true" if done else "false"
            error_str = _fmt_error(error_raw)
            action_str = _fmt_action(action)
            print(
                f"[STEP] step={current_step} action={action_str} "
                f"reward={step_reward:.2f} done={done_str} error={error_str}",
                flush=True,
            )

            # Debug to stderr
            print(
                f"    step {current_step:>2}: {action.get('action_type'):<28} "
                f"reward={step_reward:+.3f}  done={done}",
                file=sys.stderr,
            )

            if done:
                break

            step_msg = _step_msg(new_obs, prev_queried)
            messages.append({"role": "user", "content": step_msg})
            prev_queried = {
                k: dict(v)
                for k, v in new_obs.get("queried_data", {}).items()
                if isinstance(v, dict)
            }
            obs = new_obs

            if len(messages) > 20:
                messages = messages[:2] + messages[-16:]

        # Grade
        g = _session.get(f"{ENV_BASE_URL}/grader", timeout=30)
        g.raise_for_status()
        score = g.json().get("total", 0.0)

    except Exception as e:
        print(f"  [ERROR] {task_id} scenario {scenario_index}: {e}", file=sys.stderr)
        # If we haven't emitted any steps yet, emit a failure step
        if steps_used == 0:
            steps_used = 1
            rewards_list.append(0.0)
            print(
                f"[STEP] step=1 action=error reward=0.00 done=true "
                f"error={_fmt_error(str(e))}",
                flush=True,
            )

    # ── [END] ── (always emitted, even on exception)
    success_str = "true" if score > 0 else "false"
    rewards_str = ",".join(f"{rw:.2f}" for rw in rewards_list)
    print(
        f"[END] success={success_str} steps={steps_used} "
        f"score={score:.2f} rewards={rewards_str}",
        flush=True,
    )

    return score, steps_used, rewards_list


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    runs = [
        ("alert_classification", 0),
        ("alert_classification", 1),
        ("alert_classification", 2),
        ("root_cause_analysis", 0),
        ("root_cause_analysis", 1),
        ("root_cause_analysis", 2),
        ("remediation_planning", 0),
        ("remediation_planning", 1),
        ("remediation_planning", 2),
    ]

    _DIFFICULTY = {
        "alert_classification": "🟢 Easy",
        "root_cause_analysis": "🟡 Medium",
        "remediation_planning": "🔴 Hard",
    }

    results: dict[str, list[dict]] = {}

    # Banner to stderr (not stdout — structured output only on stdout)
    print("", file=sys.stderr)
    print("=" * 100, file=sys.stderr)
    print("  ☁️  CLOUD INCIDENT RESPONSE — BASELINE INFERENCE", file=sys.stderr)
    print("=" * 100, file=sys.stderr)
    print(f"  Model:    {MODEL_NAME}", file=sys.stderr)
    print(f"  Endpoint: {API_BASE_URL}", file=sys.stderr)
    print("=" * 100, file=sys.stderr)
    print("", file=sys.stderr)

    for task_id, scenario_index in runs:
        score, steps_used, rewards_list = _run_episode_structured(task_id, scenario_index)

        difficulty = _DIFFICULTY.get(task_id, "?")
        cumulative_reward = sum(rewards_list)

        # Summary per episode to stderr
        print(
            f"  {task_id:<24} {difficulty:<12} scenario={scenario_index} "
            f"steps={steps_used} reward={cumulative_reward:+.4f} score={score:.4f}",
            file=sys.stderr,
        )

        results.setdefault(task_id, []).append({
            "scenario": scenario_index,
            "score": score,
            "steps": steps_used,
            "reward": cumulative_reward,
        })

    # Summary to stderr
    print("", file=sys.stderr)
    print("=" * 100, file=sys.stderr)
    print("  📊 SUMMARY BY TASK", file=sys.stderr)
    print("=" * 100, file=sys.stderr)

    summary = {}
    for task_id in ["alert_classification", "root_cause_analysis", "remediation_planning"]:
        if task_id not in results:
            continue
        data = results[task_id]
        avg_score = sum(d["score"] for d in data) / len(data)
        scenario_scores = " | ".join(f'{d["score"]:.2f}' for d in data)
        difficulty = _DIFFICULTY.get(task_id, "?")

        print(f"  {task_id:<24} {difficulty:<12} avg={avg_score:.4f}  [{scenario_scores}]",
              file=sys.stderr)
        summary[task_id] = round(avg_score, 4)

    if summary:
        summary["overall"] = round(sum(summary.values()) / len(summary), 4)
    else:
        summary["overall"] = 0.0

    print(f"  {'OVERALL':<24} {'':12} avg={summary['overall']:.4f}", file=sys.stderr)
    print("=" * 100, file=sys.stderr)

    # JSON summary as the LAST line of stdout (for /baseline endpoint compatibility)
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    main()
