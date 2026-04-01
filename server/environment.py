"""
server/environment.py — Core OpenEnv environment for Cloud Incident Response.

Difficulty comes from SCENARIO DESIGN, not mechanics:
  EASY:   3 services, clear metrics, obvious severity
  MEDIUM: 8 services, root cause NOT in alert, must follow log breadcrumbs
  HARD:   8 services + 5-7 remediation steps + quality summary + penalties
"""

from __future__ import annotations

import os
import sys
import threading
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graders import _svc_match, grade
from server.models import Action, ActionParameters, EpisodeState, Observation, Reward
from tasks import get_scenario, get_task

_DIAGNOSTIC = frozenset({
    "query_logs", "check_metrics", "check_dependencies",
    "check_recent_deploys", "check_service_status",
})

_REMEDIATION = frozenset({
    "restart_service", "rollback_deploy", "scale_service",
    "disable_feature_flag", "clear_cache", "execute_runbook_step",
})

_SUBMIT = frozenset({
    "submit_severity", "submit_root_cause", "submit_resolution",
})

_TASK_SUBMIT = {
    "alert_classification": "submit_severity",
    "root_cause_analysis": "submit_root_cause",
    "remediation_planning": "submit_resolution",
}

_REWARD_TABLE = {
    "easy": {
        "query_new_svc":     +0.04,  "query_new_action":  +0.02,
        "query_repeat":      -0.03,  "query_unknown_svc": -0.06,
        "query_no_service":  -0.04,  "rem_good":          +0.00,
        "rem_wrong":         -0.08,  "rem_no_target":     -0.05,
        "submit_correct":    +0.02,  "submit_wrong":      -0.08,
        "past_half":         -0.04,  "timeout":           -0.15,
        "bad_action":        -0.05,  "exact_repeat":      -0.04,
    },
    "medium": {
        "query_new_svc":     +0.04,  "query_new_action":  +0.02,
        "query_repeat":      -0.04,  "query_unknown_svc": -0.06,
        "query_no_service":  -0.04,  "rem_good":          +0.06,
        "rem_wrong":         -0.10,  "rem_no_target":     -0.06,
        "submit_correct":    +0.02,  "submit_wrong":      -0.10,
        "past_half":         -0.02,  "timeout":           -0.15,
        "bad_action":        -0.05,  "exact_repeat":      -0.05,
    },
    "hard": {
        "query_new_svc":     +0.03,  "query_new_action":  +0.01,
        "query_repeat":      -0.03,  "query_unknown_svc": -0.05,
        "query_no_service":  -0.03,  "rem_good":          +0.06,
        "rem_wrong":         -0.15,  "rem_no_target":     -0.05,
        "submit_correct":    +0.02,  "submit_wrong":      -0.12,
        "past_half":         -0.02,  "timeout":           -0.20,
        "bad_action":        -0.05,  "exact_repeat":      -0.04,
    },
}

_TASK_DIFFICULTY = {
    "alert_classification": "easy",
    "root_cause_analysis": "medium",
    "remediation_planning": "hard",
}


class IncidentEnvironment:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._s: dict = {}
        self._scenario: dict = {}
        self._task_def: dict = {}
        self._ready = False

    def reset(self, task_id: str = "alert_classification",
              scenario_index: int = 0) -> Observation:
        with self._lock:
            task_def = get_task(task_id)
            scenario = get_scenario(task_id, scenario_index)
            self._task_def = task_def
            self._scenario = scenario
            self._s = {
                "episode_id": str(uuid.uuid4()),
                "task_id": task_id,
                "scenario_id": scenario["scenario_id"],
                "step_count": 0,
                "max_steps": task_def["max_steps"],
                "action_history": [],
                "queried_data": {},
                "queried_keys": set(),
                "services_queried": set(),
                "exact_hashes": set(),
                "submitted": False,
                "resolved": False,
                "done": False,
                "cumulative_reward": 0.0,
                "feedback": f"Episode started. {scenario['description']}",
                "last_action_error": None,
            }
            self._ready = True
            return self._build_obs()

    def step(self, action: Action) -> tuple[Observation, Reward, bool, dict]:
        with self._lock:
            if not self._ready:
                raise RuntimeError("Call reset() before step().")
            s = self._s
            s["last_action_error"] = None

            if s["done"]:
                return (self._build_obs(),
                        Reward(score=0.0, reason="episode already done",
                               cumulative=s["cumulative_reward"]),
                        True, {})

            s["step_count"] += 1
            step_num = s["step_count"]
            at = action.action_type
            params = action.parameters
            task_id = s["task_id"]
            diff = _TASK_DIFFICULTY.get(task_id, "medium")
            rt = _REWARD_TABLE[diff]

            s["action_history"].append({
                "action_type": at,
                "parameters": params.model_dump(exclude_none=True),
                "step": step_num,
            })

            r = 0.0
            fb: list[str] = []

            h = f"{at}|{params.model_dump_json(exclude_none=True)}"
            if h in s["exact_hashes"]:
                r += rt["exact_repeat"]
                fb.append(f"exact repeat ({rt['exact_repeat']:+.2f})")
            s["exact_hashes"].add(h)

            half = max(1, s["max_steps"] // 2)
            if step_num > half and at not in _SUBMIT:
                r += rt["past_half"]
                fb.append(f"past halfway ({rt['past_half']:+.3f})")

            if at in _DIAGNOSTIC:
                r, fb = self._handle_diagnostic(at, params, r, fb, rt)
            elif at in _REMEDIATION:
                r, fb = self._handle_remediation(at, params, r, fb, rt, task_id)
            elif at in _SUBMIT:
                r, fb, terminal = self._handle_submit(at, params, r, fb, rt, task_id)
                if terminal:
                    s["done"] = True
            else:
                r += rt["bad_action"]
                fb.append(f"unknown action '{at}' ({rt['bad_action']:+.2f})")
                s["last_action_error"] = f"Unknown action type: {at}"

            if step_num >= s["max_steps"] and not s["done"]:
                r += rt["timeout"]
                fb.append(f"timeout ({rt['timeout']:+.2f})")
                s["done"] = True

            if s["done"]:
                result = grade(s["task_id"], s, self._scenario)
                grader_score = result["total"]
                s["cumulative_reward"] = round(
                    s["cumulative_reward"] + r + grader_score, 4)
                fb.append(f"grader={grader_score:.3f} ({result['feedback']})")
            else:
                s["cumulative_reward"] = round(s["cumulative_reward"] + r, 4)

            s["feedback"] = " | ".join(fb) if fb else "ok"
            return (self._build_obs(),
                    Reward(score=round(r, 4), reason=s["feedback"],
                           cumulative=s["cumulative_reward"]),
                    s["done"],
                    {"step": step_num, "feedback": s["feedback"]})

    def state(self) -> EpisodeState:
        with self._lock:
            if not self._ready:
                raise RuntimeError("No active episode — call reset() first.")
            s = self._s
            return EpisodeState(
                episode_id=s["episode_id"], task_id=s["task_id"],
                scenario_id=s["scenario_id"], step_count=s["step_count"],
                max_steps=s["max_steps"],
                action_history=list(s["action_history"]),
                queried_data=dict(s["queried_data"]),
                submitted=s["submitted"], resolved=s["resolved"],
                done=s["done"], cumulative_reward=s["cumulative_reward"],
                feedback=s["feedback"])

    def _handle_diagnostic(self, at, params, r, fb, rt):
        s = self._s
        svc = (params.service or "").lower().strip()
        known = {v.lower() for v in self._scenario.get("known_services", set())}
        tool = self._scenario.get("tool_responses", {}).get(at, {})
        key = (at, svc)

        if not svc:
            r += rt["query_no_service"]
            fb.append(f"{at}: no service ({rt['query_no_service']:+.2f})")
            s["last_action_error"] = f"{at} requires a service parameter"
            return r, fb

        if svc not in known:
            r += rt["query_unknown_svc"]
            fb.append(f"unknown service '{svc}' ({rt['query_unknown_svc']:+.2f})")
            s["last_action_error"] = f"Unknown service: {svc}"
            return r, fb

        if key in s["queried_keys"]:
            r += rt["query_repeat"]
            fb.append(f"repeat [{at}][{svc}] ({rt['query_repeat']:+.2f})")
        elif svc in s["services_queried"]:
            r += rt["query_new_action"]
            fb.append(f"new action on {svc} ({rt['query_new_action']:+.2f})")
            s["queried_keys"].add(key)
        else:
            r += rt["query_new_svc"]
            fb.append(f"new service {svc} ({rt['query_new_svc']:+.2f})")
            s["queried_keys"].add(key)
            s["services_queried"].add(svc)

        result = tool.get(svc, f"No data available for '{svc}'.")
        s["queried_data"].setdefault(at, {})[svc] = result
        return r, fb

    def _handle_remediation(self, at, params, r, fb, rt, task_id):
        s = self._s
        if task_id == "alert_classification":
            r += rt["rem_wrong"]
            fb.append(f"remediation in easy task ({rt['rem_wrong']:+.2f})")
            s["last_action_error"] = "Remediation not available in alert_classification"
            return r, fb

        svc = (params.service or "").lower().strip()
        flag = (params.flag or "").lower().strip()
        runbook = (params.runbook_action or "").lower().strip()
        target = (params.target or "").lower().strip()

        if not (svc or flag or runbook or target):
            r += rt["rem_no_target"]
            fb.append(f"{at}: no target ({rt['rem_no_target']:+.2f})")
            s["last_action_error"] = f"{at} requires a target"
            return r, fb

        keys = {at}
        if svc:     keys.add(f"{at}:{svc}")
        if flag:    keys.add(f"{at}:{flag}")
        if runbook: keys.add(f"execute_runbook_step:{runbook}")
        if target:  keys.add(f"execute_runbook_step:{target}")

        wrong_map = self._scenario.get("wrong_actions", {})
        rem_data = self._scenario.get("remediation_data", {})

        is_wrong = any(k in wrong_map for k in keys)
        if not is_wrong and svc:
            for wk in wrong_map:
                if ":" in wk:
                    w_at, w_svc = wk.split(":", 1)
                    if w_at == at and _svc_match(svc, w_svc):
                        is_wrong = True
                        break

        if is_wrong:
            r += rt["rem_wrong"]
            reason = next((wrong_map[k] for k in keys if k in wrong_map), "wrong")
            fb.append(f"wrong: {at} — {str(reason)[:60]} ({rt['rem_wrong']:+.2f})")
        else:
            r += rt["rem_good"]
            tgt = svc or flag or runbook or target
            fb.append(f"executed {at}:{tgt} ({rt['rem_good']:+.2f})")
            at_data = rem_data.get(at, {})
            result = (at_data.get(svc) or at_data.get(flag) or at_data.get(runbook)
                      or at_data.get(target) or "action executed successfully")
            s["queried_data"].setdefault(at, {})[tgt] = result
        return r, fb

    def _handle_submit(self, at, params, r, fb, rt, task_id):
        s = self._s
        correct = _TASK_SUBMIT.get(task_id, "")
        if at != correct:
            r += rt["submit_wrong"]
            fb.append(f"wrong submit '{at}' (need '{correct}') ({rt['submit_wrong']:+.2f})")
            s["last_action_error"] = f"Wrong submission type: use {correct}"
            return r, fb, False

        s["submitted"] = True
        r += rt["submit_correct"]
        fb.append(f"submitted ({rt['submit_correct']:+.2f})")

        if at == "submit_severity":
            fb.append(f"severity={(params.severity or '').upper().strip()}")
        elif at == "submit_root_cause":
            fb.append(f"svc={params.service or ''}, mode={params.failure_mode or ''}")
        elif at == "submit_resolution":
            summary = params.summary or ""
            inv = sum(1 for a in s["action_history"]
                      if a.get("action_type") in _DIAGNOSTIC | _REMEDIATION)
            if summary.strip() and inv >= 1:
                s["resolved"] = True
                fb.append("resolved")
            else:
                fb.append("insufficient investigation")
        return r, fb, True

    def _build_obs(self):
        s = self._s
        sc = self._scenario
        td = self._task_def
        return Observation(
            episode_id=s["episode_id"], task_id=s["task_id"],
            scenario_id=s["scenario_id"], step_count=s["step_count"],
            max_steps=s["max_steps"],
            incident_summary=sc.get("incident_summary", sc.get("description", "")),
            alert=sc.get("alert", {}),
            available_actions=td.get("available_actions", []),
            queried_data=dict(s["queried_data"]),
            cumulative_reward=s["cumulative_reward"],
            done=s["done"], feedback=s["feedback"],
            known_services=sorted(sc.get("known_services", set())),
            last_action_error=s.get("last_action_error"))