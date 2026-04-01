"""
graders.py — Deterministic graders for all 3 Cloud Incident Response tasks.

Public API:
    grade(task_id, state, scenario) -> {"total": float, "breakdown": dict, "feedback": str}

All scores are in [0.0, 1.0].

Grading Philosophy:
  - Easy task: binary-ish — did you get the severity right?
  - Medium task: partial credit for correct service, bonus for efficiency
  - Hard task: multi-component — base + efficiency − penalties + summary quality
"""

from __future__ import annotations


def _normalise(s: str) -> str:
    """Lowercase, strip whitespace, collapse hyphens/underscores."""
    return s.lower().strip().replace("_", "-").replace(" ", "-")


def _svc_match(submitted: str, correct: str) -> bool:
    s = _normalise(submitted)
    c = _normalise(correct)
    if s == c:
        return True
    if s in c or c in s:
        return True
    aliases = {
        "network": "network-infra",
        "network-infrastructure": "network-infra",
        "cdn": "cdn-edge",
        "postgres": "postgres-db",
        "postgresql": "postgres-db",
        "analytics": "analytics-service",
        "payment": "payment-service",
        "auth": "auth-service",
        "api": "api-gateway",
        "api-gw": "api-gateway",
        "fraud": "fraud-detection-service",
        "fraud-detection": "fraud-detection-service",
        "order": "order-service",
        "orders": "order-service",
        "image": "image-service",
        "images": "image-service",
        "product": "product-service",
        "products": "product-service",
        "redis": "redis-session",
        "redis-cache": "redis-payment-cache",
    }
    return aliases.get(s, s) == c or s == aliases.get(c, c)


def grade(task_id: str, state: dict, scenario: dict) -> dict:
    _graders = {
        "alert_classification": _grade_alert_classification,
        "root_cause_analysis": _grade_root_cause_analysis,
        "remediation_planning": _grade_remediation_planning,
    }
    fn = _graders.get(task_id)
    if fn is None:
        return {
            "total": 0.0,
            "breakdown": {},
            "feedback": f"Unknown task_id '{task_id}'",
        }
    return fn(state, scenario)


# ── Task 1: Alert Classification (Easy) ──────────────────────────────────────
#
# Scoring:
#   1.0  — exact severity match
#   0.5  — adjacent severity (e.g. P1 vs P2)
#   0.25 — two levels off (e.g. P1 vs P3)
#   0.0  — wrong by 3+ levels or no submission
#
# This is genuinely EASY: with 3 steps, an agent queries 1–2 services,
# reads the error_rate + revenue_impact, and classifies. The data is
# unambiguous — the correct answer is clearly derivable from the alert.


def _grade_alert_classification(state: dict, scenario: dict) -> dict:
    history = state.get("action_history", [])
    correct = scenario.get("correct_severity", "P1")
    adjacent = scenario.get("adjacent_severities", [])
    order = ["P1", "P2", "P3", "P4"]

    submitted = None
    for a in history:
        if a.get("action_type") == "submit_severity":
            submitted = a.get("parameters", {}).get("severity", "").upper().strip()
            break

    if not submitted:
        return {
            "total": 0.0,
            "breakdown": {"submitted": False, "severity_match": 0.0},
            "feedback": "No severity submitted — score 0.0",
        }

    if submitted == correct:
        score, msg = 1.0, f"Exact match: {submitted}"
    elif submitted in adjacent:
        score, msg = 0.5, f"Adjacent: submitted {submitted}, correct {correct}"
    else:
        try:
            dist = abs(order.index(submitted) - order.index(correct))
        except ValueError:
            dist = 4
        score = 0.25 if dist == 2 else 0.0
        msg = f"Wrong: submitted {submitted}, correct {correct} (distance={dist})"

    return {
        "total": score,
        "breakdown": {
            "submitted_severity": submitted,
            "correct_severity": correct,
            "severity_match": score,
        },
        "feedback": msg,
    }


# ── Task 2: Root Cause Analysis (Medium) ─────────────────────────────────────
#
# Scoring (total up to 1.0):
#   Base (up to 0.6):
#     0.60 — correct service AND failure mode keywords match
#     0.35 — correct service only
#     0.10 — wrong service (partial credit for at least submitting)
#   Efficiency bonus (up to 0.4):
#     Based on investigation precision: queried relevant services / total queries
#     Plus bonus for breadth of investigation (up to 3 unique known services)
#
# This is genuinely MEDIUM: the root cause is NOT in the alert's
# affected_services list. The agent must investigate services outside
# the blast radius, correlate log evidence, and identify the upstream
# trigger — this requires multi-hop reasoning across 4–6 services.


def _grade_root_cause_analysis(state: dict, scenario: dict) -> dict:
    history = state.get("action_history", [])
    correct_rc = scenario.get("correct_root_cause", {})
    correct_svc = correct_rc.get("service", "").lower().strip()
    correct_mode = correct_rc.get("failure_mode", "").lower().strip()
    known = {s.lower() for s in scenario.get("known_services", set())}

    diag_types = {
        "query_logs",
        "check_metrics",
        "check_dependencies",
        "check_recent_deploys",
        "check_service_status",
    }

    sub_svc, sub_mode, sub_step = "", "", len(history)
    for a in history:
        if a.get("action_type") == "submit_root_cause":
            p = a.get("parameters", {})
            sub_svc = p.get("service", "").lower().strip()
            sub_mode = p.get("failure_mode", "").lower().strip()
            sub_step = a.get("step", len(history))
            break

    if not sub_svc:
        return {
            "total": 0.0,
            "breakdown": {"base": 0.0, "efficiency": 0.0, "submitted": False},
            "feedback": "No root cause submitted — score 0.0",
        }

    svc_match = _svc_match(sub_svc, correct_svc)
    mode_kws = [w for w in correct_mode.split() if len(w) > 3]
    mode_match = svc_match and (
        any(kw in sub_mode for kw in mode_kws) if mode_kws else True
    )

    if mode_match:
        base, base_fb = 0.6, "Correct service + failure mode"
    elif svc_match:
        base, base_fb = 0.35, "Correct service only — failure mode unclear"
    else:
        # Give MORE partial credit for investigation effort even with wrong answer
        pre_submit_diag = [
            a for a in history[:sub_step]
            if a.get("action_type") in diag_types
        ]
        investigated = len({
            a.get("parameters", {}).get("service", "").lower()
            for a in pre_submit_diag
        } - {""})
        # 0.05 base + up to 0.15 for investigating 3+ services
        wrong_base = min(0.20, 0.05 + investigated * 0.05)
        base, base_fb = wrong_base, (
            f"Wrong service: '{sub_svc}' (correct: '{correct_svc}') — "
            f"investigated {investigated} services"
        )

    efficiency = 0.0
    if svc_match:
        pre_submit = [
            a
            for a in history[: sub_step]
            if a.get("action_type") in diag_types
        ]
        queried_svcs = {
            a.get("parameters", {}).get("service", "").lower() for a in pre_submit
        }
        relevant = queried_svcs & known
        total_q = len(pre_submit)
        if total_q > 0:
            precision = len(relevant) / max(total_q, 1)
            efficiency = round(
                min(0.4, precision * 0.4 + min(len(relevant), 3) * 0.05), 4
            )

    total = round(min(1.0, base + efficiency), 4)
    return {
        "total": total,
        "breakdown": {
            "base": base,
            "efficiency_bonus": efficiency,
            "service_match": svc_match,
            "mode_match": mode_match,
            "submitted_service": sub_svc,
            "correct_service": correct_svc,
        },
        "feedback": f"{base_fb} | efficiency={efficiency:.2f} | total={total:.2f}",
    }


# ── Task 3: Remediation Planning (Hard) ──────────────────────────────────────
#
# Scoring (total up to 1.0):
#   Base (0.6 if submitted with any investigation):
#     Requires at least 1 diagnostic/remediation action + a summary
#   Efficiency bonus (up to 0.3):
#     Fraction of correct_remediation_sequence steps matched
#   Wrong action penalty (up to -0.15):
#     −0.05 per wrong action taken (capped at 3)
#   Summary quality bonus (up to 0.10):
#     Based on keyword coverage in the resolution summary
#
# This is genuinely HARD: requires multi-phase execution:
#   Phase 1: Diagnose (query logs to confirm root cause)
#   Phase 2: Remediate (execute 3–5 specific actions in order)
#   Phase 3: Document (write a coherent summary with key details)
# Wrong remediation actions actively harm the score. The sequence
# matters. The summary must reference specific services and actions.


def _grade_remediation_planning(state: dict, scenario: dict) -> dict:
    history = state.get("action_history", [])
    correct_seq = scenario.get("correct_remediation_sequence", [])
    wrong_map = scenario.get("wrong_actions", {})
    keywords = scenario.get("resolution_keywords", [])

    diag_rem = {
        "query_logs",
        "check_metrics",
        "check_dependencies",
        "check_recent_deploys",
        "check_service_status",
        "restart_service",
        "rollback_deploy",
        "scale_service",
        "disable_feature_flag",
        "clear_cache",
        "execute_runbook_step",
    }

    summary = ""
    for a in history:
        if a.get("action_type") == "submit_resolution":
            summary = a.get("parameters", {}).get("summary", "")
            break

    inv_count = sum(1 for a in history if a.get("action_type") in diag_rem)

    if not summary or inv_count < 1:
        return {
            "total": 0.0,
            "breakdown": {
                "base": 0.0,
                "efficiency": 0.0,
                "penalty": 0.0,
                "summary_bonus": 0.0,
            },
            "feedback": "No resolution submitted or no investigation — score 0.0",
        }

    # Base scales with investigation depth — not a free 0.60
    diag_count = sum(
        1 for a in history if a.get("action_type") in {
            "query_logs", "check_metrics", "check_dependencies",
            "check_recent_deploys", "check_service_status",
        }
    )
    rem_count = sum(
        1 for a in history if a.get("action_type") in {
            "restart_service", "rollback_deploy", "scale_service",
            "disable_feature_flag", "clear_cache", "execute_runbook_step",
        }
    )
    diag_credit = min(0.20, diag_count * 0.05)
    rem_credit = min(0.20, rem_count * 0.05)
    base = round(0.10 + diag_credit + rem_credit, 4)

    executed = set()
    for a in history:
        at = a.get("action_type", "")
        p = a.get("parameters", {})
        svc = p.get("service", "")
        flag = p.get("flag", "")
        runbook = p.get("runbook_action", "")
        target = p.get("target", "")
        executed.add(at)
        if svc:
            executed.add(f"{at}:{svc}")
        if flag:
            executed.add(f"{at}:{flag}")
        if runbook:
            executed.add(f"execute_runbook_step:{runbook}")
        if target:
            executed.add(f"execute_runbook_step:{target}")

    def _seq_key_matches(seq_key: str) -> bool:
        if seq_key in executed:
            return True
        if ":" in seq_key:
            action, target = seq_key.split(":", 1)
            for ex_key in executed:
                if ":" in ex_key:
                    ex_action, ex_target = ex_key.split(":", 1)
                    if ex_action == action and _svc_match(ex_target, target):
                        return True
        return False

    matched = sum(1 for k in correct_seq if _seq_key_matches(k))
    efficiency = (
        round((matched / len(correct_seq)) * 0.3, 4) if correct_seq else 0.0
    )

    wrong_count = sum(
        1
        for a in history
        if (
            a.get("action_type") in wrong_map
            or f"{a.get('action_type')}:{a.get('parameters', {}).get('service', '')}"
            in wrong_map
        )
    )
    penalty = round(min(0.30, wrong_count * 0.10), 4)


    sl = summary.lower()
    hits = sum(1 for kw in keywords if kw in sl)
    summary_bonus = 0.10 if hits >= 3 else (0.05 if hits >= 1 else 0.0)

    total = round(max(0.0, min(1.0, base + efficiency - penalty + summary_bonus)), 4)

    return {
        "total": total,
        "breakdown": {
            "base": base,
            "efficiency_bonus": efficiency,
            "wrong_action_penalty": -penalty,
            "summary_bonus": summary_bonus,
            "correct_actions_matched": matched,
            "correct_actions_total": len(correct_seq),
            "wrong_actions_count": wrong_count,
            "summary_keywords_hit": hits,
        },
        "feedback": (
            f"base={base} | efficiency={efficiency:.2f} "
            f"({matched}/{len(correct_seq)} correct) | "
            f"penalty=-{penalty:.2f} | summary={summary_bonus:.2f} | "
            f"total={total:.2f}"
        ),
    }