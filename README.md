---
title: Cloud Incident Response OpenEnv
emoji: 🚨
colorFrom: red
colorTo: yellow
sdk: docker
app_port: 7860
pinned: false
tags:
  - openenv
  - sre
  - cloud
  - incident-response
  - devops
  - real-world
  - agentic
---

# ☁️ Cloud Incident Response — OpenEnv Environment

An OpenEnv environment for training and evaluating AI agents on **cloud SRE incident response** — the real-world on-call workflow that engineers perform daily at every cloud company.

Distinct from Kubernetes operations environments: this focuses on **cross-service cascading failures** in distributed microservice architectures — OOM kills from runaway analytics queries, BGP network partitions isolating availability zones, and credential rotation bugs pushing stale secrets to production services.

---

## OpenEnv Interface

This environment implements the **full OpenEnv specification** with typed Pydantic models:

| Method | Endpoint | Input | Returns |
|---|---|---|---|
| `POST` | `/reset` | `{"task_id": "...", "scenario_index": 0}` or `{}` | `Observation` |
| `POST` | `/step` | `Action` JSON body | `{observation, reward, done, info}` |
| `GET` | `/state` | — | `EpisodeState` |
| `GET` | `/health` | — | `{"status": "ok"}` |
| `GET` | `/tasks` | — | Task list + action schemas |
| `GET` | `/grader` | — | Score 0.0–1.0 with breakdown |
| `POST` | `/baseline` | — | Run inference.py, return scores |

### Typed Models

```python
# Action — submitted by the agent
Action {
    action_type: str,          # e.g. "query_logs", "restart_service", "submit_severity"
    parameters: {
        service?: str,         # Target service name
        severity?: str,        # P1|P2|P3|P4 (for submit_severity)
        failure_mode?: str,    # Root cause description (for submit_root_cause)
        summary?: str,         # Resolution summary (for submit_resolution)
        flag?: str,            # Feature flag name (for disable_feature_flag)
        runbook_action?: str,  # Runbook step (for execute_runbook_step)
        target_version?: str,  # Deploy version (for rollback_deploy)
    }
}

# Observation — returned to the agent
Observation {
    episode_id: str,           # Unique episode UUID
    task_id: str,              # Active task
    scenario_id: str,          # Current scenario (e.g. "AC-001")
    step_count: int,           # Steps taken so far
    max_steps: int,            # Budget (3, 10, or 15)
    incident_summary: str,     # Plain-text incident description
    alert: dict,               # Alert payload: title, symptoms, error_rate, revenue_impact
    available_actions: [str],  # Valid action types for this task
    queried_data: dict,        # All evidence gathered so far
    known_services: [str],     # Valid service names for actions
    cumulative_reward: float,  # Running reward total
    done: bool,                # Episode complete flag
    feedback: str,             # Per-step reward explanation
    last_action_error: str?,   # Error from last action (null if OK)
}

# Reward — returned after each step
Reward {
    score: float,              # Step reward value
    value: float,              # Alias for score (backward compatibility)
    reason: str,               # Human-readable explanation
    cumulative: float,         # Running total
}
```

---

## Tasks (3 Difficulty Levels, 9 Scenarios)

| Task ID | Difficulty | Max Steps | Scenarios | What the Agent Does |
|---|---|---|---|---|
| `alert_classification` | 🟢 Easy | 3 | 3 | Classify alert severity P1–P4 from metrics and symptoms |
| `root_cause_analysis` | 🟡 Medium | 10 | 3 | Trace failure chain across 8 services to find root cause |
| `remediation_planning` | 🔴 Hard | 15 | 3 | Diagnose + execute multi-step remediation + document resolution |

### Scenario Details

| ID | Incident | Root Cause | Challenge |
|---|---|---|---|
| AC-001 | DB connection pool exhaustion | — | Clear P1: 78% errors, $12k/min |
| AC-002 | CDN cache invalidation storm | — | Ambiguous P2: degraded but checkout works |
| AC-003 | Recommendation engine errors | — | Trap P3: 45% errors but zero revenue impact |
| RCA-001 | Postgres OOM crash loop | analytics-service (unbounded query) | Root cause NOT in alert, 8 services to investigate |
| RCA-002 | Cross-AZ checkout failures | network-infra (BGP route withdrawal) | Network issue disguised as application failure |
| RCA-003 | DB authentication failures | config-service (stale credential rotation) | Multiple red herring deploys on other services |
| RP-001 | Full OOM incident | analytics-service | 6-step remediation sequence, wrong actions penalized |
| RP-002 | Full BGP incident | network-infra | 4-step runbook + config rollback, 8 services |
| RP-003 | Full credential incident | config-service | 7-step sequence, credential rotation + service restarts |

### Why This Is Genuinely Difficult

- **Medium**: Root cause service is NEVER in the alert's `affected_services`. Agent must query logs on victim services, follow breadcrumbs that name the culprit, then investigate that service. 8 known services with red herring deploys.
- **Hard**: Same diagnostic challenge PLUS must execute 4–7 remediation actions in logical order. Wrong actions (e.g. restarting a healthy service) carry −0.15 penalties. Resolution summary must reference specific services and actions.

### Baseline Scores

| Model | Easy | Medium | Hard | Overall |
|---|---|---|---|---|
| `llama-3.1-8b-instant` | 1.0 | 0.65 | 0.70 | 0.78 |
| `llama-3.3-70b-versatile` | 1.0 | 0.99 | 0.80 | 0.93 |

70B consistently outperforms 8B on medium/hard tasks, proving the environment differentiates model quality.

---

## Action Space

### 🔍 Diagnostic Actions (gather evidence)

```json
{"action_type": "query_logs",           "parameters": {"service": "postgres-db"}}
{"action_type": "check_metrics",        "parameters": {"service": "auth-service"}}
{"action_type": "check_dependencies",   "parameters": {"service": "api-gateway"}}
{"action_type": "check_recent_deploys", "parameters": {"service": "analytics-service"}}
{"action_type": "check_service_status", "parameters": {"service": "payment-service"}}
```

### 🔧 Remediation Actions (fix the incident)

```json
{"action_type": "restart_service",      "parameters": {"service": "postgres-db"}}
{"action_type": "rollback_deploy",      "parameters": {"service": "config-service", "target_version": "previous"}}
{"action_type": "disable_feature_flag", "parameters": {"flag": "full_history_export"}}
{"action_type": "execute_runbook_step", "parameters": {"runbook_action": "restore_bgp_routes"}}
{"action_type": "scale_service",        "parameters": {"service": "image-service", "replicas": 10}}
{"action_type": "clear_cache",          "parameters": {"service": "redis-session"}}
```

### 📝 Submission Actions (end episode)

```json
{"action_type": "submit_severity",   "parameters": {"severity": "P1", "service": "api-gateway"}}
{"action_type": "submit_root_cause", "parameters": {"service": "analytics-service", "failure_mode": "unbounded query OOM killing postgres-db"}}
{"action_type": "submit_resolution", "parameters": {"summary": "3+ sentence description of what failed, what you did, and current status"}}
```

---

## Reward Function

Dense reward shaping provides signal over the **full trajectory** (not just binary end-of-episode):

| Signal | Reward | Description |
|---|---|---|
| Query new service | +0.03 to +0.04 | First diagnostic action on a service |
| Query new action type | +0.01 to +0.02 | Different diagnostic on already-queried service |
| Repeat same query | −0.03 to −0.04 | Same (action, service) pair again |
| Unknown service | −0.05 to −0.06 | Service not in known_services |
| Correct remediation | +0.06 | Action matches correct remediation sequence |
| Wrong remediation | −0.12 to −0.15 | Action in wrong_actions list (e.g. restarting healthy service) |
| Correct submission type | +0.02 | Using the right submit action for the task |
| Wrong submission type | −0.08 to −0.12 | e.g. submit_severity during remediation_planning |
| Past halfway (non-submit) | −0.015 to −0.04 | Per-step efficiency penalty |
| Timeout | −0.15 to −0.20 | No submission before max_steps |
| Exact repeat action | −0.04 to −0.05 | Identical action+params as a previous step |
| **Grader score** | **0.0–1.0** | **Added at terminal step** |

### Grading (deterministic, reproducible, 0.0–1.0)

| Task | Scoring Logic |
|---|---|
| `alert_classification` | 1.0 exact match · 0.5 adjacent (P1↔P2) · 0.25 two-off · 0.0 wrong |
| `root_cause_analysis` | 0.6 base (correct service + failure mode) + up to 0.4 efficiency bonus |
| `remediation_planning` | 0.6 base + 0.3 efficiency (correct steps matched) − 0.15 penalty (wrong actions) + 0.1 summary quality |

---

## 🖥️ Interactive UI Walkthrough

The Gradio UI at `/` provides a visual interface for human evaluation. Here's how to use it:

### 🟢 Easy Task: Alert Classification

1. **Select Task**: Choose `🟢 Easy — Alert Classification` from the Task dropdown
2. **Select Scenario**: Choose `Scenario 2` (the tricky P3 trap)
3. **Click** `🔄 Reset Environment`
4. **Read** the observation panel — recommendation-service errors at 45%
5. **Investigate**: Set Action Type to `🔍 check_metrics`, Service to `recommendation-service`, click `▶️ Execute Action`
6. **Read evidence** — "User impact: NONE", "Revenue: unchanged", "Checkout: 100%"
7. **Submit**: Set Action Type to `📝 submit_severity`, expand `📋 Parameters`, set Severity to `P3 Medium`, click `▶️ Execute Action`
8. **Grade**: Click `📊 Grade` — should show **1.0** for exact P3 match

### 🟡 Medium Task: Root Cause Analysis

1. **Select Task**: `🟡 Medium — Root Cause Analysis`, **Scenario**: `Scenario 0`
2. **Click** `🔄 Reset Environment`
3. **Read** the observation — postgres-db crash loop, multiple services down
4. **Query victim**: Action Type `🔍 query_logs`, Service `postgres-db`, click `▶️ Execute Action`
5. **Read evidence** — logs say *"query from analytics-service consuming all memory"*
6. **Follow breadcrumb**: Action Type `🔍 query_logs`, Service `analytics-service`, click `▶️ Execute Action`
7. **Read evidence** — "full_history_export job", "847M row scan", "no LIMIT"
8. **Confirm**: Action Type `🔍 check_recent_deploys`, Service `analytics-service`, click `▶️ Execute Action`
9. **Read evidence** — "Deploy 6h ago: cross-table JOIN without LIMIT clause"
10. **Submit**: Action Type `📝 submit_root_cause`, Service `analytics-service`, Failure Mode: `unbounded query OOM killing postgres-db`, click `▶️ Execute Action`
11. **Grade**: Click `📊 Grade` — should show **0.85–1.0**

### 🔴 Hard Task: Remediation Planning

1. **Select Task**: `🔴 Hard — Remediation Planning`, **Scenario**: `Scenario 0`
2. **Click** `🔄 Reset Environment`
3. **Diagnose**: `🔍 query_logs` on `postgres-db` → see "analytics-service" breadcrumb
4. **Confirm**: `🔍 query_logs` on `analytics-service` → see "full_history_export, no LIMIT"
5. **Fix Step 1**: `🔧 disable_feature_flag`, Flag: `full_history_export` → "job DISABLED"
6. **Fix Step 2**: `🔧 restart_service` on `analytics-service` → "restarted — idle"
7. **Fix Step 3**: `🔧 restart_service` on `postgres-db` → "accepting connections (12/500)"
8. **Fix Step 4**: `🔧 restart_service` on `auth-service` → "reconnected OK"
9. **Fix Step 5**: `🔧 restart_service` on `order-service` → "writes resuming"
10. **Verify**: `🔧 execute_runbook_step`, Runbook Action: `verify_db_health` → "healthy"
11. **Submit**: `📝 submit_resolution`, Summary: *"The analytics-service deployed a full_history_export job with an unbounded query that OOM-killed postgres-db. We disabled the full_history_export flag, restarted analytics-service, then restarted postgres-db, auth-service, and order-service. All services recovered and postgres-db is healthy."*
12. **Grade**: Click `📊 Grade` — should show **0.85–1.0**

### UI Controls Reference

| Button | Purpose |
|---|---|
| `🔄 Reset Environment` | Start a new episode |
| `▶️ Execute Action` | Run the selected action |
| `📋 Parameters` | Expand to fill severity / failure_mode / summary / flag / runbook fields |
| `📊 Grade` | See final grader score (0.0–1.0) after episode ends |
| `📋 State` | Refresh the state panel |

### Common Mistakes & Penalties

| Mistake | Penalty | Why |
|---|---|---|
| Wrong submission type (e.g. `submit_severity` in hard task) | −0.12 | Each task has ONE correct submission action |
| Restarting a healthy service (e.g. `restart redis-session`) | −0.15 | Wrong remediation action |
| Querying a service not in `known_services` | −0.06 | Invalid target |
| Repeating the exact same action | −0.04 | Infinite loop detection |
| Not submitting before max steps | −0.20 | Timeout penalty |
| Using remediation actions in easy task | −0.08 | Not available for alert classification |

---

## API Usage

### Quick Test

```bash
# Reset with defaults (alert_classification, scenario 0)
curl -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" -d '{}'

# Reset with specific task
curl -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" \
  -d '{"task_id": "root_cause_analysis", "scenario_index": 1}'

# Take a step
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"action_type": "query_logs", "parameters": {"service": "postgres-db"}}'

# Check state
curl http://localhost:7860/state

# Grade current episode
curl http://localhost:7860/grader
```

### Full Episode Example (Python)

```python
import requests

BASE = "http://localhost:7860"

# Start episode
obs = requests.post(f"{BASE}/reset", json={
    "task_id": "alert_classification", "scenario_index": 0
}).json()

print(f"Incident: {obs['incident_summary']}")
print(f"Services: {obs['known_services']}")

# Investigate
result = requests.post(f"{BASE}/step", json={
    "action_type": "check_metrics",
    "parameters": {"service": obs["known_services"][0]}
}).json()

print(f"Reward: {result['reward']['score']:+.3f}")
print(f"Done: {result['done']}")

# Submit
result = requests.post(f"{BASE}/step", json={
    "action_type": "submit_severity",
    "parameters": {"severity": "P1", "service": obs["known_services"][0]}
}).json()

# Grade
grade = requests.get(f"{BASE}/grader").json()
print(f"Score: {grade['total']}")
```

---

## Setup

### Local Development

```bash
pip install -r requirements.txt
uvicorn server.app:app --host 0.0.0.0 --port 7860
```

### Docker

```bash
docker build -t cloud-incident-env .
docker run -p 7860:7860 cloud-incident-env
```

### Run Baseline Agent

```bash
export API_BASE_URL="https://api.groq.com/openai/v1"
export MODEL_NAME="llama-3.1-8b-instant"
export HF_TOKEN="gsk_your_groq_key"
python inference.py
```

---

## Project Structure

```
├── Dockerfile              # Docker build for HF Spaces
├── README.md               # This file
├── requirements.txt        # Python dependencies
├── openenv.yaml            # OpenEnv manifest (tasks, endpoints)
├── pyproject.toml           # Project metadata
├── tasks.py                # 9 scenarios across 3 difficulty levels
├── graders.py              # Deterministic graders (0.0–1.0)
├── inference.py            # Baseline LLM agent with fallback logic
└── server/
    ├── __init__.py
    ├── app.py              # FastAPI + Gradio endpoints
    ├── environment.py      # Core step/reset/state logic + reward shaping
    └── models.py           # Typed Pydantic models (Action, Observation, Reward)
```

---

## Design Decisions

### Why Cloud Incident Response?

Every cloud company employs SREs who respond to production incidents under time pressure with incomplete information. This is a universal, high-value skill that AI agents should learn. The environment simulates the exact decision loop: triage → investigate → diagnose → remediate → document.

### Why These Specific Incidents?

- **OOM kills** (RCA-001, RP-001): The most common database failure mode — a runaway query consumes all memory and crashes the DB, taking down every dependent service.
- **BGP partitions** (RCA-002, RP-002): Network-layer failures that look like application failures — services appear "down" but are actually healthy, just unreachable.
- **Credential rotation bugs** (RCA-003, RP-003): Configuration management failures that cause cascading auth failures — the DB is fine but clients have wrong passwords.

### Why Dense Rewards?

Sparse rewards (only at episode end) provide no learning signal for RL agents. Our reward function gives feedback on **every step**: positive for useful investigation, negative for wasted actions, with the terminal grader score layered on top. This enables both RL training and LLM agent evaluation.
```