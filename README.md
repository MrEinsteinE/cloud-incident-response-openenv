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

An OpenEnv environment for training and evaluating AI agents on **cloud SRE incident response** — the real-world on-call workflow that engineers at every cloud company perform daily.

Distinct from Kubernetes operations environments: this focuses on **cross-service cascading failures** in distributed microservice architectures — connection pool exhaustion, CDN cache storms, OOM kills, credential rotation failures, and BGP network partitions.

## Authors

- **Einstein** — Environment Design & Grader Implementation
- **Sidra** — Scenario Design & Testing

---

## 🎯 Why This Environment

Every cloud company employs SREs who respond to production incidents under time pressure with incomplete information. This environment simulates the exact decision loop:

| Phase | What the Agent Does |
|---|---|
| **Triage** | Read alert, assess blast radius, classify severity (P1–P4) |
| **Investigate** | Query logs, metrics, dependencies, recent deploys |
| **Diagnose** | Correlate signals across services to find root cause |
| **Remediate** | Execute correct runbook steps in the right sequence |
| **Document** | Submit resolution summary for post-incident review |

Agents trained here learn the same skills a human SRE develops: service dependency traversal, log correlation, cascading failure analysis, and targeted remediation.

---

## 📊 Baseline Scores

Using `Llama 3.1 8B Instruct` · deterministic (`temperature=0.0`) · fully reproducible

| Task | Difficulty | S0 | S1 | S2 | Average |
|---|---|---|---|---|---|
| `alert_classification` | 🟢 Easy | 1.00 | 1.00 | 1.00 | **1.00** |
| `root_cause_analysis` | 🟡 Medium | 1.00 | 0.20 | 1.00 | **0.73** |
| `remediation_planning` | 🔴 Hard | 0.60 | 0.45 | 0.59 | **0.55** |
| **Overall** | | | | | **0.76** |

### Score Interpretation

```
Easy   1.00 ████████████████████  Clear metrics → straightforward classification
Medium 0.73 ██████████████▌       Root cause hidden — model fails on BGP scenario (S1=0.20)
Hard   0.55 ███████████           Multi-phase execution with wrong-action penalties
```

- **Easy → 1.00:** Alert metrics (error rate, revenue impact) directly indicate severity. An 8B model reliably classifies P1/P2/P3 with 2 diagnostic queries.
- **Medium → 0.73:** Root cause service is NOT in the alert. Model must investigate beyond the blast radius. Succeeds on OOM and credential scenarios but fails on BGP network partition (S1=0.20) where no victim log names the root cause.
- **Hard → 0.55:** Same diagnostic challenge as medium PLUS multi-step remediation sequence, wrong-action penalties (−0.10 each), and documentation quality scoring. Model wastes steps on repeated status checks and sometimes executes counterproductive remediations.

---

## 🏗️ Tasks

| Task ID | Difficulty | Max Steps | Objective | Submission Action |
|---|---|---|---|---|
| `alert_classification` | 🟢 Easy | 3 | Classify alert severity (P1–P4) | `submit_severity` |
| `root_cause_analysis` | 🟡 Medium | 10 | Find root cause service + failure mode | `submit_root_cause` |
| `remediation_planning` | 🔴 Hard | 15 | Diagnose + remediate + document | `submit_resolution` |

### Scenarios (3 per task = 9 total episodes)

| ID | Incident Type | Root Cause | Why It's Hard |
|---|---|---|---|
| AC-001 | DB connection pool exhaustion | — | Clear P1: 78% errors, $12k/min revenue loss |
| AC-002 | CDN cache invalidation storm | — | Ambiguous P2: degraded but checkout works |
| AC-003 | Recommendation service errors | — | Trap P3: 45% errors but zero revenue impact |
| RCA-001 | Postgres OOM kill | analytics-service | Must correlate "analytics export query" in DB logs |
| RCA-002 | BGP network partition | network-infra | No victim log names network-infra — hardest scenario |
| RCA-003 | Credential rotation bug | config-service | Must trace "secrets rotation" hint to config-service |
| RP-001 | Full OOM remediation | analytics-service | 6-step sequence: disable job → restart chain |
| RP-002 | Full BGP remediation | network-infra | 4-step sequence: restore routes → rollback → verify |
| RP-003 | Full credential fix | config-service | 7-step sequence: rollback → rotate → restart → verify |

---

## 🎮 Action Space

### Diagnostic Actions (gather evidence)
```json
{"action_type": "query_logs",           "parameters": {"service": "<name>"}}
{"action_type": "check_metrics",        "parameters": {"service": "<name>"}}
{"action_type": "check_dependencies",   "parameters": {"service": "<name>"}}
{"action_type": "check_recent_deploys", "parameters": {"service": "<name>"}}
{"action_type": "check_service_status", "parameters": {"service": "<name>"}}
```

### Remediation Actions (fix the incident)
```json
{"action_type": "restart_service",      "parameters": {"service": "<name>"}}
{"action_type": "rollback_deploy",      "parameters": {"service": "<name>"}}
{"action_type": "scale_service",        "parameters": {"service": "<name>", "replicas": 10}}
{"action_type": "disable_feature_flag", "parameters": {"flag": "<flag_name>"}}
{"action_type": "clear_cache",          "parameters": {"service": "<name>"}}
{"action_type": "execute_runbook_step", "parameters": {"runbook_action": "<action>"}}
```

### Submission Actions (end the episode)
```json
{"action_type": "submit_severity",   "parameters": {"severity": "P1|P2|P3|P4", "service": "<name>"}}
{"action_type": "submit_root_cause", "parameters": {"service": "<name>", "failure_mode": "<description>"}}
{"action_type": "submit_resolution", "parameters": {"summary": "<3+ sentence summary>"}}
```

---

## 👁️ Observation Space

| Field | Type | Description |
|---|---|---|
| `episode_id` | string | Unique episode UUID |
| `task_id` | string | Active task identifier |
| `scenario_id` | string | Current scenario (e.g., `RCA-001`) |
| `step_count` / `max_steps` | int | Progress through episode |
| `incident_summary` | string | Plain-text incident description (no root cause hints) |
| `alert` | dict | Alert payload with severity, symptoms, affected services |
| `available_actions` | list | Valid action types for this task |
| `queried_data` | dict | All evidence gathered so far |
| `known_services` | list | Exact service names valid for actions |
| `cumulative_reward` | float | Running reward total |
| `done` | bool | Episode terminal flag |
| `feedback` | string | Per-step feedback explaining reward |
| `last_action_error` | string? | Error message if last action was invalid |

---

## 💰 Reward Function

Dense reward shaping throughout the trajectory — not just terminal scoring.

### Per-Step Rewards

| Event | Easy | Medium | Hard |
|---|---|---|---|
| Query new service (first time) | +0.04 | +0.04 | +0.03 |
| Query new action on known service | +0.02 | +0.02 | +0.01 |
| Repeat exact same query | −0.03 | −0.04 | −0.03 |
| Query unknown service | −0.06 | −0.06 | −0.05 |
| Correct remediation action | — | +0.06 | +0.06 |
| Wrong remediation action | −0.08 | −0.10 | −0.15 |
| Step past halfway (non-submit) | −0.04 | −0.02 | −0.02 |
| Timeout without submission | −0.15 | −0.15 | −0.20 |

### Grader Scoring (terminal, deterministic)

| Task | Scoring Logic |
|---|---|
| `alert_classification` | 1.0 exact · 0.5 adjacent · 0.25 two-off · 0.0 wrong |
| `root_cause_analysis` | Up to 0.6 base (service + failure mode) + up to 0.4 efficiency bonus. Wrong service: 0.05–0.20 based on investigation effort |
| `remediation_planning` | Scaled base (0.10–0.50 by investigation depth) + 0.30 efficiency − up to 0.30 wrong-action penalty + 0.10 summary quality |

---

## 🔌 API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Gradio UI — interactive environment demo |
| `GET` | `/health` | `{"status":"ok","version":"0.1.0"}` |
| `POST` | `/reset` | Start new episode (accepts `task_id`, `scenario_index`) |
| `POST` | `/step` | Submit action → returns observation, reward, done, info |
| `GET` | `/state` | Full current episode state with action history |
| `GET` | `/tasks` | All tasks with action schemas |
| `GET` | `/grader` | Score current episode (0.0–1.0) with breakdown |

---

## 🚀 Setup & Usage

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

### Run Baseline Inference
```bash
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="meta-llama/Llama-3.1-8B-Instruct"
export HF_TOKEN="your_token"
python inference.py
```

### Quick API Test
```bash
# Reset
curl -X POST "http://localhost:7860/reset?task_id=alert_classification&scenario_index=0"

# Step
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"action_type":"query_logs","parameters":{"service":"api-gateway"}}'

# Grade
curl http://localhost:7860/grader
```

---

## 📁 Project Structure

```
.
├── Dockerfile              # Container build
├── README.md               # This file
├── requirements.txt        # Python dependencies
├── openenv.yaml            # OpenEnv metadata + task definitions
├── inference.py            # Baseline agent (OpenAI client + smart fallback)
├── tasks.py                # 9 scenarios across 3 difficulty levels
├── graders.py              # Deterministic graders (0.0–1.0)
└── server/
    ├── __init__.py
    ├── app.py              # FastAPI + Gradio endpoints
    ├── environment.py      # Core step()/reset()/state() logic
    └── models.py           # Typed Pydantic models (Action, Observation, Reward)
```

---

## ✅ Validation

```bash
# OpenEnv spec validation
openenv validate    # → [OK] Ready for multi-mode deployment

# Docker build
docker build -t cloud-incident-env .    # → builds successfully

# Health check
curl http://localhost:7860/health       # → {"status":"ok","version":"0.1.0"}
```

## Team
- **Einstein** — [@MrEinsteinE](https://github.com/MrEinsteinE)
- **Sidra** — [@sidraaiman](https://github.com/sidraaiman)