"""
server/app.py — FastAPI + Gradio server for Cloud Incident Response OpenEnv.

Endpoints (OpenEnv spec):
  GET  /health  → {"status": "ok"}
  POST /reset   → Observation (accepts JSON body or query params)
  POST /step    → {"observation": ..., "reward": ..., "done": ..., "info": ...}
  GET  /state   → EpisodeState
  GET  /tasks   → task list with action schemas
  GET  /grader  → grading result for current episode
  POST /baseline → run inference.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from server.environment import IncidentEnvironment
from server.models import Action, ActionParameters
from tasks import ALL_TASKS, list_tasks

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_env: IncidentEnvironment | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _env
    _env = IncidentEnvironment()
    yield


def _get_env() -> IncidentEnvironment:
    if _env is None:
        raise HTTPException(503, "Environment initialising — retry in a moment")
    return _env


def _get_env_direct() -> IncidentEnvironment:
    if _env is None:
        raise RuntimeError("Environment not initialised yet")
    return _env


app = FastAPI(
    title="Cloud Incident Response — OpenEnv",
    version="0.1.0",
    description=(
        "OpenEnv environment for training AI agents on cloud SRE incident response. "
        "Implements step()/reset()/state() API with typed Observation, Action, and Reward models."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── OpenEnv API Endpoints ─────────────────────────────────────────────────────


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "version": "0.1.0"}


@app.get("/api/info")
def api_info():
    """Environment metadata."""
    return {
        "status": "running",
        "name": "cloud-incident-response",
        "version": "0.1.0",
        "description": "OpenEnv environment for cloud SRE incident response",
        "tasks": list(ALL_TASKS.keys()),
        "docs": "/docs",
    }


@app.post("/reset")
async def reset(request: Request):
    """Reset the environment and start a new episode.
    
    Accepts task_id and scenario_index via:
      - Query parameters: /reset?task_id=...&scenario_index=...
      - JSON body: {"task_id": "...", "scenario_index": 0}
      - Empty body: uses defaults (alert_classification, scenario 0)
    
    Returns: Observation dict
    """
    task_id = "alert_classification"
    scenario_index = 0

    # Parse query params
    qp = request.query_params
    if qp.get("task_id"):
        task_id = qp["task_id"]
    if qp.get("scenario_index"):
        try:
            scenario_index = int(qp["scenario_index"])
        except ValueError:
            pass

    # Parse JSON body (may be empty {} or have fields)
    try:
        body = await request.json()
        if isinstance(body, dict):
            task_id = body.get("task_id", task_id)
            si = body.get("scenario_index")
            if si is not None:
                scenario_index = int(si)
    except Exception:
        pass  # Empty body or non-JSON is fine — use defaults

    env = _get_env()
    try:
        obs = env.reset(task_id=task_id, scenario_index=scenario_index)
        return obs.model_dump()
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/step")
def step(action: Action):
    """Take one step in the environment.
    
    Accepts: Action JSON body with action_type and parameters
    Returns: {"observation": {...}, "reward": {...}, "done": bool, "info": {...}}
    """
    env = _get_env()
    try:
        obs, reward, done, info = env.step(action)
        return {
            "observation": obs.model_dump(),
            "reward": reward.model_dump(),
            "done": done,
            "info": info,
        }
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/state")
def state():
    """Get the current episode state.
    
    Returns: EpisodeState dict with full action history and internal state
    """
    env = _get_env()
    try:
        return env.state().model_dump()
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/tasks")
def tasks():
    """List all available tasks with action schemas."""
    return {
        "tasks": list_tasks(),
        "total": len(ALL_TASKS),
        "action_schema": {
            "diagnostic": [
                {"action_type": "query_logs", "parameters": {"service": "string"}},
                {"action_type": "check_metrics", "parameters": {"service": "string"}},
                {"action_type": "check_dependencies", "parameters": {"service": "string"}},
                {"action_type": "check_recent_deploys", "parameters": {"service": "string"}},
                {"action_type": "check_service_status", "parameters": {"service": "string"}},
            ],
            "remediation": [
                {"action_type": "restart_service", "parameters": {"service": "string"}},
                {"action_type": "rollback_deploy", "parameters": {"service": "string", "target_version": "string"}},
                {"action_type": "scale_service", "parameters": {"service": "string", "replicas": "int"}},
                {"action_type": "disable_feature_flag", "parameters": {"flag": "string"}},
                {"action_type": "clear_cache", "parameters": {"service": "string"}},
                {"action_type": "execute_runbook_step", "parameters": {"runbook_action": "string"}},
            ],
            "submission": [
                {"action_type": "submit_severity", "parameters": {"severity": "P1|P2|P3|P4", "service": "string"}},
                {"action_type": "submit_root_cause", "parameters": {"service": "string", "failure_mode": "string"}},
                {"action_type": "submit_resolution", "parameters": {"summary": "string"}},
            ],
        },
    }


@app.get("/grader")
def grader():
    """Grade the current episode. Returns score 0.0-1.0 with breakdown."""
    env = _get_env()
    try:
        s = env.state()
        from graders import grade
        result = grade(s.task_id, s.model_dump(), env._scenario)
        return {
            "total": result["total"],
            "breakdown": result["breakdown"],
            "feedback": result["feedback"],
            "task_id": s.task_id,
            "scenario_id": s.scenario_id,
            "steps_used": s.step_count,
            "done": s.done,
        }
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, str(e))


@app.post("/baseline")
def baseline():
    """Run the baseline inference script and return results."""
    script = os.path.join(_ROOT, "inference.py")
    if not os.path.exists(script):
        raise HTTPException(500, "inference.py not found")
    try:
        result = subprocess.run(
            [sys.executable, script],
            capture_output=True, text=True, timeout=1200, cwd=_ROOT,
            env={**os.environ, "ENV_BASE_URL": "http://localhost:7860"},
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(500, "inference.py timed out (>20 min)")

    if result.returncode != 0:
        raise HTTPException(500, result.stderr[-2000:])

    lines = result.stdout.strip().splitlines()
    last = lines[-1] if lines else ""
    try:
        return json.loads(last)
    except Exception:
        return {"raw_output": result.stdout[-3000:]}

@app.get("/status")
def root_status():
    """Root health check — returns JSON."""
    return {
        "status": "running",
        "name": "cloud-incident-response",
        "version": "0.1.0",
        "tasks": list(ALL_TASKS.keys()),
    }
# ── Gradio UI ─────────────────────────────────────────────────────────────────

import gradio as gr

DIFFICULTY_BADGE = {
    "alert_classification": "🟢 Easy",
    "root_cause_analysis": "🟡 Medium",
    "remediation_planning": "🔴 Hard",
}

DIFFICULTY_INFO = {
    "alert_classification": "3 steps · Classify severity P1–P4",
    "root_cause_analysis": "10 steps · Find root cause service + failure mode",
    "remediation_planning": "15 steps · Diagnose, fix, and document",
}

SUBMIT_ACTION = {
    "alert_classification": "submit_severity",
    "root_cause_analysis": "submit_root_cause",
    "remediation_planning": "submit_resolution",
}

_DIAG_ACTIONS = [
    "query_logs", "check_metrics", "check_dependencies",
    "check_recent_deploys", "check_service_status",
]
_REM_ACTIONS = [
    "restart_service", "rollback_deploy", "scale_service",
    "disable_feature_flag", "clear_cache", "execute_runbook_step",
]


def _fmt_obs(obs: dict) -> str:
    lines = []
    lines.append(f"### 📋 Scenario `{obs.get('scenario_id', '—')}`\n")
    summary = obs.get("incident_summary", "")
    if summary:
        lines.append(f"> {summary[:600]}\n")
    alert = obs.get("alert", {})
    if alert:
        lines.append("#### 🔔 Alert Details\n")
        if alert.get("title"):
            lines.append(f"**Title:** {alert['title']}\n")
        symptoms = alert.get("symptoms", [])
        if symptoms:
            lines.append("**Symptoms:**")
            for s in symptoms:
                lines.append(f"- {s}")
            lines.append("")
        info_items = []
        if alert.get("error_rate") is not None:
            info_items.append(f"Error Rate: **{alert['error_rate']:.0%}**")
        if alert.get("duration_minutes") is not None:
            info_items.append(f"Duration: **{alert['duration_minutes']} min**")
        if alert.get("revenue_impact_per_min") is not None:
            info_items.append(f"Revenue: **${alert['revenue_impact_per_min']:,.0f}/min**")
        if info_items:
            lines.append(" · ".join(info_items) + "\n")
    known = obs.get("known_services", [])
    if known:
        lines.append(f"#### 🖥️ Known Services\n`{'` · `'.join(known)}`\n")
    task_id = obs.get("task_id", "")
    submit = SUBMIT_ACTION.get(task_id, "")
    if submit:
        diff = DIFFICULTY_INFO.get(task_id, "")
        lines.append(f"#### 📝 Submit: `{submit}`")
        if diff:
            lines.append(f"*{diff}*\n")
    err = obs.get("last_action_error")
    if err:
        lines.append(f"#### ⚠️ Last Action Error\n`{err}`\n")
    qd = obs.get("queried_data", {})
    if qd:
        lines.append("---\n#### 📊 Evidence Collected\n")
        for action_type, services in qd.items():
            if isinstance(services, dict):
                for svc, data in services.items():
                    d = str(data)
                    if len(d) > 400:
                        d = d[:400] + " …"
                    lines.append(f"**`[{action_type}]` → `{svc}`**")
                    lines.append(f"```\n{d}\n```\n")
    return "\n".join(lines)


def _fmt_state(s: dict) -> str:
    task_id = s.get("task_id", "—")
    diff = DIFFICULTY_BADGE.get(task_id, "")
    done = s.get("done", False)
    status = "🏁 Complete" if done else "⚡ Active"
    step_count = s.get("step_count", 0)
    max_steps = s.get("max_steps", 0)
    cum_reward = s.get("cumulative_reward", 0.0)
    pct = (step_count / max_steps * 100) if max_steps > 0 else 0
    bar_filled = int(pct / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)

    return (
        f"### {status}\n\n"
        f"| Field | Value |\n|---|---|\n"
        f"| **Task** | `{task_id}` {diff} |\n"
        f"| **Episode** | `{s.get('episode_id', '—')[:12]}…` |\n"
        f"| **Progress** | {step_count}/{max_steps} `{bar}` {pct:.0f}% |\n"
        f"| **Reward** | `{cum_reward:+.4f}` |\n"
        f"| **Submitted** | {'✅' if s.get('submitted') else '❌'} |\n"
    )


def _fmt_history(action_history: list[dict]) -> str:
    if not action_history:
        return "*No actions yet.*"
    lines = ["| Step | Action | Parameters |", "|:---:|---|---|"]
    for a in action_history:
        step = a.get("step", "?")
        at = a.get("action_type", "?")
        p = a.get("parameters", {})
        p_str = ", ".join(f"`{k}={v}`" for k, v in p.items() if v) or "—"
        icon = "🔍" if at in _DIAG_ACTIONS else ("🔧" if at in _REM_ACTIONS else "📝")
        lines.append(f"| {step} | {icon} `{at}` | {p_str} |")
    return "\n".join(lines)


def _fmt_reward(reward_text: str, grader_result: dict | None = None) -> str:
    lines = [reward_text]
    if grader_result:
        total = grader_result.get("total", 0.0)
        emoji = "🟢" if total >= 0.8 else ("🟡" if total >= 0.5 else "🔴")
        lines.append(f"\n### {emoji} Grader Score: **{total:.4f}** / 1.0\n")
        bd = grader_result.get("breakdown", {})
        if bd:
            lines.append("| Component | Value |\n|---|---|")
            for k, v in bd.items():
                lines.append(f"| {k} | `{v}` |")
            lines.append("")
        fb = grader_result.get("feedback", "")
        if fb:
            lines.append(f"> {fb}")
    return "\n".join(lines)


def _gr_reset(task_id: str, scenario_index: str):
    try:
        env = _get_env_direct()
        obs = env.reset(task_id=task_id, scenario_index=int(scenario_index))
        st = env.state()
        services = obs.known_services
        return (
            _fmt_obs(obs.model_dump()),
            _fmt_state(st.model_dump()),
            _fmt_history([]),
            "✅ Episode started.",
            gr.Dropdown(choices=services, value=services[0] if services else None),
        )
    except Exception as e:
        err = f"❌ **Error:** {e}"
        return (err, err, "", err, gr.Dropdown(choices=[]))


def _gr_step(action_type, service, severity, failure_mode, summary, flag, runbook_action, target_version):
    try:
        env = _get_env_direct()
        params = ActionParameters(
            service=service or None, severity=severity if severity else None,
            failure_mode=failure_mode or None, summary=summary or None,
            flag=flag or None, runbook_action=runbook_action or None,
            target_version=target_version or None,
        )
        action = Action(action_type=action_type, parameters=params)
        obs, reward, done, info = env.step(action)
        st = env.state()
        reward_text = (
            f"### Step Reward: `{reward.score:+.4f}`\n\n"
            f"**Cumulative:** `{reward.cumulative:+.4f}`\n\n"
            f"**Feedback:** {reward.reason}"
        )
        if done:
            reward_text += "\n\n---\n🏁 **EPISODE COMPLETE** — Click **Grade Episode**"
        return (
            _fmt_obs(obs.model_dump()),
            _fmt_state(st.model_dump()),
            _fmt_history(st.action_history),
            reward_text,
        )
    except Exception as e:
        err = f"❌ **Error:** {e}"
        return (err, "", "", err)


def _gr_grade():
    try:
        env = _get_env_direct()
        s = env.state()
        from graders import grade
        result = grade(s.task_id, s.model_dump(), env._scenario)
        return _fmt_reward("### Final Grading", result)
    except Exception as e:
        return f"❌ {e}"


def _gr_state():
    try:
        env = _get_env_direct()
        return _fmt_state(env.state().model_dump())
    except Exception as e:
        return f"❌ {e}"


CUSTOM_CSS = """
:root, html, body, .gradio-container { color-scheme: light !important; }
body.dark, html.dark, .dark {
    color-scheme: light !important;
    --body-background-fill: #ffffff !important;
    --background-fill-primary: #ffffff !important;
    --background-fill-secondary: #f8fafc !important;
}
.gradio-container {
    background: #ffffff !important;
    max-width: 1500px !important;
    margin: 0 auto !important;
}
.env-header {
    display: flex; justify-content: space-between; align-items: center;
    padding: 20px 16px; border-bottom: 2px solid #e2e8f0;
    margin-bottom: 20px; background: linear-gradient(135deg, #f8fafc, #ffffff);
    border-radius: 12px 12px 0 0;
}
.env-header-left {
    display: flex; align-items: center; gap: 14px;
    font-size: 1.5rem; font-weight: 800; color: #0f172a;
}
.env-header-dot {
    width: 14px; height: 14px; border-radius: 50%;
    background: #22c55e; box-shadow: 0 0 8px rgba(34,197,94,0.4);
}
.env-header-right { font-size: 0.9rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; }
.section-title {
    font-weight: 700; font-size: 0.95rem; color: #1e293b;
    margin: 16px 0 8px; padding: 8px 12px; background: #f1f5f9;
    border-radius: 8px; border-left: 3px solid #3b82f6;
}
"""

FORCE_LIGHT_JS = """
function() {
    document.body.classList.remove('dark');
    document.documentElement.classList.remove('dark');
    document.documentElement.style.setProperty('color-scheme', 'light');
}
"""

with gr.Blocks(
    title="Cloud Incident Response — OpenEnv",
    css=CUSTOM_CSS, js=FORCE_LIGHT_JS,
    theme=gr.themes.Soft(primary_hue="blue", neutral_hue="slate",
                         font=gr.themes.GoogleFont("Inter")),
) as demo:

    gr.HTML("""
    <div class="env-header">
        <div class="env-header-left">
            <span class="env-header-dot"></span> ☁️ Cloud Incident Response
        </div>
        <span class="env-header-right">OpenEnv · v0.1.0</span>
    </div>
    """)

    with gr.Accordion("📖 How to Use", open=False):
        gr.Markdown("""
### Quick Start
1. Select **Task** + **Scenario** → Click **🔄 Reset**
2. Choose **Action Type** + **Service** → Click **▶️ Execute**
3. Repeat: investigate → remediate → submit
4. Click **📊 Grade** for final score (0.0–1.0)

### Tasks
| Task | Difficulty | Steps | Submission |
|---|---|---|---|
| `alert_classification` | 🟢 Easy | 3 | `submit_severity` |
| `root_cause_analysis` | 🟡 Medium | 10 | `submit_root_cause` |
| `remediation_planning` | 🔴 Hard | 15 | `submit_resolution` |

### Important
- **Medium/Hard**: `check_recent_deploys` requires prior `query_logs` or `check_metrics` on that service
- Each action gives immediate reward feedback
- Wrong remediation actions are penalized
        """)

    with gr.Row(equal_height=False):
        with gr.Column(scale=2, min_width=380):
            gr.HTML('<div class="section-title">🎯 Episode Setup</div>')
            with gr.Row():
                task_dd = gr.Dropdown(
                    choices=[("🟢 Easy — Alert Classification", "alert_classification"),
                             ("🟡 Medium — Root Cause Analysis", "root_cause_analysis"),
                             ("🔴 Hard — Remediation Planning", "remediation_planning")],
                    value="alert_classification", label="Task", scale=2)
                scenario_dd = gr.Dropdown(
                    choices=[("Scenario 0", "0"), ("Scenario 1", "1"), ("Scenario 2", "2")],
                    value="0", label="Scenario", scale=1)
            reset_btn = gr.Button("🔄 Reset Environment", variant="secondary", size="lg")

            gr.HTML('<div class="section-title">🎮 Action Controls</div>')
            action_type_dd = gr.Dropdown(
                choices=[("🔍 query_logs", "query_logs"), ("🔍 check_metrics", "check_metrics"),
                         ("🔍 check_dependencies", "check_dependencies"),
                         ("🔍 check_recent_deploys", "check_recent_deploys"),
                         ("🔍 check_service_status", "check_service_status"),
                         ("🔧 restart_service", "restart_service"),
                         ("🔧 rollback_deploy", "rollback_deploy"),
                         ("🔧 scale_service", "scale_service"),
                         ("🔧 disable_feature_flag", "disable_feature_flag"),
                         ("🔧 clear_cache", "clear_cache"),
                         ("🔧 execute_runbook_step", "execute_runbook_step"),
                         ("📝 submit_severity", "submit_severity"),
                         ("📝 submit_root_cause", "submit_root_cause"),
                         ("📝 submit_resolution", "submit_resolution")],
                value="query_logs", label="Action Type")
            service_dd = gr.Dropdown(choices=[], label="Target Service",
                                     allow_custom_value=True, info="Populated after Reset")

            with gr.Accordion("📋 Parameters", open=False):
                severity_dd = gr.Dropdown(
                    choices=[("—", ""), ("P1 Critical", "P1"), ("P2 High", "P2"),
                             ("P3 Medium", "P3"), ("P4 Low", "P4")],
                    value="", label="Severity")
                failure_mode_input = gr.Textbox(label="Failure Mode", lines=1,
                                                placeholder="e.g. unbounded query OOM killing postgres-db")
                summary_input = gr.Textbox(label="Resolution Summary", lines=4,
                                           placeholder="3+ sentences: what failed, what you did, status")
                flag_input = gr.Textbox(label="Feature Flag", lines=1, placeholder="e.g. full_history_export")
                runbook_input = gr.Textbox(label="Runbook Action", lines=1, placeholder="e.g. restore_bgp_routes")
                target_version_input = gr.Textbox(label="Target Version", lines=1, placeholder="e.g. previous")

            step_btn = gr.Button("▶️ Execute Action", variant="primary", size="lg")

            gr.HTML('<div class="section-title">📊 Controls</div>')
            with gr.Row():
                grade_btn = gr.Button("📊 Grade", variant="secondary", size="sm")
                state_btn = gr.Button("📋 State", variant="secondary", size="sm")

            gr.HTML('<div class="section-title">📌 State</div>')
            state_display = gr.Markdown("### ⏳ Ready\n\nSelect task → Reset → Begin")

        with gr.Column(scale=3, min_width=480):
            gr.HTML('<div class="section-title">👁️ Observation</div>')
            obs_display = gr.Markdown("### 👋 Welcome\n\nSelect a task and click **Reset** to begin.")

            gr.HTML('<div class="section-title">📜 History</div>')
            history_display = gr.Markdown("*No actions yet.*")

            gr.HTML('<div class="section-title">💰 Reward</div>')
            reward_display = gr.Markdown("*Start an episode first.*")

    reset_btn.click(fn=_gr_reset, inputs=[task_dd, scenario_dd],
                    outputs=[obs_display, state_display, history_display, reward_display, service_dd])
    step_btn.click(fn=_gr_step,
                   inputs=[action_type_dd, service_dd, severity_dd, failure_mode_input,
                           summary_input, flag_input, runbook_input, target_version_input],
                   outputs=[obs_display, state_display, history_display, reward_display])
    grade_btn.click(fn=_gr_grade, outputs=[reward_display])
    state_btn.click(fn=_gr_state, outputs=[state_display])

app = gr.mount_gradio_app(app, demo, path="/")


def main():
    """Start the OpenEnv server."""
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860, reload=False)


if __name__ == "__main__":
    main()