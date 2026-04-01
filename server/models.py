"""
server/models.py — Typed Pydantic v2 models for the OpenEnv interface.

Implements the full OpenEnv spec:
  - Action: typed action with parameters
  - Observation: full environment state visible to the agent
  - Reward: score + reason + cumulative (with backward-compatible 'value' alias)
  - EpisodeState: internal state for GET /state
"""

from __future__ import annotations

from pydantic import BaseModel, Field, computed_field


class ActionParameters(BaseModel):
    """Flexible parameter bag — different action types use different fields."""

    service: str | None = None
    severity: str | None = None
    failure_mode: str | None = None
    summary: str | None = None
    target_version: str | None = None
    replicas: int | None = None
    flag: str | None = None
    runbook_action: str | None = None
    target: str | None = None
    reasoning: str | None = None

    model_config = {"extra": "allow"}


class Action(BaseModel):
    """An action submitted by the agent to the environment.
    
    Attributes:
        action_type: One of the valid action types (query_logs, check_metrics, etc.)
        parameters: Action-specific parameters
    """

    action_type: str
    parameters: ActionParameters = Field(default_factory=ActionParameters)

    model_config = {"extra": "allow"}


class Observation(BaseModel):
    """Observation returned after reset() or step().
    
    Contains all information visible to the agent at this point in the episode.
    
    Attributes:
        episode_id: Unique episode UUID
        task_id: Active task identifier
        scenario_id: Current scenario identifier
        step_count: Number of steps taken so far
        max_steps: Maximum steps allowed
        incident_summary: Human-readable incident description
        alert: Alert payload with severity, symptoms, affected services
        available_actions: List of valid action types for this task
        queried_data: All tool responses gathered so far (evidence)
        cumulative_reward: Running reward total
        done: Whether the episode has ended
        feedback: Per-step feedback string
        known_services: Exact service names valid for actions
        last_action_error: Error message if last action was invalid (None if OK)
    """

    episode_id: str
    task_id: str
    scenario_id: str
    step_count: int
    max_steps: int
    incident_summary: str
    alert: dict
    available_actions: list[str]
    queried_data: dict
    cumulative_reward: float
    done: bool
    feedback: str
    known_services: list[str] = Field(default_factory=list)
    last_action_error: str | None = None


class Reward(BaseModel):
    """Reward signal returned after each step().

    Primary field is ``score`` (the actual reward value).
    ``value`` is a computed alias for backward compatibility with OpenEnv validators.
    
    Attributes:
        score: The reward value for this step
        reason: Human-readable explanation of the reward
        cumulative: Running total of all rewards in the episode
    """

    score: float
    reason: str
    cumulative: float

    @computed_field
    @property
    def value(self) -> float:
        """Backward-compatible alias for *score*."""
        return self.score


class StepResult(BaseModel):
    """Result returned by POST /step — matches OpenEnv spec."""
    
    observation: Observation
    reward: Reward
    done: bool
    info: dict = Field(default_factory=dict)


class EpisodeState(BaseModel):
    """Full episode state returned by GET /state.
    
    Contains internal bookkeeping not shown to agents directly.
    """

    episode_id: str
    task_id: str
    scenario_id: str
    step_count: int
    max_steps: int
    action_history: list[dict]
    queried_data: dict
    submitted: bool
    resolved: bool
    done: bool
    cumulative_reward: float
    feedback: str