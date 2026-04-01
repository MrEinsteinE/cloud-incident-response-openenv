"""
tasks.py — Task and scenario definitions for Cloud Incident Response OpenEnv.

Difficulty calibration targets:
  EASY   → 8B: 0.75-1.0,  70B: 0.85-1.0
  MEDIUM → 8B: 0.30-0.50,  70B: 0.45-0.65
  HARD   → 8B: 0.15-0.35,  70B: 0.30-0.50

Design principles for genuine difficulty:
  EASY: Alert metrics are clear. Only trick is P2-vs-P3 ambiguity.
  MEDIUM: Root cause buried. 8-10 known services. Multiple red herrings.
    incident_summary does NOT hint at root cause. Must investigate 4+ services.
  HARD: Same diagnosis challenge + 5-7 step remediation sequence +
    10+ known services (many wrong choices) + quality summary required.

Public API:
    get_task(task_id)            -> task metadata dict
    get_scenario(task_id, index) -> scenario dict
    list_tasks()                 -> list of task dicts
    ALL_TASKS                    -> dict[task_id -> metadata]
"""

from __future__ import annotations

ALL_TASKS: dict = {
    "alert_classification": {
        "id": "alert_classification",
        "name": "Task 1: Alert Severity Classification",
        "difficulty": "easy",
        "max_steps": 3,
        "score_range": [0.0, 1.0],
        "description": (
            "An alert has fired. Query logs and metrics across affected services, "
            "then classify the incident severity: P1 (CRITICAL — complete outage or "
            "revenue >$1,000/min), P2 (HIGH — major degradation affecting most users), "
            "P3 (MEDIUM — partial/minor issue with graceful fallback), "
            "P4 (LOW — informational). Submit with submit_severity."
        ),
        "available_actions": [
            "query_logs",
            "check_metrics",
            "check_dependencies",
            "check_recent_deploys",
            "submit_severity",
        ],
        "submission_action": "submit_severity",
        "scenarios": 3,
    },
    "root_cause_analysis": {
        "id": "root_cause_analysis",
        "name": "Task 2: Root Cause Analysis",
        "difficulty": "medium",
        "max_steps": 10,
        "score_range": [0.0, 1.0],
        "description": (
            "A production incident is active with multiple services showing errors. "
            "Use diagnostic tools to trace the failure chain. The root cause may be "
            "any service in the system — not necessarily one showing errors. "
            "Query logs, metrics, dependencies, and recent deploys across ALL "
            "available services to find the true trigger. Submit with submit_root_cause."
        ),
        "available_actions": [
            "query_logs",
            "check_metrics",
            "check_dependencies",
            "check_recent_deploys",
            "check_service_status",
            "submit_root_cause",
        ],
        "submission_action": "submit_root_cause",
        "scenarios": 3,
    },
    "remediation_planning": {
        "id": "remediation_planning",
        "name": "Task 3: Incident Remediation",
        "difficulty": "hard",
        "max_steps": 15,
        "score_range": [0.0, 1.0],
        "description": (
            "A critical production incident requires full end-to-end resolution. "
            "Diagnose the root cause among many services, execute the correct "
            "remediation sequence (order matters — wrong actions are penalized), "
            "then submit a detailed resolution summary. Scored on diagnosis quality, "
            "remediation correctness, action efficiency, and documentation."
        ),
        "available_actions": [
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
            "submit_resolution",
        ],
        "submission_action": "submit_resolution",
        "scenarios": 3,
    },
}

# ---------------------------------------------------------------------------
# Scenario data — 3 tasks × 3 scenarios = 9 total episodes
# ---------------------------------------------------------------------------

SCENARIOS: dict = {

    # ══════════════════════════════════════════════════════════════════════
    # TASK 1: ALERT CLASSIFICATION (EASY)
    # Target: 8B→0.75-1.0, 70B→0.85-1.0
    #
    # AC-001: Clear P1 (78% errors, $12k/min) — should be trivial
    # AC-002: Ambiguous P2 (degraded but working, $800/min)
    # AC-003: Trap P3 (45% errors but zero revenue impact, graceful fallback)
    # ══════════════════════════════════════════════════════════════════════

    "alert_classification": [
        # AC-001: Clear P1
        {
            "scenario_id": "AC-001",
            "description": (
                "Cascading failure across multiple services. "
                "Assess severity based on user and revenue impact."
            ),
            "incident_summary": (
                "Alert fired: api-gateway reporting elevated error rates. "
                "Multiple downstream services affected. "
                "Assess the severity of this incident."
            ),
            "alert": {
                "id": "ALT-20240315-001",
                "title": "api-gateway error rate elevated",
                "severity_fired": "UNCLASSIFIED",
                "affected_services": ["api-gateway", "auth-service", "postgres-db"],
                "symptoms": [
                    "api-gateway: HTTP 503 rate 78% (baseline: 0.1%)",
                    "auth-service: connection timeout 94% of requests",
                    "postgres-db: connection pool 500/500 utilized",
                    "checkout flow: unavailable",
                    "user logins: failing",
                ],
                "error_rate": 0.78,
                "duration_minutes": 4,
                "revenue_impact_per_min": 12000,
            },
            "known_services": {"api-gateway", "auth-service", "postgres-db"},
            "tool_responses": {
                "query_logs": {
                    "api-gateway": (
                        "2024-03-15T10:04:12Z ERROR upstream timeout auth-service:8080\n"
                        "2024-03-15T10:04:13Z ERROR 503 Service Unavailable\n"
                        "2024-03-15T10:04:14Z ERROR circuit breaker OPEN"
                    ),
                    "auth-service": (
                        "2024-03-15T10:04:10Z ERROR too many clients already\n"
                        "2024-03-15T10:04:11Z ERROR connection pool exhausted (500/500)"
                    ),
                    "postgres-db": (
                        "2024-03-15T10:04:00Z FATAL remaining slots reserved for superuser\n"
                        "2024-03-15T10:04:01Z LOG max_connections=500 active=500"
                    ),
                },
                "check_metrics": {
                    "api-gateway": "5xx rate: 78% | p99: 30s | circuit_breaker: OPEN",
                    "auth-service": "Error rate: 94% | DB wait: 28s | Queue: 847",
                    "postgres-db": "Connections: 500/500 (100%) | CPU: 98% | Memory: 89%",
                },
                "check_dependencies": {
                    "api-gateway": "Depends on: auth-service [CRITICAL]",
                    "auth-service": "Depends on: postgres-db [CRITICAL]",
                    "postgres-db": "No upstream dependencies",
                },
                "check_recent_deploys": {
                    "api-gateway": "No recent changes",
                    "auth-service": "Deploy 47 min ago — connection pool size change",
                    "postgres-db": "No recent changes",
                },
            },
            "correct_severity": "P1",
            "adjacent_severities": ["P2"],
        },

        # AC-002: Ambiguous P2 — degraded but not down
        {
            "scenario_id": "AC-002",
            "description": (
                "Service degradation affecting page load times. "
                "Core transaction flows still operational. "
                "Assess severity carefully."
            ),
            "incident_summary": (
                "Alert fired: CDN cache performance degraded. "
                "Origin servers under increased load. "
                "Assess the severity of this incident."
            ),
            "alert": {
                "id": "ALT-20240315-002",
                "title": "CDN cache performance anomaly detected",
                "severity_fired": "UNCLASSIFIED",
                "affected_services": ["cdn-edge", "product-service", "image-service"],
                "symptoms": [
                    "CDN cache hit rate: 3% (normal: 94%)",
                    "product-service: elevated origin traffic",
                    "image-service: CPU 95%, p99 latency 18s",
                    "Product pages: loading slowly",
                    "Checkout: still functional",
                ],
                "error_rate": 0.15,
                "duration_minutes": 8,
                "revenue_impact_per_min": 800,
            },
            "known_services": {"cdn-edge", "product-service", "image-service"},
            "tool_responses": {
                "query_logs": {
                    "cdn-edge": (
                        "2024-03-15T10:22:00Z INFO cache MISS ratio: 97%\n"
                        "2024-03-15T10:20:11Z WARN mass cache invalidation — 2.1M keys purged\n"
                        "2024-03-15T10:20:10Z INFO purge pattern: /* (ALL keys)"
                    ),
                    "product-service": (
                        "2024-03-15T10:22:05Z WARN request queue depth: 12,400\n"
                        "2024-03-15T10:22:06Z ERROR timeout from image-service\n"
                        "2024-03-15T10:22:07Z WARN worker pool 95%"
                    ),
                    "image-service": (
                        "2024-03-15T10:22:00Z WARN CPU throttling 95%\n"
                        "2024-03-15T10:22:01Z ERROR worker pool exhausted\n"
                        "2024-03-15T10:22:02Z WARN memory at 91%"
                    ),
                },
                "check_metrics": {
                    "cdn-edge": "Cache hit: 3% | Origin RPS: 48,000 | Bandwidth: 890 Gbps",
                    "product-service": "Origin RPS: 48k (norm: 1.2k) | Queue: 12,400",
                    "image-service": "CPU: 95% | Memory: 91% | p99: 18s",
                },
                "check_dependencies": {
                    "cdn-edge": "Origin: product-service [OVERLOADED]",
                    "product-service": "Depends on: image-service [DEGRADED]",
                    "image-service": "Depends on: object-storage [OK]",
                },
                "check_recent_deploys": {
                    "cdn-edge": "Cronjob updated 2h ago — purge pattern changed",
                    "product-service": "No recent changes",
                    "image-service": "No recent changes",
                },
            },
            "correct_severity": "P2",
            "adjacent_severities": ["P1", "P3"],
        },

        # AC-003: P3 trap — high error rate but zero impact
        {
            "scenario_id": "AC-003",
            "description": (
                "Internal service reporting elevated errors. "
                "Determine actual user and business impact. "
                "Not all high error rates are critical."
            ),
            "incident_summary": (
                "Alert fired: recommendation-service error rate elevated to 45%. "
                "Assess the severity based on actual user and business impact."
            ),
            "alert": {
                "id": "ALT-20240315-003",
                "title": "recommendation-service error rate 45%",
                "severity_fired": "UNCLASSIFIED",
                "affected_services": ["recommendation-service", "product-service"],
                "symptoms": [
                    "recommendation-service: error rate 45% (baseline: 2%)",
                    "product-service: using fallback recommendation logic",
                    "User experience: default recommendations shown",
                    "Checkout: fully functional",
                    "Revenue: no measurable change",
                ],
                "error_rate": 0.45,
                "duration_minutes": 22,
                "revenue_impact_per_min": 0,
            },
            "known_services": {"recommendation-service", "product-service", "redis-reco-cache"},
            "tool_responses": {
                "query_logs": {
                    "recommendation-service": (
                        "2024-03-15T09:48:00Z ERROR model inference timeout (>5s)\n"
                        "2024-03-15T09:48:01Z WARN ML model server overloaded\n"
                        "2024-03-15T09:48:02Z INFO fallback: returning default recommendations"
                    ),
                    "product-service": (
                        "2024-03-15T09:48:05Z INFO recommendation-service returned defaults\n"
                        "2024-03-15T09:48:06Z INFO serving page with default recs — no user impact"
                    ),
                    "redis-reco-cache": "Operating normally — cache hit rate 88%",
                },
                "check_metrics": {
                    "recommendation-service": (
                        "Error rate: 45% | Fallback rate: 45% | "
                        "Model server: OVERLOADED | User impact: NONE (graceful)"
                    ),
                    "product-service": (
                        "Error rate: 0.1% (normal) | Checkout: 100% | Revenue: unchanged"
                    ),
                    "redis-reco-cache": "Hit rate: 88% | Memory: 34% | HEALTHY",
                },
                "check_dependencies": {
                    "recommendation-service": "Depends on: ML model server [SLOW]",
                    "product-service": "Depends on: recommendation-service [DEGRADED — has fallback]",
                    "redis-reco-cache": "No dependencies",
                },
                "check_recent_deploys": {
                    "recommendation-service": "Model update 3h ago — new model v2.4",
                    "product-service": "No recent changes",
                    "redis-reco-cache": "No recent changes",
                },
            },
            "correct_severity": "P3",
            "adjacent_severities": ["P2", "P4"],
        },
    ],

    # ══════════════════════════════════════════════════════════════════════
    # TASK 2: ROOT CAUSE ANALYSIS (MEDIUM)
    # Target: 8B→0.30-0.50, 70B→0.45-0.65
    #
    # KEY DESIGN RULES:
    # 1. Root cause service NEVER in affected_services
    # 2. incident_summary describes SYMPTOMS only, no hints
    # 3. 8-10 known_services (many to investigate)
    # 4. Red herring deploys on non-root-cause services
    # 5. Root cause only findable via check_recent_deploys + query_logs
    #    on the specific service — not from looking at victims
    # ══════════════════════════════════════════════════════════════════════

    "root_cause_analysis": [

        # RCA-001: analytics-service OOM kills postgres-db
        # 8 known services. Root cause: analytics-service.
        # Red herrings: auth-service deploy (cosmetic), redis healthy
        {
            "scenario_id": "RCA-001",
            "description": (
                "Multiple services reporting failures. Database appears to be "
                "the epicenter but the true trigger may be elsewhere."
            ),
            "incident_summary": (
                "Multiple services are failing. postgres-db is in a crash loop. "
                "auth-service, order-service, and api-gateway are all reporting errors. "
                "Investigate all available services to find what triggered this cascade."
            ),
            "alert": {
                "id": "ALT-RCA-001",
                "title": "Multiple service failures — database crash loop",
                "severity_fired": "P1",
                "affected_services": [
                    "api-gateway", "auth-service", "order-service", "postgres-db",
                ],
                "symptoms": [
                    "postgres-db: crash loop — 4 restarts in 12 minutes",
                    "auth-service: 100% connection failures",
                    "order-service: all writes failing",
                    "api-gateway: 503 on authenticated routes",
                ],
                "error_rate": 0.95,
                "duration_minutes": 14,
            },
            "known_services": {
                "api-gateway", "auth-service", "order-service",
                "postgres-db", "analytics-service", "redis-session",
                "product-service", "notification-service",
            },
            "tool_responses": {
                        # In RCA-001, replace the query_logs section:
        "query_logs": {
            "postgres-db": (
                "2024-03-16T02:11:00Z LOG database system shut down\n"
                "2024-03-16T02:10:58Z FATAL terminated by kernel OOM killer\n"
                "2024-03-16T02:10:30Z LOG long-running query from "
                "analytics-service consuming all available memory — "
                "running for 12 minutes, no LIMIT clause"
            ),
            "analytics-service": (
                "2024-03-16T01:58:00Z INFO starting scheduled job: full_history_export\n"
                "2024-03-16T01:58:01Z DEBUG executing: SELECT * FROM events "
                "JOIN user_sessions ON ... JOIN orders ON ... — no LIMIT\n"
                "2024-03-16T01:58:02Z WARN query plan estimates 847M row scan\n"
                "2024-03-16T02:10:55Z ERROR job terminated — connection to database lost"
            ),
            "auth-service": (
                "2024-03-16T02:11:05Z ERROR connect ECONNREFUSED postgres-db:5432\n"
                "2024-03-16T02:11:06Z ERROR all retries exhausted"
            ),
            "api-gateway": (
                "2024-03-16T02:11:10Z ERROR upstream auth-service: 503"
            ),
            "order-service": (
                "2024-03-16T02:11:08Z ERROR pq: database system is starting up"
            ),
            "redis-session": "No errors — operating normally",
            "product-service": (
                "2024-03-16T02:11:12Z WARN DB queries failing — serving cached data"
            ),
            "notification-service": (
                "2024-03-16T02:11:15Z ERROR cannot send — user lookup failed"
            ),
        },
                "check_metrics": {
                    "postgres-db": (
                        "Memory: peaked at 31.8GB/32GB before kill | "
                        "Restarts: 4 in 12min | Status: RESTARTING | "
                        "Heaviest client: 10.0.5.47"
                    ),
                    "analytics-service": (
                        "Last job: FAILED | Memory during job: 28GB | "
                        "IP: 10.0.5.47 | CPU: idle (job terminated)"
                    ),
                    "auth-service": "Connections: 0% success | Queued requests: 1,200",
                    "api-gateway": "503 rate: 95% | Auth: DOWN",
                    "order-service": "Write success: 0% | DB: RESTARTING",
                    "redis-session": "Hit rate: 99.2% | Memory: 42% | HEALTHY",
                    "product-service": "Serving cached data | DB queries: 100% failing",
                    "notification-service": "Queue backlog: 8,400 | DB: DOWN",
                },
                "check_dependencies": {
                    "postgres-db": (
                        "Clients: auth-service, order-service, analytics-service, "
                        "product-service, notification-service"
                    ),
                    "analytics-service": "Depends on: postgres-db [CRASH LOOP]",
                    "auth-service": "Depends on: postgres-db [CRASH LOOP], redis-session [OK]",
                    "api-gateway": "Depends on: auth-service [DOWN], product-service [DEGRADED]",
                    "order-service": "Depends on: postgres-db [CRASH LOOP]",
                    "redis-session": "Standalone cache — no DB dependency",
                    "product-service": "Depends on: postgres-db [CRASH LOOP — using cache]",
                    "notification-service": "Depends on: postgres-db [CRASH LOOP]",
                },
                "check_recent_deploys": {
                    "analytics-service": (
                        "Deploy 6h ago: added scheduled data export job — "
                        "runs daily at 02:00 UTC. Change includes cross-table "
                        "JOIN query without LIMIT clause"
                    ),
                    "postgres-db": "No deploys in 3 weeks",
                    "auth-service": (
                        "Deploy 2h ago: updated structured logging format. "
                        "No functional changes, no query changes, no connection changes."
                    ),
                    "order-service": "No recent deploys",
                    "redis-session": "No recent deploys",
                    "api-gateway": "No recent deploys",
                    "product-service": (
                        "Deploy 3 days ago: added product image lazy loading. "
                        "No DB changes."
                    ),
                    "notification-service": "No recent deploys",
                },
                "check_service_status": {
                    "postgres-db": "RESTARTING | Uptime: 47s | Last crash: OOM",
                    "analytics-service": "ERROR | Last job: FAILED 12min ago",
                    "auth-service": "DOWN | Blocked on postgres-db",
                    "api-gateway": "DEGRADED | 95% errors",
                    "order-service": "DOWN | Blocked on postgres-db",
                    "redis-session": "HEALTHY | 99.2% hit rate",
                    "product-service": "DEGRADED | Cache fallback active",
                    "notification-service": "DEGRADED | Queue backlog 8,400",
                },
            },
            "correct_root_cause": {
                "service": "analytics-service",
                "failure_mode": "unbounded query OOM killing postgres-db",
            },
            "wrong_actions": {
                "restart_service:auth-service": "victim — DB must be fixed first",
                "restart_service:api-gateway": "downstream — won't help",
                "restart_service:order-service": "victim — won't help",
                "scale_service:postgres-db": "won't prevent OOM from bad query",
                "rollback_deploy:postgres-db": "no recent deploys",
                "rollback_deploy:auth-service": "auth deploy was cosmetic only",
                "rollback_deploy:product-service": "product deploy unrelated",
                "restart_service:redis-session": "redis is healthy",
                "restart_service:notification-service": "victim — won't help",
            },
        },

        # RCA-002: network-infra BGP withdrawal
        # 8 known services. Root cause: network-infra.
        # Red herrings: payment-service looks down, postgres-db exists
        {
            "scenario_id": "RCA-002",
            "description": (
                "Checkout failures concentrated in specific availability zones. "
                "Some services appear unreachable while others work fine."
            ),
            "incident_summary": (
                "Checkout failure rate has spiked to 61%. payment-service and "
                "fraud-detection-service are unreachable from some parts of the "
                "infrastructure but appear healthy from others. Multiple services "
                "to investigate. Find the root cause."
            ),
            "alert": {
                "id": "ALT-RCA-002",
                "title": "Checkout failures — partial service unreachability",
                "severity_fired": "P2",
                "affected_services": [
                    "order-service", "payment-service", "fraud-detection-service",
                ],
                "symptoms": [
                    "checkout failure rate: 61%",
                    "payment-service: intermittently unreachable",
                    "fraud-detection-service: intermittently unreachable",
                    "failures appear zone-specific",
                ],
                "error_rate": 0.61,
                "duration_minutes": 9,
            },
            "known_services": {
                "order-service", "payment-service", "fraud-detection-service",
                "postgres-db", "redis-payment-cache", "network-infra",
                "cdn-edge", "api-gateway",
            },
            "tool_responses": {
                        # In RCA-002, replace query_logs:
        "query_logs": {
            "order-service": (
                "2024-03-17T14:32:10Z ERROR connection timeout "
                "payment-service:8080 — no route to host\n"
                "2024-03-17T14:32:11Z ERROR fraud-detection-service: i/o timeout\n"
                "2024-03-17T14:32:12Z WARN failures only from AZ-2/AZ-3, "
                "AZ-1 traffic normal — possible network-infra issue"
            ),
            "payment-service": (
                "2024-03-17T14:31:58Z WARN health check from external LB failing\n"
                "2024-03-17T14:31:59Z INFO local AZ-1 traffic: all normal\n"
                "2024-03-17T14:32:00Z INFO processing requests normally (local only)"
            ),
            "fraud-detection-service": (
                "2024-03-17T14:32:00Z INFO local requests: processing normally\n"
                "2024-03-17T14:32:01Z WARN external health probes: 100% timeout"
            ),
            "network-infra": (
                "2024-03-17T14:31:45Z CRITICAL BGP session 10.0.2.1 DOWN — "
                "routes to 10.0.1.0/24 withdrawn from peer\n"
                "2024-03-17T14:31:45Z CRITICAL BGP session 10.0.3.1 DOWN — "
                "routes to 10.0.1.0/24 withdrawn from peer\n"
                "2024-03-17T14:31:44Z INFO configuration change applied — "
                "export filter policy updated"
            ),
            "postgres-db": "Operating normally — no errors",
            "redis-payment-cache": "Operating normally — all healthy",
            "cdn-edge": "Operating normally — cache serving fine",
            "api-gateway": (
                "2024-03-17T14:32:15Z ERROR some backend routes timing out\n"
                "2024-03-17T14:32:16Z INFO AZ-1 backends: responding normally"
            ),
        },
                "check_metrics": {
                    "order-service": (
                        "Failure rate varies by source AZ: "
                        "AZ-1: 0.2% | AZ-2: 99% | AZ-3: 98%"
                    ),
                    "payment-service": (
                        "Internal processing: 100% success | "
                        "Inbound from AZ-2: 0 connections | Inbound from AZ-3: 0 connections | "
                        "Inbound from AZ-1: normal"
                    ),
                    "fraud-detection-service": (
                        "Internal: normal | External probes: 100% timeout"
                    ),
                    "network-infra": (
                        "BGP sessions: AZ-1 internal UP | "
                        "AZ-2→AZ-1: WITHDRAWN | AZ-3→AZ-1: WITHDRAWN | "
                        "Last change: 18min ago"
                    ),
                    "postgres-db": "All metrics normal",
                    "redis-payment-cache": "All metrics normal",
                    "cdn-edge": "Cache hit: 91% | Normal operation",
                    "api-gateway": "Mixed — AZ-1 OK, AZ-2/AZ-3 partial failures",
                },
                "check_dependencies": {
                    "order-service": (
                        "Depends on: payment-service [PARTIAL], "
                        "fraud-detection-service [PARTIAL]"
                    ),
                    "payment-service": "Depends on: postgres-db [OK], redis-payment-cache [OK]",
                    "fraud-detection-service": "Depends on: postgres-db [OK]",
                    "network-infra": (
                        "BGP peers: AZ-2 [WITHDRAWN], AZ-3 [WITHDRAWN], AZ-1 [UP]"
                    ),
                    "postgres-db": "All connections healthy",
                    "redis-payment-cache": "All connections healthy",
                    "cdn-edge": "No issues",
                    "api-gateway": "Depends on: multiple backends [MIXED]",
                },
                "check_recent_deploys": {
                    "network-infra": (
                        "Router configuration change 18min ago — modified BGP "
                        "export filter policy. Change accidentally removed AZ-1 "
                        "prefix 10.0.1.0/24 from advertisements to AZ-2 and AZ-3 peers."
                    ),
                    "payment-service": "No recent deploys",
                    "order-service": "No recent deploys",
                    "fraud-detection-service": "No recent deploys",
                    "postgres-db": (
                        "Minor config change 5 days ago — increased shared_buffers. "
                        "No issues since."
                    ),
                    "redis-payment-cache": "No recent deploys",
                    "cdn-edge": "No recent deploys",
                    "api-gateway": (
                        "Deploy 1 day ago — added request tracing headers. "
                        "No routing changes."
                    ),
                },
                "check_service_status": {
                    "payment-service": "HEALTHY (local) | Cross-AZ: UNREACHABLE",
                    "order-service": "DEGRADED | Partial failures",
                    "network-infra": "BGP AZ-2: WITHDRAWN | BGP AZ-3: WITHDRAWN",
                    "fraud-detection-service": "HEALTHY (local) | Cross-AZ: UNREACHABLE",
                    "postgres-db": "HEALTHY",
                    "redis-payment-cache": "HEALTHY",
                    "cdn-edge": "HEALTHY",
                    "api-gateway": "DEGRADED | Mixed backend status",
                },
            },
            "correct_root_cause": {
                "service": "network-infra",
                "failure_mode": "BGP route withdrawal causing AZ network partition",
            },
            "wrong_actions": {
                "restart_service:payment-service": "healthy — network issue",
                "restart_service:order-service": "victim",
                "scale_service:payment-service": "won't fix routing",
                "clear_cache:redis-payment-cache": "cache is healthy",
                "restart_service:api-gateway": "victim of routing issue",
                "rollback_deploy:api-gateway": "deploy was unrelated tracing headers",
                "rollback_deploy:postgres-db": "config change was 5 days ago, unrelated",
                "restart_service:cdn-edge": "CDN is healthy",
            },
        },

        # RCA-003: config-service credential rotation bug
        # 8 known services. Root cause: config-service.
        # Red herrings: user-service had a recent deploy, postgres-db stressed
        {
            "scenario_id": "RCA-003",
            "description": (
                "Multiple services experiencing database authentication failures. "
                "The database itself may not be the problem."
            ),
            "incident_summary": (
                "Several services are reporting database authentication failures. "
                "postgres-db connection pool is saturated. user-service and "
                "notification-service are down. api-gateway error rate elevated. "
                "Investigate all services to find what triggered this."
            ),
            "alert": {
                "id": "ALT-RCA-003",
                "title": "Multiple services — database authentication failures",
                "severity_fired": "P2",
                "affected_services": [
                    "api-gateway", "user-service", "notification-service", "postgres-db",
                ],
                "symptoms": [
                    "user-service: FATAL password authentication failed",
                    "notification-service: FATAL password authentication failed",
                    "api-gateway: 503 rate 62%",
                    "postgres-db: connection pool 490/500",
                ],
                "error_rate": 0.62,
                "duration_minutes": 7,
            },
            "known_services": {
                "api-gateway", "user-service", "notification-service",
                "postgres-db", "config-service", "redis-session",
                "order-service", "product-service",
            },
            "tool_responses": {
                        # In RCA-003, replace query_logs:
        "query_logs": {
            "user-service": (
                "2024-03-18T08:14:00Z FATAL password authentication failed "
                "for user 'app_user'\n"
                "2024-03-18T08:14:01Z ERROR DB credentials rejected — "
                "credentials were pushed by config-service at 08:12:00Z\n"
                "2024-03-18T08:14:02Z WARN config-service credential rotation "
                "may have sent wrong credentials"
            ),
            "notification-service": (
                "2024-03-18T08:14:05Z FATAL password authentication failed\n"
                "2024-03-18T08:14:06Z WARN credentials from config-service "
                "push at 08:12:00Z appear to be stale/invalid"
            ),
            "api-gateway": (
                "2024-03-18T08:14:10Z ERROR upstream user-service: 503\n"
                "2024-03-18T08:14:11Z ERROR upstream notification-service: 503"
            ),
            "postgres-db": (
                "2024-03-18T08:14:00Z LOG auth failure from 10.0.3.x\n"
                "2024-03-18T08:14:00Z LOG auth failure from 10.0.4.x\n"
                "2024-03-18T08:14:01Z LOG 490/500 slots used by failed auth retries"
            ),
            "config-service": (
                "2024-03-18T08:12:00Z INFO secrets rotation job executed\n"
                "2024-03-18T08:12:01Z WARN rotation referenced PREVIOUS "
                "credential set instead of generating new — template bug "
                "in version v3.2.1\n"
                "2024-03-18T08:12:02Z INFO pushed credentials to: "
                "user-service, notification-service, order-service"
            ),
            "redis-session": "Operating normally",
            "order-service": (
                "2024-03-18T08:14:20Z WARN received credential push from "
                "config-service but have not restarted — still using old valid creds"
            ),
            "product-service": "Operating normally — using original credentials",
        },
                "check_metrics": {
                    "user-service": "DB auth: 100% failure | HTTP 503: 100%",
                    "notification-service": "DB auth: 100% failure | HTTP 503: 100%",
                    "api-gateway": "503 rate: 62% | Some upstreams DOWN",
                    "postgres-db": (
                        "Connections: 490/500 | Auth failures/s: 80 | "
                        "Valid connections: 10 | DB itself: HEALTHY"
                    ),
                    "config-service": (
                        "Status: HEALTHY | Last push: 7min ago | "
                        "Type: secrets_rotation | Result: COMPLETED"
                    ),
                    "redis-session": "All normal",
                    "order-service": "Using old credentials — still working",
                    "product-service": "All normal — unaffected",
                },
                "check_dependencies": {
                    "user-service": (
                        "Depends on: postgres-db [AUTH FAIL], "
                        "config-service [credential source]"
                    ),
                    "notification-service": (
                        "Depends on: postgres-db [AUTH FAIL], "
                        "config-service [credential source]"
                    ),
                    "api-gateway": "Depends on: user-service [DOWN], notification-service [DOWN]",
                    "postgres-db": "No upstream dependencies — DB is healthy",
                    "config-service": (
                        "Provides: credentials to user-service, "
                        "notification-service, order-service"
                    ),
                    "redis-session": "Standalone",
                    "order-service": (
                        "Depends on: postgres-db [OK — old creds], "
                        "config-service [pending push]"
                    ),
                    "product-service": "Depends on: postgres-db [OK — original creds]",
                },
                "check_recent_deploys": {
                    "config-service": (
                        "Deploy 2h ago: version v3.2.1 — updated secrets rotation "
                        "job template. Bug: rotation references previous credential "
                        "set instead of generating new credentials."
                    ),
                    "user-service": (
                        "Deploy 4h ago: added new profile API endpoint. "
                        "No database or credential changes."
                    ),
                    "notification-service": "No recent deploys",
                    "postgres-db": "No recent deploys",
                    "api-gateway": "No recent deploys",
                    "redis-session": "No recent deploys",
                    "order-service": (
                        "Deploy 1 day ago: updated order confirmation email template. "
                        "No DB changes."
                    ),
                    "product-service": "No recent deploys",
                },
                "check_service_status": {
                    "user-service": "DOWN | DB auth failures",
                    "notification-service": "DOWN | DB auth failures",
                    "api-gateway": "DEGRADED | 62% error rate",
                    "postgres-db": "STRESSED but HEALTHY | 490/500 connections (failed auths)",
                    "config-service": "HEALTHY | Last rotation: 7min ago (completed)",
                    "redis-session": "HEALTHY",
                    "order-service": "HEALTHY | Old credentials still valid",
                    "product-service": "HEALTHY",
                },
            },
            "correct_root_cause": {
                "service": "config-service",
                "failure_mode": "secrets rotation pushed stale credentials to downstream services",
            },
            "wrong_actions": {
                "restart_service:user-service": "will retry with same bad credentials",
                "restart_service:notification-service": "same bad credentials",
                "restart_service:postgres-db": "DB is healthy — client creds are bad",
                "scale_service:postgres-db": "connections are failed auths",
                "rollback_deploy:user-service": "user-service deploy was unrelated",
                "rollback_deploy:order-service": "order-service deploy was unrelated",
                "restart_service:api-gateway": "downstream — fix upstream first",
            },
        },
    ],

    # ══════════════════════════════════════════════════════════════════════
    # TASK 3: REMEDIATION PLANNING (HARD)
    # Target: 8B→0.15-0.35, 70B→0.30-0.50
    #
    # KEY DESIGN RULES:
    # 1. Same diagnostic challenge as medium
    # 2. 5-7 step remediation sequence required
    # 3. 8-10 known services = many wrong choices
    # 4. Wrong actions carry -0.05 penalty each (up to -0.15)
    # 5. Summary must hit 3+ keywords for bonus
    # 6. incident_summary does NOT reveal root cause
    # ══════════════════════════════════════════════════════════════════════

    "remediation_planning": [

        # RP-001: OOM remediation — 6-step sequence, 8 services
        {
            "scenario_id": "RP-001",
            "description": (
                "Full incident remediation required. Multiple services down. "
                "Diagnose the root cause, execute fixes in the correct order, "
                "and document your resolution."
            ),
            "incident_summary": (
                "CRITICAL — postgres-db is crash-looping. auth-service, order-service, "
                "and api-gateway are all down. notification-service queue backing up. "
                "Diagnose the root cause, fix it, restore all services, and document."
            ),
            "alert": {
                "id": "ALT-RP-001",
                "title": "CRITICAL: database crash loop — multiple services down",
                "severity_fired": "P1",
                "affected_services": [
                    "postgres-db", "auth-service", "order-service", "api-gateway",
                ],
            },
            "known_services": {
                "postgres-db", "auth-service", "order-service",
                "api-gateway", "analytics-service", "redis-session",
                "product-service", "notification-service",
            },
            "tool_responses": {
                "query_logs": {
                    "postgres-db": (
                        "FATAL: terminated by kernel OOM killer — "
                        "query from client 10.0.5.47 running 12min consuming all memory"
                    ),
                    "analytics-service": (
                        "INFO: starting job full_history_export\n"
                        "WARN: query plan: 847M rows, cross-table JOIN, no LIMIT\n"
                        "ERROR: job terminated — database connection lost"
                    ),
                    "auth-service": "ERROR: connect ECONNREFUSED postgres-db:5432",
                    "order-service": "ERROR: pq: database system is starting up",
                    "api-gateway": "ERROR: upstream auth-service 503",
                    "redis-session": "Operating normally",
                    "product-service": "WARN: DB failing — serving cached data",
                    "notification-service": "ERROR: user lookup failed — queuing",
                },
                "check_metrics": {
                    "postgres-db": "OOM killed | Restarts: 4 | Heaviest client: 10.0.5.47",
                    "analytics-service": "Job FAILED | Memory peak: 31GB/32GB | IP: 10.0.5.47",
                    "auth-service": "0% DB success | Queue: 1,200",
                    "order-service": "0% write success",
                    "api-gateway": "503 rate: 95%",
                    "redis-session": "HEALTHY | 99.2% hit rate",
                    "product-service": "Cache fallback active",
                    "notification-service": "Queue: 8,400 messages backed up",
                },
                "check_dependencies": {
                    "postgres-db": (
                        "Clients: auth-service, order-service, analytics-service, "
                        "product-service, notification-service"
                    ),
                    "analytics-service": "Depends on: postgres-db [CRASH LOOP]",
                    "auth-service": "Depends on: postgres-db [CRASH LOOP], redis-session [OK]",
                    "api-gateway": "Depends on: auth-service [DOWN]",
                    "order-service": "Depends on: postgres-db [CRASH LOOP]",
                    "redis-session": "Standalone",
                    "product-service": "Depends on: postgres-db [CRASH LOOP — cache fallback]",
                    "notification-service": "Depends on: postgres-db [CRASH LOOP]",
                },
                "check_recent_deploys": {
                    "analytics-service": (
                        "Deploy 6h ago: added scheduled export job — "
                        "cross-table JOIN without LIMIT clause"
                    ),
                    "postgres-db": "No deploys in 3 weeks",
                    "auth-service": "Deploy 2h ago: logging format only — no functional changes",
                    "order-service": "No recent deploys",
                    "product-service": "Deploy 3 days ago: image lazy loading — no DB changes",
                    "notification-service": "No recent deploys",
                },
                "check_service_status": {
                    "postgres-db": "CRASH LOOP | OOM | Uptime: 47s",
                    "analytics-service": "ERROR | Job FAILED",
                    "auth-service": "DOWN",
                    "order-service": "DOWN",
                    "api-gateway": "DEGRADED | 95% errors",
                    "redis-session": "HEALTHY",
                    "product-service": "DEGRADED | Cache fallback",
                    "notification-service": "DEGRADED | Queue backlog",
                },
            },
            "remediation_data": {
                "disable_feature_flag": {
                    "full_history_export": (
                        "Cron job full_history_export DISABLED — "
                        "unbounded query will not execute again"
                    ),
                },
                "restart_service": {
                    "postgres-db": "postgres-db restarted — accepting connections (12/500)",
                    "analytics-service": "analytics-service restarted — idle",
                    "auth-service": "auth-service restarted — connected to postgres-db OK",
                    "order-service": "order-service restarted — writes resuming",
                    "api-gateway": "api-gateway restarted — routing recovered",
                    "product-service": "product-service — switched from cache to live DB",
                    "notification-service": "notification-service — draining queue",
                },
                "execute_runbook_step": {
                    "verify_db_health": "postgres-db: 12/500 connections, CPU 12%, Memory 34% — healthy",
                    "check_service_recovery": (
                        "auth OK | order OK | api-gateway OK | product OK | notification DRAINING"
                    ),
                },
            },
            "correct_remediation_sequence": [
                "disable_feature_flag:full_history_export",
                "restart_service:analytics-service",
                "restart_service:postgres-db",
                "restart_service:auth-service",
                "restart_service:order-service",
                "execute_runbook_step:verify_db_health",
            ],
            "wrong_actions": {
                "rollback_deploy:postgres-db": "no recent deploy",
                "scale_service:postgres-db": "won't prevent OOM",
                "restart_service:api-gateway": "downstream — fix DB stack first",
                "rollback_deploy:auth-service": "cosmetic deploy only",
                "clear_cache:redis-session": "healthy — not related",
                "restart_service:redis-session": "healthy — not related",
                "rollback_deploy:product-service": "unrelated deploy",
                "restart_service:notification-service": "will recover once DB is up",
            },
            "resolution_keywords": [
                "analytics", "oom", "memory", "postgres", "query",
                "full_history_export", "disabled", "restarted",
                "recovered", "unbounded", "crash", "kill",
            ],
        },

        # RP-002: BGP remediation — 4-step sequence, 8 services
        {
            "scenario_id": "RP-002",
            "description": (
                "Full incident remediation required. Checkout failures affecting "
                "most users. Diagnose, fix, verify, and document."
            ),
            "incident_summary": (
                "Checkout failure rate 61%. payment-service unreachable from most "
                "of the infrastructure. Some services report no issues. "
                "Diagnose the root cause, execute remediation, verify recovery, "
                "and document the resolution."
            ),
            "alert": {
                "id": "ALT-RP-002",
                "title": "Checkout failures — partial service unreachability",
                "severity_fired": "P2",
                "affected_services": ["order-service", "payment-service"],
            },
            "known_services": {
                "network-infra", "order-service", "payment-service",
                "fraud-detection-service", "postgres-db",
                "redis-payment-cache", "cdn-edge", "api-gateway",
            },
            "tool_responses": {
                "query_logs": {
                    "network-infra": (
                        "CRITICAL: BGP peer 10.0.2.1 route withdrawal — "
                        "routes to 10.0.1.0/24 removed\n"
                        "CRITICAL: BGP peer 10.0.3.1 route withdrawal — "
                        "routes to 10.0.1.0/24 removed\n"
                        "INFO: configuration change applied — export filter updated"
                    ),
                    "order-service": "ERROR: timeout payment-service — no route to host",
                    "payment-service": "INFO: local traffic normal | WARN: external health failing",
                    "fraud-detection-service": "WARN: cross-AZ probes timeout | Local: OK",
                    "postgres-db": "Operating normally",
                    "redis-payment-cache": "Operating normally",
                    "cdn-edge": "Operating normally",
                    "api-gateway": "ERROR: some backend routes timing out",
                },
                "check_metrics": {
                    "network-infra": (
                        "BGP AZ-2→AZ-1: WITHDRAWN | AZ-3→AZ-1: WITHDRAWN | "
                        "AZ-1 internal: UP | Last change: 18min ago"
                    ),
                    "order-service": "AZ-1: 0.2% fail | AZ-2: 99% fail | AZ-3: 98% fail",
                    "payment-service": "Internal: 100% success | External: 0 inbound from AZ-2/3",
                    "fraud-detection-service": "Local: normal | External: timeout",
                    "postgres-db": "All normal",
                    "redis-payment-cache": "All normal",
                    "cdn-edge": "Cache: 91% hit | Normal",
                    "api-gateway": "Mixed — AZ-1 OK, AZ-2/3 partial failures",
                },
                "check_dependencies": {
                    "order-service": "Depends on: payment-service [PARTIAL], fraud-detection [PARTIAL]",
                    "payment-service": "Depends on: postgres-db [OK], redis-payment-cache [OK]",
                    "network-infra": "BGP: AZ-2 [WITHDRAWN], AZ-3 [WITHDRAWN]",
                    "fraud-detection-service": "Depends on: postgres-db [OK]",
                    "postgres-db": "All healthy",
                    "redis-payment-cache": "All healthy",
                    "cdn-edge": "No issues",
                    "api-gateway": "Mixed backends",
                },
                "check_recent_deploys": {
                    "network-infra": (
                        "Config change 18min ago — BGP export filter modified, "
                        "accidentally removed AZ-1 prefix from AZ-2/AZ-3 ads"
                    ),
                    "payment-service": "No recent deploys",
                    "order-service": "No recent deploys",
                    "fraud-detection-service": "No recent deploys",
                    "postgres-db": "Minor change 5 days ago — increased shared_buffers",
                    "redis-payment-cache": "No recent deploys",
                    "cdn-edge": "No recent deploys",
                    "api-gateway": "Deploy 1 day ago — tracing headers, no routing changes",
                },
                "check_service_status": {
                    "network-infra": "BGP AZ-2: WITHDRAWN | BGP AZ-3: WITHDRAWN",
                    "payment-service": "HEALTHY (local) | Cross-AZ: UNREACHABLE",
                    "order-service": "DEGRADED",
                    "fraud-detection-service": "HEALTHY (local) | Cross-AZ: UNREACHABLE",
                    "postgres-db": "HEALTHY",
                    "redis-payment-cache": "HEALTHY",
                    "cdn-edge": "HEALTHY",
                    "api-gateway": "DEGRADED",
                },
            },
            "remediation_data": {
                "rollback_deploy": {
                    "network-infra": "Router config rolled back — BGP policy restored",
                },
                "execute_runbook_step": {
                    "restore_bgp_routes": "BGP routes restored — AZ-2/3 can reach AZ-1",
                    "verify_checkout_recovery": "Checkout failure: 0.3% — resolved",
                    "verify_cross_az_connectivity": "AZ-2→AZ-1: OK | AZ-3→AZ-1: OK",
                },
            },
            "correct_remediation_sequence": [
                "execute_runbook_step:restore_bgp_routes",
                "rollback_deploy:network-infra",
                "execute_runbook_step:verify_cross_az_connectivity",
                "execute_runbook_step:verify_checkout_recovery",
            ],
            "wrong_actions": {
                "restart_service:payment-service": "healthy — network issue",
                "scale_service:payment-service": "won't fix routing",
                "restart_service:order-service": "victim",
                "clear_cache:redis-payment-cache": "unrelated",
                "restart_service:cdn-edge": "healthy",
                "restart_service:fraud-detection-service": "healthy locally",
                "restart_service:api-gateway": "victim of routing",
                "rollback_deploy:api-gateway": "deploy was unrelated",
                "rollback_deploy:postgres-db": "change was 5 days ago",
            },
            "resolution_keywords": [
                "bgp", "network", "route", "rollback", "partition",
                "restored", "az-1", "az-2", "az-3", "checkout",
                "withdrawal", "config", "advertisement", "export",
            ],
        },

        # RP-003: Credential rotation remediation — 7-step sequence, 8 services
        {
            "scenario_id": "RP-003",
            "description": (
                "Full incident remediation required. Multiple services failing "
                "database authentication. Diagnose, fix, verify, and document."
            ),
            "incident_summary": (
                "Multiple services reporting database authentication failures. "
                "postgres-db connection pool near capacity with failed auth attempts. "
                "user-service and notification-service are down. api-gateway degraded. "
                "Diagnose the root cause, execute remediation, and document."
            ),
            "alert": {
                "id": "ALT-RP-003",
                "title": "Multiple services — DB authentication failures",
                "severity_fired": "P2",
                "affected_services": [
                    "user-service", "notification-service", "api-gateway",
                ],
            },
            "known_services": {
                "api-gateway", "user-service", "notification-service",
                "postgres-db", "config-service", "redis-session",
                "order-service", "product-service",
            },
            "tool_responses": {
                "query_logs": {
                    "user-service": (
                        "FATAL: password authentication failed for user 'app_user'\n"
                        "ERROR: DB credentials rejected\n"
                        "WARN: credentials last refreshed at 08:12:00Z"
                    ),
                    "notification-service": (
                        "FATAL: password authentication failed\n"
                        "WARN: credentials from 08:12:00Z appear stale"
                    ),
                    "api-gateway": (
                        "ERROR: upstream user-service 503\n"
                        "ERROR: upstream notification-service 503"
                    ),
                    "postgres-db": (
                        "LOG: auth failure from 10.0.3.x (user-service)\n"
                        "LOG: auth failure from 10.0.4.x (notification-service)\n"
                        "LOG: 490/500 slots used by failed auth retries"
                    ),
                    "config-service": (
                        "INFO: secrets rotation executed at 08:12:00Z\n"
                        "WARN: rotation used PREVIOUS credential set — "
                        "template bug in v3.2.1\n"
                        "INFO: pushed to: user-service, notification-service, order-service"
                    ),
                    "redis-session": "Operating normally",
                    "order-service": (
                        "WARN: received credential push at 08:12:00Z — "
                        "not applied yet, still using old valid credentials"
                    ),
                    "product-service": "Operating normally — using original credentials",
                },
                "check_metrics": {
                    "user-service": "DB auth: 100% failure | HTTP 503: 100%",
                    "notification-service": "DB auth: 100% failure | HTTP 503: 100%",
                    "api-gateway": "503 rate: 62%",
                    "postgres-db": "Connections: 490/500 | Auth failures/s: 80 | DB: HEALTHY",
                    "config-service": "HEALTHY | Last push: 7min ago | Type: secrets_rotation",
                    "redis-session": "All normal",
                    "order-service": "HEALTHY | Using old (valid) credentials",
                    "product-service": "HEALTHY | Unaffected",
                },
                "check_dependencies": {
                    "user-service": "Depends on: postgres-db [AUTH FAIL], config-service [creds]",
                    "notification-service": "Depends on: postgres-db [AUTH FAIL], config-service [creds]",
                    "api-gateway": "Depends on: user-service [DOWN], notification-service [DOWN]",
                    "postgres-db": "No upstream — DB itself is healthy",
                    "config-service": "Provides credentials to: user-svc, notification-svc, order-svc",
                    "redis-session": "Standalone",
                    "order-service": "Depends on: postgres-db [OK — old creds]",
                    "product-service": "Depends on: postgres-db [OK — original creds]",
                },
                "check_recent_deploys": {
                    "config-service": (
                        "Deploy 2h ago: v3.2.1 — updated secrets rotation template. "
                        "Bug: references previous credential set instead of generating new."
                    ),
                    "user-service": "Deploy 4h ago: profile endpoint — no DB changes",
                    "notification-service": "No recent deploys",
                    "postgres-db": "No recent deploys",
                    "api-gateway": "No recent deploys",
                    "redis-session": "No recent deploys",
                    "order-service": "Deploy 1 day ago: email template — no DB changes",
                    "product-service": "No recent deploys",
                },
                "check_service_status": {
                    "user-service": "DOWN | DB auth failures",
                    "notification-service": "DOWN | DB auth failures",
                    "api-gateway": "DEGRADED | 62%",
                    "postgres-db": "STRESSED | 490/500 connections (failed auths)",
                    "config-service": "HEALTHY | Rotation completed",
                    "redis-session": "HEALTHY",
                    "order-service": "HEALTHY | Old creds valid",
                    "product-service": "HEALTHY",
                },
            },
            "remediation_data": {
                "rollback_deploy": {
                    "config-service": "config-service rolled back to v3.2.0 — bug removed",
                },
                "execute_runbook_step": {
                    "trigger_credential_rotation": (
                        "Correct credentials generated and pushed to "
                        "user-service, notification-service, order-service"
                    ),
                    "verify_db_connectivity": (
                        "user-service: DB OK | notification-service: DB OK | "
                        "order-service: DB OK | postgres-db: 45/500 connections"
                    ),
                    "verify_api_recovery": "api-gateway 503 rate: 0.1% — recovered",
                },
                "restart_service": {
                    "user-service": "user-service restarted — DB auth OK with correct creds",
                    "notification-service": "notification-service restarted — DB auth OK",
                    "order-service": "order-service restarted — using correct credentials",
                },
            },
            "correct_remediation_sequence": [
                "rollback_deploy:config-service",
                "execute_runbook_step:trigger_credential_rotation",
                "restart_service:user-service",
                "restart_service:notification-service",
                "restart_service:order-service",
                "execute_runbook_step:verify_db_connectivity",
                "execute_runbook_step:verify_api_recovery",
            ],
            "wrong_actions": {
                "restart_service:postgres-db": "DB is healthy — problem is credentials",
                "scale_service:postgres-db": "connections are failed auths",
                "restart_service:api-gateway": "downstream — fix auth first",
                "rollback_deploy:user-service": "deploy was unrelated",
                "rollback_deploy:order-service": "deploy was unrelated",
                "clear_cache:redis-session": "healthy",
                "restart_service:product-service": "healthy",
                "restart_service:redis-session": "healthy",
            },
            "resolution_keywords": [
                "config", "credential", "rotation", "stale", "password",
                "authentication", "rollback", "config-service", "v3.2.1",
                "restarted", "recovered", "push", "secrets", "template",
            ],
        },
    ],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_task(task_id: str) -> dict:
    if task_id not in ALL_TASKS:
        raise ValueError(
            f"Unknown task_id '{task_id}'. Valid: {list(ALL_TASKS.keys())}"
        )
    return ALL_TASKS[task_id]


def get_scenario(task_id: str, index: int) -> dict:
    if task_id not in SCENARIOS:
        raise ValueError(f"No scenarios for task_id '{task_id}'.")
    scenarios = SCENARIOS[task_id]
    if index < 0 or index >= len(scenarios):
        raise ValueError(
            f"Scenario index {index} out of range for task '{task_id}' "
            f"(valid: 0–{len(scenarios) - 1})"
        )
    return scenarios[index]


def list_tasks() -> list:
    return list(ALL_TASKS.values())