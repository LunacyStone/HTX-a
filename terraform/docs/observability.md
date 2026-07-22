# Observability Design (Task 4)

## What to Monitor / Alert On, by Hop

Both modes share most of their on-premise and network-edge path, so the same signals apply to both unless noted.

| Hop | Signal | Why |
|---|---|---|
| **On-prem VM (Mode A)** | mTLS client cert/key expiry — alert at <14 days, escalate at <3 days | Prevents an expired cert silently breaking Mode A with no warning |
| **On-prem VM (Mode B)** | Scheduled job heartbeat (did the nightly batch task actually fire) | Detects a silently-skipped run (cron/scheduler failure), not just a failed run |
| **On-prem VM (both)** | Disk space headroom | Prevents log/queue growth from crashing the host mid-transfer |
| **Internal firewall (both)** | Whitelist deny counter | A rising count usually signals the whitelisted VM's IP changed, not an attack — fast, specific diagnosis |
| **LB + Forward Proxies (both)** | Inter-proxy load imbalance ratio; per-proxy connection success rate; asymmetry alert | Confirms the LB is actually distributing load, and isolates whether a failure is proxy-specific or systemic |
| **Internet-facing firewall (both)** | Byte outflow > 0 and connection duration > 0 | Confirms traffic is genuinely flowing and sessions are establishing, not just "rule allows it" |
| **API Gateway (Mode A)** | Request count, 4xx/5xx rate, latency (p50/p95/p99), mTLS handshake failure rate (tracked separately from app errors) | Separates transport/auth failures from application bugs |
| **AWS Transfer Family (Mode B)** | Connection count; auth success/failure by reason | Distinguishes credential issues from network issues at the exact authentication boundary |
| **S3 Bucket (Mode B)** | Object PUT rate; policy-denial rate | Confirms files are landing, and flags silent permission drift |
| **Validation function (Mode B)** | Pass/fail counts, by failure reason (integrity / schema / content) | Lets a reviewer see *which* validation layer is rejecting files, not just "failed" |
| **Database (both)** | Insert success/fail, insert latency, duplicate/idempotency rejections, connection-pool saturation, role-assume failures | Surfaces both data-quality issues (duplicates) and infrastructure issues (pool exhaustion, IAM) at the final hop |

## Cross-Boundary Correlation

**Mode A:** a client-generated correlation ID (UUID, `X-Correlation-ID` header) is created on-premise before the first hop, logged at every downstream component, and cross-referenced with API Gateway's native `requestId` to bridge custom tracing with AWS-native tooling (CloudWatch Logs Insights, X-Ray).

**Mode B:** the correlation key is the **filename + checksum**, generated on-premise before transfer and logged at every stage (push → arrival → validation → load/quarantine). This deliberately reuses the same checksum generated for Task 6's integrity check, rather than building separate tracking.

## Runbook Entry — Failed Nightly File Transfer

1. **Trigger:** scheduled-job heartbeat missing, or validation function reports a failure for the expected filename/date.
2. **First step:** search all logs (on-prem push log, S3 arrival event, validation function log) by the file's correlation key (filename + checksum) to retrieve its full journey in one query.
3. **Diagnose by stage:** heartbeat missing → on-prem scheduler issue; push logged but no S3 arrival → network/proxy/Transfer Family path; arrival logged but validation failed → check failure reason (integrity/schema/content) from the validation function's structured output.
4. **Contain:** failed file is already in quarantine by design (per Task 1/6), so production data is not at risk while diagnosing.
5. **Resolve & re-run:** fix root cause, manually re-trigger the batch job or re-push the corrected file; confirm success via the same correlation key before closing the incident.
