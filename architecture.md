# Architecture Design — Hybrid Cloud Integration

## Overview

This design connects a legacy on-premise application to a cloud-native microservice (Kubernetes) via two integration modes:

- **Mode A** — real-time REST API calls, on demand
- **Mode B** — nightly batch CSV file transfer

Both modes are designed as **on-premise-initiated, outbound-only connections**, since the on-premise network has no direct inbound internet access. All data in transit is encrypted, every hop is independently authenticated and authorised, and the pipeline is observable end-to-end.

## Connectivity Layer

A **forward proxy** deployed on-premise handles all outbound traffic to the cloud for both modes. Because on-premise always initiates the connection, this satisfies the no-inbound-access constraint without requiring any special network exception. For production resilience, two proxy instances sit behind a load balancer to avoid a single point of failure; on-premise applications are configured to route outbound cloud traffic through this proxy tier.

*Alternative considered: AWS Direct Connect / Azure ExpressRoute — provides a private, dedicated physical connection, but note this gives network privacy, not encryption by default; TLS would still need to be layered on top. Rejected here in favour of the simpler, faster-to-provision forward proxy approach, given the constraints and scale of this integration. Worth revisiting if traffic volume or latency requirements grow.*

## Mode A — Real-Time API

**Path:** On-premise app → forward proxy → cloud API Gateway → Kubernetes microservice, over HTTPS with **mTLS**.

| Boundary | Authentication | Authorisation |
|---|---|---|
| On-prem app → proxy | Internal network trust / service account (stays within on-prem network) | N/A — internal hop |
| Proxy → API Gateway | **mTLS** — mutual certificate exchange; both client and server verify each other before any request is sent | API Gateway maps the client certificate to a scope, restricting the caller to specific reference-data endpoints only |
| API Gateway → K8s microservice | Relies on the cloud VPC's private network boundary (internal, trusted network) | Microservice enforces least-privilege at the application layer — the authenticated identity maps to a read-only role for reference data |

**Trade-off:** mTLS terminates at the API Gateway for centralised certificate management. This is operationally simpler than extending mTLS to the pod itself, but places more trust in the internal cloud network boundary. A stricter zero-trust design would extend mTLS end-to-end (e.g., via a service mesh like Istio/Linkerd), at the cost of added operational complexity — noted here as a future improvement rather than implemented now.

## Mode B — Nightly Batch File Transfer

**Path:** On-premise app pushes the CSV file outbound via **SFTP**, through the same forward proxy, to a cloud-side SFTP endpoint (e.g., AWS Transfer Family backed by S3).

| Boundary | Authentication | Authorisation |
|---|---|---|
| On-prem app → proxy | Internal network trust, same as Mode A | N/A — internal hop |
| Proxy → SFTP endpoint | **Dedicated SSH key pair**, used only for this automated batch process — intentionally separate from Mode A's mTLS certificates | SSH identity is scoped to a single restricted storage path/prefix; cannot read or write anywhere else in cloud storage |
| Storage → validation function | Function triggered automatically by a storage-arrival event | Executes under a least-privilege role — permitted only to read the landing path, write to quarantine, and invoke the DB load step |
| Validation function → database | Scoped service credential (e.g., IAM role or secrets-manager-issued DB credential) | Authorised only for inserts into the specific transaction table — no broader database access |

**Why a separate credential from Mode A:** Mode B is an unattended, automated process with no live session behind it. Using a dedicated SSH key (rather than reusing Mode A's mTLS certificate) limits blast radius — if either credential is ever compromised, the exposure is contained to a single mode and a narrowly scoped resource.

**Validation pipeline (triggered on file arrival):**
1. **Integrity check** — checksum generated on-premise before send, recomputed and compared on arrival, to detect transmission corruption.
2. **Structural validation** — schema and header check, to catch malformed or unexpected file formats.
3. **Content validation** — business-rule checks (e.g., valid data ranges, required fields present).
4. Files failing any check are routed to a **quarantine location** and trigger an alert; only files passing all checks proceed to the database load step.

## Trade-offs Considered (Summary)

- **Forward proxy vs. Direct Connect/ExpressRoute** — proxy chosen for simplicity and faster provisioning; dedicated connection would offer more consistent latency/reliability at higher cost, worth revisiting at scale.
- **mTLS termination point** — gateway-level termination is simpler to operate centrally; pod-level termination is more secure but operationally heavier.
- **Per-boundary least-privilege credentials vs. one shared credential** — a single shared credential across the pipeline would be simpler to manage, but was rejected in favour of scoped, per-boundary credentials to minimise blast radius if any one credential is compromised.
