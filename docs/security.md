# Security Considerations (Task 5)

## Top 3 Security Risks

### 1. No malware/virus scanning on ingested files

**Risk:** AWS does not scan S3 uploads for malware by default. A malicious or compromised CSV pushed via Mode B could reach the validation pipeline and, if it happens to pass schema/content checks, the production database — without ever being checked for embedded malicious content.

**Mitigation:** Add an explicit malware-scanning step, triggered on S3 object arrival, **before** the existing integrity/schema/content validation stages. Concretely: enable **Amazon GuardDuty Malware Protection for S3**, which scans newly uploaded objects and tags/quarantines infected files automatically; alternatively, run **ClamAV** inside the same Lambda used for validation, as an open-source fallback. Either way, a file failing the malware scan is routed to the same quarantine bucket already designed for failed validation, and never reaches the schema/content checks or the database.

### 2. Private key / certificate theft (Mode A mTLS cert, Mode B SSH key)

**Risk:** Mode A's mTLS client certificate and Mode B's SSH private key both reside on the on-premise VM. If either is stolen (e.g., VM compromise), an attacker could impersonate the on-premise system to the cloud endpoint.

**Mitigation:** Store both the mTLS private key and SSH private key in a **hardware-backed keystore (TPM) on the on-premise VM**, rather than as flat files on disk, so the key material cannot be copied out even with filesystem access. On the cloud side, issue and manage the mTLS certificate via **AWS Certificate Manager Private CA**, and store any corresponding cloud-side secrets in **AWS Secrets Manager** with automatic rotation enabled. Rotation cadence is tied directly to the Task 4 observability design: certificate expiry alerts already fire at 14 days and 3 days, and rotation should complete before the 14-day warning threshold, giving a clear operational deadline rather than an open-ended "rotate frequently."

### 3. IAM roles under-validated or over-permitted

**Risk:** This is a current, real gap in this project, not a hypothetical — the GitHub Actions OIDC role built in Task 3 currently holds `AmazonVPCFullAccess` and `AmazonEC2FullAccess`, far broader than the specific `ec2:CreateVpc`, `ec2:CreateSecurityGroup`-level actions Terraform actually performs. An over-permissioned pipeline identity increases the damage a compromised workflow run could do.

**Mitigation:** Replace the broad managed policies with a **custom least-privilege IAM policy** scoped to only the specific actions used by this project's Terraform resources. Detect drift from least-privilege going forward using **AWS IAM Access Analyzer**, which specifically flags unused permissions and over-broad roles — a concrete, automatable control, rather than relying on manual periodic review alone.
