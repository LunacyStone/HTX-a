# Terraform Security Risk Analyzer

Analyzes git diff or Terraform plan JSON output to detect security risks and classify changes by risk level.

## Features

- Parses `git diff` output.
- Parses Terraform plan JSON output.
- Detects risky security group and network ACL changes.
- Detects overly permissive IAM policy changes.
- Detects encryption removal or downgrade.
- Produces a JSON report.
- Exits with a non-zero status when high-risk findings are detected.

## Classes

### `RiskLevel`

Defines the supported risk levels: `low`, `medium`, and `high`.

### `SecurityFinding`

Stores a single security finding with description, risk level, reasoning, recommendation, and optional resource metadata.

### `TerraformSecurityAnalyzer`

Main analyzer class that parses input and generates security findings.

## Functions

| Function | Description |
|---|---|
| `__init__` | Initializes findings and defines high-risk ports and sensitive IAM actions. |
| `parse_git_diff` | Parses git diff text into changed files, resources, added lines, and removed lines. |
| `parse_terraform_plan_json` | Extracts resource changes from Terraform plan JSON output. |
| `analyze_cidr_exposure` | Detects security group rules that expose sensitive ports or all ports to `0.0.0.0/0`. |
| `analyze_iam_permissions` | Detects new wildcard IAM actions or overly broad IAM resource permissions. |
| `analyze_encryption_changes` | Detects removed, disabled, or downgraded encryption settings. |
| `analyze_network_acl_changes` | Detects network ACL rules that allow all traffic from `0.0.0.0/0`. |
| `analyze_security_group_changes` | Analyzes git diff lines for security group rules that open internet CIDR blocks. |
| `analyze_git_diff_changes` | Runs git-diff-specific checks for security group and IAM policy changes. |
| `analyze_json_plan_changes` | Runs Terraform plan checks for security groups, IAM policies, encryption, and network ACLs. |
| `analyze` | Detects the input format and runs the appropriate analysis path. |
| `get_report` | Returns a structured summary and list of findings. |
| `has_high_risk` | Returns `True` if any finding has a high risk level. |
| `main` | Parses CLI arguments, reads input, runs analysis, prints the report, and sets the exit code. |

## Usage

### Analyze a git diff file

```bash
python detector.py --git-diff git_diff.txt