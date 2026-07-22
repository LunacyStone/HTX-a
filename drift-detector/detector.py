#!/usr/bin/env python3
"""
Terraform Security Risk Analyzer
Analyzes git diff or terraform plan JSON output to detect security risks
and classify changes by risk level.
"""

import json
import re
import sys
import argparse
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class SecurityFinding:
    change_description: str
    risk_level: str
    reasoning: str
    recommendation: str
    resource_address: Optional[str] = None
    change_type: Optional[str] = None


class TerraformSecurityAnalyzer:
    """Analyzes Terraform changes for security risks."""
    
    def __init__(self):
        self.findings: List[SecurityFinding] = []
        
        # High-risk ports that should never be open to 0.0.0.0/0
        self.high_risk_ports = {
            22: "SSH",
            23: "Telnet",
            3389: "RDP",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            9200: "Elasticsearch",
            50000: "Jenkins"
        }
        
        # Sensitive IAM actions
        self.sensitive_iam_actions = [
            "iam:*",
            "iam:CreateUser",
            "iam:DeleteUser",
            "iam:CreateAccessKey",
            "iam:AttachUserPolicy",
            "iam:AttachRolePolicy",
            "sts:AssumeRole",
            "kms:Decrypt",
            "kms:Encrypt",
            "secretsmanager:*",
            "ssm:GetParameter"
        ]

    def parse_git_diff(self, diff_text: str) -> List[Dict[str, Any]]:
        """Parse git diff output to extract changes."""
        changes = []
        current_file = None
        current_resource = None
        added_lines = []
        removed_lines = []
        
        lines = diff_text.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Detect file change
            if line.startswith('diff --git'):
                if current_file and (added_lines or removed_lines):
                    changes.append({
                        'file': current_file,
                        'resource': current_resource,
                        'added': added_lines,
                        'removed': removed_lines
                    })
                current_file = line.split('/')[-1] if '/' in line else line
                added_lines = []
                removed_lines = []
                current_resource = None
                
            # Detect resource block
            elif line.startswith('@@') or line.startswith('resource'):
                resource_match = re.search(r'resource\s+"([^"]+)"\s+"([^"]+)"', line)
                if resource_match:
                    current_resource = f"{resource_match.group(1)}.{resource_match.group(2)}"
                    
            # Track added lines
            elif line.startswith('+') and not line.startswith('+++'):
                added_lines.append(line[1:].strip())
                
            # Track removed lines
            elif line.startswith('-') and not line.startswith('---'):
                removed_lines.append(line[1:].strip())
                
            i += 1
        
        # Don't forget the last change
        if current_file and (added_lines or removed_lines):
            changes.append({
                'file': current_file,
                'resource': current_resource,
                'added': added_lines,
                'removed': removed_lines
            })
        
        return changes

    def parse_terraform_plan_json(self, plan_json: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse terraform plan JSON output."""
        changes = []
        
        resource_changes = plan_json.get('resource_changes', [])
        
        for resource in resource_changes:
            address = resource.get('address', '')
            change = resource.get('change', {})
            actions = change.get('actions', [])
            
            before = change.get('before', {})
            after = change.get('after', {})
            
            changes.append({
                'resource': address,
                'actions': actions,
                'before': before,
                'after': after,
                'file': address.split('.')[0] if '.' in address else ''
            })
        
        return changes

    def analyze_cidr_exposure(self, resource: str, before: Dict, after: Dict) -> Optional[SecurityFinding]:
        """Check for dangerous CIDR block exposures."""
        if 'cidr_blocks' not in after:
            return None
            
        cidr_blocks = after.get('cidr_blocks', [])
        old_cidr_blocks = before.get('cidr_blocks', []) if before else []
        
        # Check if 0.0.0.0/0 was added
        if '0.0.0.0/0' in cidr_blocks and '0.0.0.0/0' not in old_cidr_blocks:
            # Check what ports are affected
            from_port = after.get('from_port', 0)
            to_port = after.get('to_port', 65535)

            # Check if any known high-risk port falls within the opened range.
            # NOTE: previously this iterated port-by-port with an arbitrary
            # 100-port cap (range(from_port, min(to_port+1, from_port+100))),
            # which silently missed high-risk ports in wide ranges that don't
            # start near them (e.g. from_port=2000, to_port=65535 would miss
            # 3306/3389/5432/6379/9200/27017/50000 entirely, since they're
            # all more than 100 ports above 2000). Checking direct membership
            # against the known high-risk port set is correct regardless of
            # how wide the opened range is, and is O(1) per port instead of
            # scanning a bounded window.
            exposed_high_risk_ports = {
                port: name
                for port, name in self.high_risk_ports.items()
                if from_port <= port <= to_port
            }
            if exposed_high_risk_ports:
                other_ports = ", ".join(
                    f"{p} ({n})" for p, n in exposed_high_risk_ports.items()
                )
                return SecurityFinding(
                    change_description=f"Security group rule opens sensitive port(s) to internet (0.0.0.0/0): {other_ports}",
                    risk_level=RiskLevel.HIGH.value,
                    reasoning=f"The opened range {from_port}-{to_port} includes sensitive service port(s) ({other_ports}) exposed to the entire internet. This allows anyone to attempt connections to these sensitive services.",
                    recommendation="Restrict cidr_blocks to specific IP ranges or VPC CIDR blocks. Use security groups and network ACLs to limit access to trusted sources only."
                )

            # Even if not a known high-risk port, opening all ports is dangerous
            if from_port == 0 and to_port == 65535:
                return SecurityFinding(
                    change_description="Security group rule opens ALL ports (0-65535) to internet (0.0.0.0/0)",
                    risk_level=RiskLevel.HIGH.value,
                    reasoning="All TCP/UDP ports are exposed to the internet. This is an extremely dangerous configuration that exposes all services.",
                    recommendation="Specify explicit port ranges needed for your application. Never open all ports to 0.0.0.0/0."
                )
            
            # Medium risk for other ports opened to internet
            return SecurityFinding(
                change_description=f"Security group rule opens ports {from_port}-{to_port} to internet (0.0.0.0/0)",
                risk_level=RiskLevel.MEDIUM.value,
                reasoning=f"Ports {from_port}-{to_port} are exposed to the entire internet. This increases the attack surface.",
                recommendation="Restrict cidr_blocks to specific IP ranges or use VPC peering/PrivateLink for internal services."
            )
        
        return None

    def analyze_iam_permissions(self, resource: str, before: Dict, after: Dict) -> Optional[SecurityFinding]:
        """Check for overly permissive IAM policies."""
        # Check for wildcard actions or resources
        policy_doc = after.get('policy', '')
        old_policy_doc = before.get('policy', '') if before else ''
        
        if isinstance(policy_doc, dict):
            policy_doc = json.dumps(policy_doc)
        
        # Check for new wildcard permissions
        if policy_doc and '*' in policy_doc:
            # Check if this is a new addition
            if not old_policy_doc or '*' not in old_policy_doc:
                if '"Action": "*"' in policy_doc or '"Action":"*"' in policy_doc:
                    return SecurityFinding(
                        change_description="IAM policy grants wildcard (*) actions",
                        risk_level=RiskLevel.HIGH.value,
                        reasoning="The policy grants all possible actions (*), which violates the principle of least privilege and could allow unauthorized access to all AWS resources.",
                        recommendation="Specify explicit actions needed for the use case. Avoid wildcards in IAM policies. Use AWS IAM Access Analyzer to identify minimum required permissions."
                    )
                
                if '"Resource": "*"' in policy_doc or '"Resource":"*"' in policy_doc:
                    # Check if it's combined with sensitive actions
                    for action in self.sensitive_iam_actions:
                        if action in policy_doc:
                            return SecurityFinding(
                                change_description=f"IAM policy grants {action} on all resources (*)",
                                risk_level=RiskLevel.HIGH.value,
                                reasoning=f"Granting {action} on all resources (*) is overly permissive and could lead to privilege escalation or data exposure.",
                                recommendation=f"Restrict the Resource ARN to specific resources. For {action}, use resource-level permissions where available."
                            )
                    
                    return SecurityFinding(
                        change_description="IAM policy grants actions on all resources (*)",
                        risk_level=RiskLevel.MEDIUM.value,
                        reasoning="The policy applies to all resources (*), which may be overly permissive depending on the actions granted.",
                        recommendation="Specify explicit resource ARNs where possible. Use conditions to further restrict access."
                    )
        
        return None

    def analyze_encryption_changes(self, resource: str, before: Dict, after: Dict) -> Optional[SecurityFinding]:
        """Check for removal or disabling of encryption settings."""
        encryption_fields = [
            'sse_algorithm', 'kms_master_key_id', 'encrypted', 
            'storage_encrypted', 'enable_encryption', 'encryption'
        ]
        
        for field in encryption_fields:
            before_value = before.get(field) if before else None
            after_value = after.get(field)
            
            # Check if encryption was removed or disabled
            if before_value and not after_value:
                return SecurityFinding(
                    change_description=f"Encryption setting '{field}' was removed or disabled",
                    risk_level=RiskLevel.HIGH.value,
                    reasoning=f"Removing encryption ({field}) exposes data at rest to potential unauthorized access and violates compliance requirements.",
                    recommendation="Enable encryption for all data stores. Use AWS KMS for key management. Ensure encryption is enabled in production environments."
                )
            
            # Check if encryption algorithm was downgraded
            if field == 'sse_algorithm' and before_value != after_value:
                if after_value in ['AES256'] and before_value in ['aws:kms']:
                    return SecurityFinding(
                        change_description=f"Encryption downgraded from {before_value} to {after_value}",
                        risk_level=RiskLevel.MEDIUM.value,
                        reasoning="Downgrading from KMS-managed keys to S3-managed keys reduces control over encryption keys and audit capabilities.",
                        recommendation="Use AWS KMS customer-managed keys (CMKs) for better key control, rotation, and audit trails."
                    )
        
        return None

    def analyze_network_acl_changes(self, resource: str, before: Dict, after: Dict) -> Optional[SecurityFinding]:
        """Check for dangerous network ACL changes."""
        # Check for rules that allow all traffic
        if 'ingress' in after or 'egress' in after:
            for direction in ['ingress', 'egress']:
                rules = after.get(direction, [])
                old_rules = before.get(direction, []) if before else []
                
                if isinstance(rules, dict):
                    rules = [rules]
                
                for rule in rules:
                    if isinstance(rule, dict):
                        # Check for allow all
                        if rule.get('action') == 'allow':
                            from_port = rule.get('from_port', 0)
                            to_port = rule.get('to_port', 65535)
                            cidr = rule.get('cidr_block', '')
                            
                            if cidr == '0.0.0.0/0' and from_port == 0 and to_port == 65535:
                                # Check if this is new
                                is_new = True
                                for old_rule in (old_rules if isinstance(old_rules, list) else [old_rules]):
                                    if isinstance(old_rule, dict) and old_rule.get('cidr_block') == cidr:
                                        is_new = False
                                        break
                                
                                if is_new:
                                    return SecurityFinding(
                                        change_description=f"Network ACL {direction} rule allows all traffic from 0.0.0.0/0",
                                        risk_level=RiskLevel.HIGH.value,
                                        reasoning=f"Allowing all {direction} traffic from the internet bypasses network security controls and exposes all services.",
                                        recommendation=f"Restrict {direction} rules to specific ports and CIDR blocks. Use security groups for instance-level protection."
                                    )
        
        return None

    def analyze_security_group_changes(self, resource: str, added: List[str], removed: List[str]) -> Optional[SecurityFinding]:
        """Analyze git diff for security group changes."""
        # Check for 0.0.0.0/0 in added lines
        added_text = '\n'.join(added)
        for line in added:
            if '0.0.0.0/0' in line:
                # Extract from_port / to_port using regex (handles Terraform's
                # aligned whitespace, e.g. "from_port   = 0", which the
                # previous exact-string checks like 'from_port = 0' in text
                # silently failed to match, missing the assignment's own
                # sample diff — opening 0-65535 to 0.0.0.0/0 — entirely).
                from_match = re.search(r'from_port\s*=\s*(\d+)', added_text)
                to_match = re.search(r'to_port\s*=\s*(\d+)', added_text)
                from_port = int(from_match.group(1)) if from_match else None
                to_port = int(to_match.group(1)) if to_match else None

                # Check for any high-risk port within the opened range
                if from_port is not None and to_port is not None:
                    exposed = {
                        p: n for p, n in self.high_risk_ports.items()
                        if from_port <= p <= to_port
                    }
                    if exposed:
                        ports_desc = ", ".join(f"{p} ({n})" for p, n in exposed.items())
                        return SecurityFinding(
                            change_description=f"Security group opens sensitive port(s) to 0.0.0.0/0: {ports_desc}",
                            risk_level=RiskLevel.HIGH.value,
                            reasoning=f"The opened range {from_port}-{to_port} includes sensitive service port(s) ({ports_desc}) exposed to the entire internet.",
                            recommendation="Restrict to specific IP ranges or use VPN/Direct Connect for secure access."
                        )

                    # Check for all ports opened, even if none are in the
                    # known high-risk list
                    if from_port == 0 and to_port == 65535:
                        return SecurityFinding(
                            change_description="Security group opens ALL ports to 0.0.0.0/0",
                            risk_level=RiskLevel.HIGH.value,
                            reasoning="All ports are being exposed to the internet, which is extremely dangerous.",
                            recommendation="Specify explicit port ranges. Never open all ports to the internet."
                        )

                return SecurityFinding(
                    change_description="Security group rule adds 0.0.0.0/0 CIDR block",
                    risk_level=RiskLevel.MEDIUM.value,
                    reasoning="Opening security group to the internet increases attack surface.",
                    recommendation="Use specific IP ranges or VPC CIDR blocks instead of 0.0.0.0/0."
                )
        
        return None

    def analyze_git_diff_changes(self, changes: List[Dict]) -> List[SecurityFinding]:
        """Analyze git diff changes for security issues."""
        findings = []
        
        for change in changes:
            resource = change.get('resource', '')
            added = change.get('added', [])
            removed = change.get('removed', [])
            
            # Check for security group changes
            if 'security_group' in resource or 'security_group_rule' in resource:
                finding = self.analyze_security_group_changes(resource, added, removed)
                if finding:
                    finding.resource_address = resource
                    finding.change_type = 'git_diff'
                    findings.append(finding)
            
            # Check for IAM policy changes
            if 'iam' in resource and 'policy' in resource:
                for line in added:
                    if '*' in line and ('Action' in line or 'Resource' in line):
                        findings.append(SecurityFinding(
                            change_description="IAM policy modification detected with wildcard",
                            risk_level=RiskLevel.MEDIUM.value,
                            reasoning="IAM policy is being modified with wildcard characters which may grant excessive permissions.",
                            recommendation="Review IAM policy changes carefully. Ensure they follow least privilege principle."
                        ))
                        break
        
        return findings

    def analyze_json_plan_changes(self, changes: List[Dict]) -> List[SecurityFinding]:
        """Analyze terraform plan JSON changes for security issues."""
        findings = []
        
        for change in changes:
            resource = change.get('resource', '')
            actions = change.get('actions', [])
            before = change.get('before', {})
            after = change.get('after', {})
            
            # Skip if no change or if it's a delete
            if not actions or 'delete' in actions:
                continue
            
            # Check for security group rule changes
            if 'aws_security_group_rule' in resource or 'azurerm_security_rule' in resource:
                finding = self.analyze_cidr_exposure(resource, before, after)
                if finding:
                    finding.resource_address = resource
                    finding.change_type = 'terraform_plan'
                    findings.append(finding)
            
            # Check for IAM policy changes
            if 'iam_policy' in resource or 'iam_role_policy' in resource:
                finding = self.analyze_iam_permissions(resource, before, after)
                if finding:
                    finding.resource_address = resource
                    finding.change_type = 'terraform_plan'
                    findings.append(finding)
            
            # Check for encryption changes
            if any(x in resource for x in ['s3_bucket', 'rds', 'dynamodb', 'ebs', 'efs']):
                finding = self.analyze_encryption_changes(resource, before, after)
                if finding:
                    finding.resource_address = resource
                    finding.change_type = 'terraform_plan'
                    findings.append(finding)
            
            # Check for network ACL changes
            if 'network_acl' in resource:
                finding = self.analyze_network_acl_changes(resource, before, after)
                if finding:
                    finding.resource_address = resource
                    finding.change_type = 'terraform_plan'
                    findings.append(finding)
        
        return findings

    def analyze(self, input_data: str, input_format: str = 'auto') -> List[SecurityFinding]:
        """
        Main analysis method.
        
        Args:
            input_data: Git diff text or terraform plan JSON string
            input_format: 'git_diff', 'terraform_plan', or 'auto'
        
        Returns:
            List of SecurityFinding objects
        """
        self.findings = []
        
        # Auto-detect format if needed
        if input_format == 'auto':
            try:
                plan_json = json.loads(input_data)
                if 'resource_changes' in plan_json:
                    input_format = 'terraform_plan'
                else:
                    input_format = 'git_diff'
            except json.JSONDecodeError:
                input_format = 'git_diff'
        
        if input_format == 'git_diff':
            changes = self.parse_git_diff(input_data)
            self.findings.extend(self.analyze_git_diff_changes(changes))
        elif input_format == 'terraform_plan':
            plan_json = json.loads(input_data)
            changes = self.parse_terraform_plan_json(plan_json)
            self.findings.extend(self.analyze_json_plan_changes(changes))
        
        return self.findings

    def get_report(self) -> Dict[str, Any]:
        """Generate structured report."""
        high_risk = [f for f in self.findings if f.risk_level == RiskLevel.HIGH.value]
        medium_risk = [f for f in self.findings if f.risk_level == RiskLevel.MEDIUM.value]
        low_risk = [f for f in self.findings if f.risk_level == RiskLevel.LOW.value]
        
        return {
            'summary': {
                'total_findings': len(self.findings),
                'high_risk': len(high_risk),
                'medium_risk': len(medium_risk),
                'low_risk': len(low_risk),
                'has_high_risk': len(high_risk) > 0
            },
            'findings': [asdict(f) for f in self.findings]
        }

    def has_high_risk(self) -> bool:
        """Check if any findings are high risk."""
        return any(f.risk_level == RiskLevel.HIGH.value for f in self.findings)


def main():
    parser = argparse.ArgumentParser(
        description='Terraform Security Risk Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze git diff from file
  python terraform_security_analyzer.py --git-diff git_diff.txt
  
  # Analyze terraform plan JSON from file
  python terraform_security_analyzer.py --plan plan.json
  
  # Analyze from stdin
  cat git_diff.txt | python terraform_security_analyzer.py
  
  # Output to file
  python terraform_security_analyzer.py --plan plan.json --output report.json
        """
    )
    
    parser.add_argument('--git-diff', type=str, help='Path to git diff output file')
    parser.add_argument('--plan', type=str, help='Path to terraform plan JSON file')
    parser.add_argument('--input', type=str, help='Read from specified file (auto-detect format)')
    parser.add_argument('--output', type=str, help='Output report to file (default: stdout)')
    parser.add_argument('--format', type=str, choices=['git_diff', 'terraform_plan', 'auto'],
                       default='auto', help='Input format (default: auto)')
    
    args = parser.parse_args()
    
    # Determine input source
    input_data = None
    input_format = args.format
    
    if args.git_diff:
        with open(args.git_diff, 'r') as f:
            input_data = f.read()
        input_format = 'git_diff'
    elif args.plan:
        with open(args.plan, 'r') as f:
            input_data = f.read()
        input_format = 'terraform_plan'
    elif args.input:
        with open(args.input, 'r') as f:
            input_data = f.read()
    else:
        # Read from stdin
        input_data = sys.stdin.read()
    
    if not input_data or not input_data.strip():
        print("Error: No input data provided", file=sys.stderr)
        sys.exit(1)
    
    # Run analysis
    analyzer = TerraformSecurityAnalyzer()
    try:
        analyzer.analyze(input_data, input_format)
    except Exception as e:
        print(f"Error analyzing input: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Generate report
    report = analyzer.get_report()
    
    # Output report
    output_json = json.dumps(report, indent=2)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_json)
        print(f"Report written to {args.output}")
    else:
        print(output_json)
    
    # Print summary to stderr
    print(f"\n=== Security Analysis Summary ===", file=sys.stderr)
    print(f"Total findings: {report['summary']['total_findings']}", file=sys.stderr)
    print(f"High risk: {report['summary']['high_risk']}", file=sys.stderr)
    print(f"Medium risk: {report['summary']['medium_risk']}", file=sys.stderr)
    print(f"Low risk: {report['summary']['low_risk']}", file=sys.stderr)
    
    # Exit with non-zero code if high risk findings
    if analyzer.has_high_risk():
        print("\n⚠️  HIGH RISK FINDINGS DETECTED - Pipeline should fail", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n✓ No high risk findings detected", file=sys.stderr)
        sys.exit(0)


if __name__ == '__main__':
    main()
