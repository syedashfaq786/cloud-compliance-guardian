import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api import _run_github_repo_scan

result = _run_github_repo_scan(
    repo_name="mixed-demo-repo",
    terraform_framework="NIST",
    container_framework="NIST",
    scan_containers=True
)

print("=" * 50)
print("SCAN SUMMARY")
print("=" * 50)
print(f"Terraform Audit ID: {result.get('terraform_audit_id')}")
print(f"\nContainer Results ({len(result.get('container', []))} scans):")
for c in result.get('container', []):
    print(f"  - {c['target']}: {c['status']}")
    print(f"    Framework: {c['framework']}")
    print(f"    Audit ID: {c.get('audit_id', 'N/A')}")
