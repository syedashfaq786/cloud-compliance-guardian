"""
PR Comment Bot — Posts compliance audit results as GitHub Pull Request comments.

Creates:
1. A summary comment with compliance scorecard table
2. Inline review comments on specific files for each finding

Usage:
    python post_review.py /path/to/audit_report.json
"""

import json
import os
import sys
import requests


GITHUB_API = "https://api.github.com"
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


def load_report(path: str) -> dict:
    """Load the audit report JSON."""
    with open(path, "r") as f:
        return json.load(f)


def build_summary_comment(report: dict) -> str:
    """Build a markdown summary comment for the PR."""
    score = report.get("compliance_score", 0)
    total = report.get("total_findings", 0)
    counts = report.get("severity_counts", {})
    files = report.get("files_scanned", 0)
    resources = report.get("resources_scanned", 0)

    # Grade
    if score >= 90:
        grade = "🟢 A"
    elif score >= 75:
        grade = "🟡 B"
    elif score >= 60:
        grade = "🟠 C"
    else:
        grade = "🔴 F"

    comment = f"""## ☁️ Cloud-Compliance Guardian Report

### Compliance Scorecard

| Metric | Value |
|--------|-------|
| **Grade** | {grade} |
| **Score** | **{score}%** |
| **Files Scanned** | {files} |
| **Resources Scanned** | {resources} |
| **Total Findings** | {total} |

### Severity Breakdown

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | {counts.get('CRITICAL', 0)} |
| 🟠 HIGH | {counts.get('HIGH', 0)} |
| 🟡 MEDIUM | {counts.get('MEDIUM', 0)} |
| 🔵 LOW | {counts.get('LOW', 0)} |

"""

    # Add findings table
    findings = report.get("findings", [])
    if findings:
        comment += "### Findings Detail\n\n"
        comment += "| # | CIS Rule | Severity | Resource | Description |\n"
        comment += "|---|----------|----------|----------|-------------|\n"

        for i, f in enumerate(findings[:25], 1):  # Limit to 25 in table
            sev = f.get("severity", "MEDIUM")
            emoji = SEVERITY_EMOJI.get(sev, "⬜")
            desc = f.get("description", "")[:80].replace("|", "\\|")
            comment += (
                f"| {i} | CIS {f.get('rule_id', '?')} "
                f"| {emoji} {sev} "
                f"| `{f.get('resource_address', '?')}` "
                f"| {desc} |\n"
            )

        if len(findings) > 25:
            comment += f"\n_...and {len(findings) - 25} more findings._\n"

    else:
        comment += "### ✅ All Clear!\nNo CIS Benchmark violations detected. Great work! 🎉\n"

    comment += "\n---\n_Powered by [Cloud-Compliance Guardian](https://github.com/cloud-compliance-guardian) using Cisco Sec-8B_"
    return comment


def build_inline_comments(report: dict) -> list:
    """Build inline review comments for specific findings."""
    comments = []
    findings = report.get("findings", [])

    for f in findings:
        file_path = f.get("file_path", "")
        if not file_path:
            continue

        sev = f.get("severity", "MEDIUM")
        emoji = SEVERITY_EMOJI.get(sev, "⬜")
        rule_id = f.get("rule_id", "?")
        desc = f.get("description", "No description")
        remediation = f.get("remediation_hcl", "")

        body = f"{emoji} **CIS {rule_id}** — {sev}\n\n{desc}\n"

        if f.get("reasoning"):
            body += f"\n**AI Reasoning:**\n> {f['reasoning']}\n"

        if remediation:
            body += f"\n**Remediation:**\n```hcl\n{remediation}\n```\n"

        comments.append({
            "path": file_path,
            "body": body,
            "line": 1,  # Default to line 1 since we may not have exact line info
        })

    return comments


def post_comment(repo: str, pr_number: int, body: str, token: str):
    """Post a comment on a PR."""
    url = f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    response = requests.post(url, json={"body": body}, headers=headers)
    response.raise_for_status()
    return response.json()


def post_review(repo: str, pr_number: int, comments: list, token: str):
    """Post a PR review with inline comments."""
    if not comments:
        return

    url = f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}/reviews"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    # GitHub limits to 50 comments per review
    batch = comments[:50]
    review_comments = []
    for c in batch:
        review_comments.append({
            "path": c["path"],
            "body": c["body"],
            "position": c.get("line", 1),
        })

    payload = {
        "body": "☁️ **Cloud-Compliance Guardian** found issues in this PR. See inline comments below.",
        "event": "COMMENT",
        "comments": review_comments,
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        # Fall back to individual comments if review fails
        for c in batch:
            try:
                post_comment(repo, pr_number, c["body"], token)
            except Exception:
                pass


def main():
    if len(sys.argv) < 2:
        print("Usage: python post_review.py <audit_report.json>")
        sys.exit(1)

    report_path = sys.argv[1]
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    pr_number = int(os.environ.get("PR_NUMBER", "0"))

    if not token or not repo or not pr_number:
        print("ERROR: GITHUB_TOKEN, GITHUB_REPOSITORY, and PR_NUMBER env vars required.")
        sys.exit(1)

    report = load_report(report_path)

    # Post summary comment
    summary = build_summary_comment(report)
    post_comment(repo, pr_number, summary, token)
    print(f"✅ Posted summary comment on PR #{pr_number}")

    # Post inline review comments
    inline_comments = build_inline_comments(report)
    if inline_comments:
        post_review(repo, pr_number, inline_comments, token)
        print(f"✅ Posted {len(inline_comments)} inline comments")
    else:
        print("ℹ️  No inline comments to post")


if __name__ == "__main__":
    main()
