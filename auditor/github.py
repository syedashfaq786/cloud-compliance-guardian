"""
GitHub Integration Mock/Simulator — Manages local clones of repositories for scanning.
"""

import os
import subprocess
import shutil
import uuid
from typing import Optional, Dict, Any
from .audit import run_audit

REPOS_DIR = os.path.join(os.path.dirname(__file__), "repos")

def get_repo_name_from_url(url: str) -> str:
    """Extract repository name from GitHub URL."""
    return url.rstrip("/").split("/")[-1].replace(".git", "")

def clone_repo(url: str) -> str:
    """Clone a GitHub repository to the local repos directory."""
    if not os.path.exists(REPOS_DIR):
        os.makedirs(REPOS_DIR)
    
    repo_name = get_repo_name_from_url(url)
    repo_path = os.path.join(REPOS_DIR, repo_name)
    
    if os.path.exists(repo_path):
        # If it exists, try to pull instead
        subprocess.run(["git", "-C", repo_path, "pull"], check=False)
    else:
        subprocess.run(["git", "clone", "--depth", "1", url, repo_path], check=True)
    
    return repo_name

def get_repo_metadata(repo_name: str) -> Dict[str, Any]:
    """Get latest commit info using git log."""
    repo_path = os.path.join(REPOS_DIR, repo_name)
    if not os.path.exists(repo_path):
        return {}
    
    try:
        # Get latest commit SHA, author, and message
        log_format = "%H|%an|%s|%at"
        result = subprocess.run(
            ["git", "-C", repo_path, "log", "-1", f"--format={log_format}"],
            capture_output=True,
            text=True,
            check=True
        )
        sha, author, message, timestamp = result.stdout.strip().split("|")
        
        return {
            "name": repo_name,
            "url": f"https://github.com/{repo_name}", # Simplified
            "last_commit": {
                "sha": sha[:8],
                "author": author,
                "message": message,
                "timestamp": timestamp
            }
        }
    except Exception:
        return {"name": repo_name, "error": "Could not fetch metadata"}

def sync_and_scan(repo_name: str, terraform_framework: str = "CIS") -> Dict[str, Any]:
    """Pull latest changes and run Terraform compliance audit."""
    repo_path = os.path.join(REPOS_DIR, repo_name)
    if not os.path.exists(repo_path):
        raise FileNotFoundError(f"Repo {repo_name} not found")
    
    # Git pull
    subprocess.run(["git", "-C", repo_path, "pull"], check=False)
    
    # Run audit
    report = run_audit(
        directory=repo_path,
        framework=(terraform_framework or "CIS"),
        triggered_by="github",
        pr_url=f"https://github.com/{repo_name}/commits/main"
    )
    
    return report.to_dict()
