"""
AWS Organization Topology Builder
Fetches hierarchical org structure, IAM relationships, and resources for visualization.
"""

import json
from typing import Dict, List, Any
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError


class TopologyBuilder:
    """Build hierarchical AWS organization topology for visualization."""

    def __init__(self):
        self.org_client = None
        self.iam_client = None
        self.sts_client = None
        self.ct_client  = None

    def initialize(self, access_key: str = None, secret_key: str = None, region: str = "us-east-1"):
        kwargs = {}
        if access_key and secret_key:
            kwargs["aws_access_key_id"]     = access_key
            kwargs["aws_secret_access_key"] = secret_key
        session = boto3.Session(**kwargs)
        self.org_client = session.client("organizations",  region_name=region)
        self.iam_client = session.client("iam",            region_name=region)
        self.sts_client = session.client("sts",            region_name=region)
        try:
            self.ct_client = session.client("cloudtrail", region_name=region)
        except Exception:
            self.ct_client = None

    # ── Organization hierarchy ──────────────────────────────────────────────

    def get_organization_structure(self) -> Dict[str, Any]:
        try:
            org   = self.org_client.describe_organization()["Organization"]
            roots = self.org_client.list_roots()["Roots"]
            nodes, edges = [], []
            counter = [0]

            org_node = {
                "id": org["Arn"], "type": "organization",
                "label": f"Organization",
                "parent": None,
                "data": {
                    "arn": org["Arn"],
                    "features_enabled": org.get("FeatureSet", "CONSOLIDATED_BILLING"),
                },
                "compliance": {"status": "PASS"},
                "position": {"x": 0, "y": 0},
            }
            nodes.append(org_node)

            for root in roots:
                self._process_ou(root["Id"], org_node["id"], nodes, edges, counter)

            return {"success": True, "nodes": nodes, "edges": edges, "organization": org}
        except ClientError as e:
            return {"success": False, "error": str(e), "message": "Failed to fetch org structure"}

    def _process_ou(self, ou_id: str, parent_id: str, nodes: list, edges: list, counter: list):
        try:
            ou = self.org_client.describe_organizational_unit(
                OrganizationalUnitId=ou_id
            ).get("OrganizationalUnit", {})

            ou_node = {
                "id": ou.get("Arn", f"ou-{counter[0]}"),
                "type": "organizational_unit",
                "label": ou.get("Name", "Unknown OU"),
                "parent": parent_id,
                "data": {"ou_id": ou_id, "arn": ou.get("Arn"), "accounts": []},
                "compliance": {"status": "UNKNOWN"},
                "position": {"x": counter[0] * 200, "y": 0},
            }
            nodes.append(ou_node)
            counter[0] += 1
            edges.append({"id": f"e-{parent_id}-{ou_node['id']}", "source": parent_id, "target": ou_node["id"], "type": "contains"})

            try:
                for child in self.org_client.list_children(ParentId=ou_id, ChildType="ACCOUNT")["Children"]:
                    self._add_account_node(child["Id"], ou_node["id"], nodes, edges, counter)
            except ClientError:
                pass

            try:
                for ou_child in self.org_client.list_children(ParentId=ou_id, ChildType="ORGANIZATIONAL_UNIT")["Children"]:
                    self._process_ou(ou_child["Id"], ou_node["id"], nodes, edges, counter)
            except ClientError:
                pass

        except ClientError as e:
            print(f"Error processing OU {ou_id}: {e}")

    def _add_account_node(self, account_id: str, parent_id: str, nodes: list, edges: list, counter: list):
        try:
            account = self.org_client.describe_account(AccountId=account_id)["Account"]
            account_node = {
                "id": account_id, "type": "account",
                "label": account.get("Name", "Unknown"),
                "parent": parent_id,
                "data": {
                    "account_id":   account_id,
                    "account_name": account.get("Name"),
                    "email":        account.get("Email"),
                    "status":       account.get("Status"),
                    "arn":          account.get("Arn"),
                },
                "compliance": {"status": "UNKNOWN"},
                "position": {"x": counter[0] * 150, "y": 200},
            }
            nodes.append(account_node)
            counter[0] += 1
            edges.append({"id": f"e-{parent_id}-{account_id}", "source": parent_id, "target": account_id, "type": "contains"})
        except ClientError as e:
            print(f"Error adding account {account_id}: {e}")

    # ── Account IAM topology ────────────────────────────────────────────────

    def get_account_iam_topology(self, account_id: str = None) -> Dict[str, Any]:
        try:
            nodes, edges = [], []

            if not account_id:
                account_id = self.sts_client.get_caller_identity()["Account"]

            acc_id = f"acc-{account_id}"
            nodes.append({
                "id": acc_id, "type": "account", "label": f"Account: {account_id}",
                "parent": None, "data": {"account_id": account_id},
                "compliance": {"status": "UNKNOWN"}, "position": {"x": 0, "y": 0},
            })

            # Root user from credential report
            try:
                raw    = self.iam_client.get_credential_report()["Content"]
                report = json.loads(raw.decode()) if isinstance(raw, bytes) else json.loads(raw)
                for entry in report:
                    if entry.get("user") == "<root_account>":
                        mfa_ok = entry.get("mfa_active") == "true"
                        nodes.append({
                            "id": f"root-{account_id}", "type": "iam_root", "label": "Root User",
                            "parent": acc_id,
                            "data": {
                                "mfa_active":       mfa_ok,
                                "password_enabled": entry.get("password_enabled") == "true",
                                "last_activity":    entry.get("last_activity"),
                            },
                            "compliance": {
                                "status": "PASS" if mfa_ok else "FAIL",
                                "findings": [] if mfa_ok else [{"title": "Root MFA not enabled", "severity": "CRITICAL", "status": "FAIL", "rule_id": "root-mfa"}],
                            },
                            "position": {"x": 100, "y": 100},
                        })
                        edges.append({"id": "e-acc-root", "source": acc_id, "target": f"root-{account_id}", "type": "contains"})
                        break
            except ClientError:
                pass

            # IAM users
            try:
                users = self.iam_client.list_users()["Users"]
                for i, user in enumerate(users[:20]):
                    uid = user["UserId"]
                    # Check MFA
                    mfa_devices = []
                    try:
                        mfa_devices = self.iam_client.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
                    except ClientError:
                        pass
                    mfa_ok = len(mfa_devices) > 0

                    # Access keys
                    keys = []
                    try:
                        keys = self.iam_client.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
                    except ClientError:
                        pass

                    findings = []
                    if not mfa_ok:
                        findings.append({"title": "MFA not enabled", "severity": "HIGH", "status": "FAIL", "rule_id": "iam-user-mfa"})
                    for k in keys:
                        age_days = (datetime.now(timezone.utc) - k["CreateDate"]).days
                        if age_days > 90:
                            findings.append({"title": f"Access key {k['AccessKeyId'][:8]}… is {age_days} days old", "severity": "MEDIUM", "status": "FAIL", "rule_id": "iam-key-rotation"})

                    nodes.append({
                        "id": uid, "type": "iam_user", "label": user["UserName"],
                        "parent": acc_id,
                        "data": {
                            "arn":        user["Arn"],
                            "created":    user["CreateDate"].isoformat(),
                            "mfa_active": mfa_ok,
                            "key_count":  len(keys),
                        },
                        "compliance": {
                            "status":   "FAIL" if findings else "PASS",
                            "findings": findings,
                            "failed":   len(findings),
                        },
                        "position": {"x": 100 + (i * 170), "y": 200},
                    })
                    edges.append({"id": f"e-acc-u-{uid}", "source": acc_id, "target": uid, "type": "contains"})
            except ClientError:
                pass

            # IAM roles
            try:
                roles = self.iam_client.list_roles()["Roles"]
                for i, role in enumerate(roles[:20]):
                    rid = role["RoleId"]
                    trust = role.get("AssumeRolePolicyDocument", {})
                    # Detect cross-account trust
                    cross_account = False
                    try:
                        for stmt in trust.get("Statement", []):
                            principal = stmt.get("Principal", {})
                            aws_p = principal.get("AWS", [])
                            if isinstance(aws_p, str):
                                aws_p = [aws_p]
                            if any("arn:aws:iam::" in p for p in aws_p):
                                cross_account = True
                    except Exception:
                        pass

                    nodes.append({
                        "id": rid, "type": "iam_role", "label": role["RoleName"],
                        "parent": acc_id,
                        "data": {
                            "arn":           role["Arn"],
                            "created":       role["CreateDate"].isoformat(),
                            "cross_account": cross_account,
                        },
                        "compliance": {"status": "UNKNOWN"},
                        "position": {"x": 100 + (i * 170), "y": 350},
                    })
                    edges.append({"id": f"e-acc-r-{rid}", "source": acc_id, "target": rid, "type": "contains"})
            except ClientError:
                pass

            return {"success": True, "nodes": nodes, "edges": edges, "account_id": account_id}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── CloudTrail attribution ──────────────────────────────────────────────

    def get_cloudtrail_attribution(self, region: str = "us-east-1", max_events: int = 50) -> List[Dict]:
        """Return recent CloudTrail events with attribution metadata."""
        if not self.ct_client:
            return []
        try:
            resp   = self.ct_client.lookup_events(MaxResults=max_events)
            events = resp.get("Events", [])
            result = []
            for ev in events:
                username = ev.get("Username", "Unknown")
                resources = [{"type": r.get("ResourceType",""), "name": r.get("ResourceName","")} for r in ev.get("Resources", [])]
                ct_event = ev.get("CloudTrailEvent", "{}")
                try:
                    detail = json.loads(ct_event)
                except Exception:
                    detail = {}
                error_code = detail.get("errorCode", "")
                source_ip  = detail.get("sourceIPAddress", "")
                suspicious = bool(
                    error_code in ("AccessDenied", "UnauthorizedOperation")
                    or "root" in username.lower()
                    or detail.get("userIdentity", {}).get("type") == "Root"
                )
                result.append({
                    "event_name":   ev.get("EventName", ""),
                    "event_source": detail.get("eventSource", ""),
                    "username":     username,
                    "event_time":   ev.get("EventTime", "").isoformat() if hasattr(ev.get("EventTime",""), "isoformat") else str(ev.get("EventTime","")),
                    "region":       detail.get("awsRegion", region),
                    "source_ip":    source_ip,
                    "resources":    resources,
                    "error_code":   error_code,
                    "is_suspicious": suspicious,
                })
            return result
        except ClientError:
            return []


# ── Singleton ───────────────────────────────────────────────────────────────
_topology_builder: TopologyBuilder = None


def get_topology_builder() -> TopologyBuilder:
    global _topology_builder
    if _topology_builder is None:
        _topology_builder = TopologyBuilder()
    return _topology_builder
