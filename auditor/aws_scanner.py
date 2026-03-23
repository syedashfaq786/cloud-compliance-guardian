"""
AWS Live Scanner — Fetches real-time configurations from AWS using Boto3.

Scans S3 Buckets, EC2 Security Groups, IAM Policies, and CloudTrail events.
Strips sensitive metadata (Account IDs, ARNs) before sending to Sec-8B.
"""

import os
import re
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError


class AWSScanner:
    """Fetches and normalizes AWS resource configurations for compliance auditing."""

    def __init__(
        self,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        region: Optional[str] = None,
    ):
        self.access_key = access_key or os.getenv("AWS_ACCESS_KEY_ID")
        self.secret_key = secret_key or os.getenv("AWS_SECRET_ACCESS_KEY")
        self.region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self._session = None

    def _get_session(self) -> boto3.Session:
        """Create or return cached boto3 session."""
        if self._session is None:
            kwargs = {"region_name": self.region}
            if self.access_key and self.secret_key:
                kwargs["aws_access_key_id"] = self.access_key
                kwargs["aws_secret_access_key"] = self.secret_key
            self._session = boto3.Session(**kwargs)
        return self._session

    def _client(self, service: str):
        """Get a boto3 client for a service."""
        return self._get_session().client(service)

    def test_connection(self) -> Dict[str, Any]:
        """Test AWS credentials by calling STS GetCallerIdentity."""
        try:
            sts = self._client("sts")
            identity = sts.get_caller_identity()
            return {
                "connected": True,
                "account_id": self._mask_account_id(identity.get("Account", "")),
                "user": identity.get("Arn", "").split("/")[-1] if identity.get("Arn") else "unknown",
                "region": self.region,
            }
        except NoCredentialsError:
            return {"connected": False, "error": "No AWS credentials configured"}
        except ClientError as e:
            return {"connected": False, "error": str(e)}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    # ── S3 Buckets ────────────────────────────────────────────────────────────

    def scan_s3_buckets(self) -> List[Dict[str, Any]]:
        """List all S3 buckets with their security configurations."""
        s3 = self._client("s3")
        results = []

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except (ClientError, BotoCoreError) as e:
            return [{"resource_type": "s3_bucket", "error": str(e)}]

        for bucket in buckets:
            name = bucket["Name"]
            resource = {
                "resource_type": "aws_s3_bucket",
                "resource_id": self._hash_id(name),
                "resource_name": name,
                "created": bucket.get("CreationDate", "").isoformat() if hasattr(bucket.get("CreationDate", ""), "isoformat") else str(bucket.get("CreationDate", "")),
                "config": {},
            }

            # Encryption
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                resource["config"]["encryption"] = {
                    "enabled": True,
                    "algorithm": rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] if rules else "none",
                }
            except ClientError:
                resource["config"]["encryption"] = {"enabled": False, "algorithm": "none"}

            # Versioning
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                resource["config"]["versioning"] = ver.get("Status", "Disabled")
            except ClientError:
                resource["config"]["versioning"] = "Unknown"

            # Public access block
            try:
                pub = s3.get_public_access_block(Bucket=name)
                config = pub.get("PublicAccessBlockConfiguration", {})
                resource["config"]["public_access_block"] = {
                    "block_public_acls": config.get("BlockPublicAcls", False),
                    "block_public_policy": config.get("BlockPublicPolicy", False),
                    "ignore_public_acls": config.get("IgnorePublicAcls", False),
                    "restrict_public_buckets": config.get("RestrictPublicBuckets", False),
                }
            except ClientError:
                resource["config"]["public_access_block"] = {
                    "block_public_acls": False,
                    "block_public_policy": False,
                    "ignore_public_acls": False,
                    "restrict_public_buckets": False,
                }

            # Logging
            try:
                log = s3.get_bucket_logging(Bucket=name)
                resource["config"]["logging"] = bool(log.get("LoggingEnabled"))
            except ClientError:
                resource["config"]["logging"] = False

            results.append(resource)

        return results

    # ── EC2 Security Groups ───────────────────────────────────────────────────

    def scan_security_groups(self) -> List[Dict[str, Any]]:
        """List all EC2 security groups with ingress/egress rules."""
        ec2 = self._client("ec2")
        results = []

        try:
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        except (ClientError, BotoCoreError) as e:
            return [{"resource_type": "security_group", "error": str(e)}]

        for sg in sgs:
            resource = {
                "resource_type": "aws_security_group",
                "resource_id": self._hash_id(sg["GroupId"]),
                "resource_name": sg.get("GroupName", ""),
                "config": {
                    "description": sg.get("Description", ""),
                    "vpc_id": self._hash_id(sg.get("VpcId", "")),
                    "ingress_rules": [],
                    "egress_rules": [],
                },
            }

            for rule in sg.get("IpPermissions", []):
                for cidr in rule.get("IpRanges", []):
                    resource["config"]["ingress_rules"].append({
                        "protocol": rule.get("IpProtocol", "all"),
                        "from_port": rule.get("FromPort", 0),
                        "to_port": rule.get("ToPort", 65535),
                        "cidr": cidr.get("CidrIp", ""),
                        "description": cidr.get("Description", ""),
                    })

            for rule in sg.get("IpPermissionsEgress", []):
                for cidr in rule.get("IpRanges", []):
                    resource["config"]["egress_rules"].append({
                        "protocol": rule.get("IpProtocol", "all"),
                        "from_port": rule.get("FromPort", 0),
                        "to_port": rule.get("ToPort", 65535),
                        "cidr": cidr.get("CidrIp", ""),
                    })

            results.append(resource)

        return results

    # ── IAM Policies ──────────────────────────────────────────────────────────

    def scan_iam_policies(self) -> List[Dict[str, Any]]:
        """List customer-managed IAM policies with their permissions."""
        iam = self._client("iam")
        results = []

        try:
            policies = iam.list_policies(Scope="Local", MaxItems=50).get("Policies", [])
        except (ClientError, BotoCoreError) as e:
            return [{"resource_type": "iam_policy", "error": str(e)}]

        for pol in policies:
            resource = {
                "resource_type": "aws_iam_policy",
                "resource_id": self._hash_id(pol["PolicyId"]),
                "resource_name": pol["PolicyName"],
                "config": {
                    "attachment_count": pol.get("AttachmentCount", 0),
                    "is_attachable": pol.get("IsAttachable", True),
                    "create_date": pol.get("CreateDate", "").isoformat() if hasattr(pol.get("CreateDate", ""), "isoformat") else str(pol.get("CreateDate", "")),
                },
            }

            # Get policy document
            try:
                version = pol.get("DefaultVersionId", "v1")
                doc = iam.get_policy_version(
                    PolicyArn=pol["Arn"],
                    VersionId=version
                )
                statement = doc["PolicyVersion"]["Document"].get("Statement", [])
                resource["config"]["statements"] = []
                for s in statement:
                    resource["config"]["statements"].append({
                        "effect": s.get("Effect", ""),
                        "action": s.get("Action", []),
                        "resource": self._sanitize_resources(s.get("Resource", [])),
                    })

                # Flag wildcard admin access
                resource["config"]["has_admin_access"] = any(
                    s.get("Effect") == "Allow" and
                    (s.get("Action") == "*" or (isinstance(s.get("Action"), list) and "*" in s["Action"])) and
                    (s.get("Resource") == "*" or (isinstance(s.get("Resource"), list) and "*" in s["Resource"]))
                    for s in statement
                )
            except (ClientError, KeyError):
                resource["config"]["statements"] = []
                resource["config"]["has_admin_access"] = False

            results.append(resource)

        return results

    # ── IAM Users (Password & MFA) ────────────────────────────────────────────

    def scan_iam_users(self) -> List[Dict[str, Any]]:
        """List IAM users with MFA and access key status."""
        iam = self._client("iam")
        results = []

        try:
            users = iam.list_users(MaxItems=100).get("Users", [])
        except (ClientError, BotoCoreError) as e:
            return [{"resource_type": "iam_user", "error": str(e)}]

        for user in users:
            name = user["UserName"]
            resource = {
                "resource_type": "aws_iam_user",
                "resource_id": self._hash_id(user["UserId"]),
                "resource_name": name,
                "config": {
                    "create_date": user.get("CreateDate", "").isoformat() if hasattr(user.get("CreateDate", ""), "isoformat") else "",
                    "has_mfa": False,
                    "access_keys": [],
                },
            }

            # MFA devices
            try:
                mfa = iam.list_mfa_devices(UserName=name)
                resource["config"]["has_mfa"] = len(mfa.get("MFADevices", [])) > 0
            except ClientError:
                pass

            # Access keys
            try:
                keys = iam.list_access_keys(UserName=name).get("AccessKeyMetadata", [])
                for k in keys:
                    age_days = 0
                    if hasattr(k.get("CreateDate", ""), "replace"):
                        age_days = (datetime.now(timezone.utc) - k["CreateDate"].replace(tzinfo=timezone.utc if k["CreateDate"].tzinfo is None else k["CreateDate"].tzinfo)).days
                    resource["config"]["access_keys"].append({
                        "status": k.get("Status", ""),
                        "age_days": age_days,
                        "is_old": age_days > 90,
                    })
            except ClientError:
                pass

            results.append(resource)

        return results

    # ── CloudTrail Events ─────────────────────────────────────────────────────

    def fetch_cloudtrail_events(self, max_events: int = 100) -> List[Dict[str, Any]]:
        """Fetch recent CloudTrail events for security analysis."""
        ct = self._client("cloudtrail")
        events = []

        try:
            response = ct.lookup_events(
                MaxResults=min(max_events, 50),
                StartTime=datetime.now(timezone.utc) - timedelta(hours=24),
                EndTime=datetime.now(timezone.utc),
            )

            for event in response.get("Events", []):
                sanitized = {
                    "event_id": event.get("EventId", "")[:12],
                    "event_name": event.get("EventName", ""),
                    "event_source": event.get("EventSource", ""),
                    "event_time": event.get("EventTime", "").isoformat() if hasattr(event.get("EventTime", ""), "isoformat") else str(event.get("EventTime", "")),
                    "username": event.get("Username", "unknown"),
                    "read_only": str(event.get("ReadOnly", "")),
                }

                # Parse CloudTrail event detail for security-relevant info
                try:
                    detail = json.loads(event.get("CloudTrailEvent", "{}"))
                    sanitized["source_ip"] = detail.get("sourceIPAddress", "")
                    sanitized["user_agent"] = detail.get("userAgent", "")[:50] if detail.get("userAgent") else ""
                    sanitized["error_code"] = detail.get("errorCode", "")
                    sanitized["error_message"] = detail.get("errorMessage", "")[:100] if detail.get("errorMessage") else ""

                    # Flag suspicious events
                    sanitized["is_suspicious"] = bool(
                        sanitized["error_code"] in ("AccessDenied", "UnauthorizedAccess", "Client.UnauthorizedAccess") or
                        "Delete" in sanitized["event_name"] or
                        "Detach" in sanitized["event_name"] or
                        "Disable" in sanitized["event_name"] or
                        "Remove" in sanitized["event_name"]
                    )
                except (json.JSONDecodeError, AttributeError):
                    sanitized["is_suspicious"] = False

                events.append(sanitized)

        except (ClientError, BotoCoreError) as e:
            return [{"error": str(e), "event_name": "CloudTrailFetchError"}]

        return events

    # ── Full Scan ─────────────────────────────────────────────────────────────

    def run_full_scan(self) -> Dict[str, Any]:
        """Run a complete scan of all supported AWS resource types."""
        results = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "region": self.region,
            "resources": [],
            "events": [],
            "summary": {
                "s3_buckets": 0,
                "security_groups": 0,
                "iam_policies": 0,
                "iam_users": 0,
                "cloudtrail_events": 0,
            },
        }

        # S3 Buckets
        s3_resources = self.scan_s3_buckets()
        results["resources"].extend(s3_resources)
        results["summary"]["s3_buckets"] = len([r for r in s3_resources if "error" not in r])

        # Security Groups
        sg_resources = self.scan_security_groups()
        results["resources"].extend(sg_resources)
        results["summary"]["security_groups"] = len([r for r in sg_resources if "error" not in r])

        # IAM Policies
        iam_resources = self.scan_iam_policies()
        results["resources"].extend(iam_resources)
        results["summary"]["iam_policies"] = len([r for r in iam_resources if "error" not in r])

        # IAM Users
        user_resources = self.scan_iam_users()
        results["resources"].extend(user_resources)
        results["summary"]["iam_users"] = len([r for r in user_resources if "error" not in r])

        # CloudTrail Events
        events = self.fetch_cloudtrail_events()
        results["events"] = events
        results["summary"]["cloudtrail_events"] = len([e for e in events if "error" not in e])

        return results

    # ── Privacy Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _mask_account_id(account_id: str) -> str:
        """Mask AWS account ID for display (show last 4 digits)."""
        if len(account_id) >= 4:
            return "****" + account_id[-4:]
        return "****"

    @staticmethod
    def _hash_id(raw_id: str) -> str:
        """Hash sensitive IDs to prevent leaking to the model."""
        if not raw_id:
            return ""
        return hashlib.sha256(raw_id.encode()).hexdigest()[:12]

    @staticmethod
    def _sanitize_resources(resources) -> Any:
        """Strip ARNs from resource fields, keep only the resource type/name."""
        if isinstance(resources, str):
            if resources == "*":
                return "*"
            # Strip ARN, keep last segment
            return resources.split(":")[-1] if ":" in resources else resources
        if isinstance(resources, list):
            return [AWSScanner._sanitize_resources(r) for r in resources]
        return resources
