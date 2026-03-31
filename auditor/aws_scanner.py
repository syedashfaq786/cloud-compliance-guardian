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

    def __init__(self, access_key=None, secret_key=None, region=None, session_token=None):
        self.access_key = access_key or os.getenv("AWS_ACCESS_KEY_ID")
        self.secret_key = secret_key or os.getenv("AWS_SECRET_ACCESS_KEY")
        self.session_token = session_token or os.getenv("AWS_SESSION_TOKEN")
        self.region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self._session = None
        self._clients = {} # Cache clients by (service, region)

    def _get_session(self) -> boto3.Session:
        """Create or return cached boto3 session."""
        if self._session is None:
            kwargs = {}
            if self.access_key and self.secret_key:
                kwargs["aws_access_key_id"] = self.access_key
                kwargs["aws_secret_access_key"] = self.secret_key
                if self.session_token:
                    kwargs["aws_session_token"] = self.session_token
            # If no keys, it will use environment or profile
            try:
                self._session = boto3.Session(**kwargs)
            except Exception:
                self._session = boto3.Session()
        return self._session

    def _client(self, service: str, region: Optional[str] = None):
        """Get a boto3 client for a service, optionally in a specific region."""
        region_name = region or self.region
        cache_key = (service, region_name)
        if cache_key not in self._clients:
            self._clients[cache_key] = self._get_session().client(service, region_name=region_name)
        return self._clients[cache_key]

    def get_available_regions(self) -> List[str]:
        """Fetch all available AWS regions for the current account."""
        # Use cached property if session is already initialized and we've fetched before
        if hasattr(self, "_cached_regions") and self._cached_regions:
            return self._cached_regions
            
        try:
            ec2 = self._client("ec2", region="us-east-1")
            regions = ec2.describe_regions()
            self._cached_regions = [r["RegionName"] for r in regions.get("Regions", [])]
            return self._cached_regions
        except Exception:
            # Persistent fallback list if API fails
            self._cached_regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-south-1", "ap-southeast-1", "eu-central-1"]
            return self._cached_regions

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
            code = e.response.get("Error", {}).get("Code", "")
            if code == "SignatureDoesNotMatch":
                return {"connected": False, "error": "Secret Access Key is incorrect. Please re-copy it from the AWS IAM console (watch for extra spaces)."}
            if code == "InvalidClientTokenId":
                return {"connected": False, "error": "Access Key ID is invalid or has been deactivated."}
            return {"connected": False, "error": str(e)}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    # ── S3 Buckets ────────────────────────────────────────────────────────────

    def scan_s3_buckets(self) -> List[Dict[str, Any]]:
        """List all S3 buckets with their security configurations and regions."""
        s3_global = self._client("s3")
        results = []

        try:
            buckets = s3_global.list_buckets().get("Buckets", [])
        except (ClientError, BotoCoreError) as e:
            return [{"resource_type": "aws_s3_bucket", "error": str(e), "region": "global"}]

        for bucket in buckets:
            name = bucket["Name"]
            
            # Determine bucket region for regional API calls
            try:
                location = s3_global.get_bucket_location(Bucket=name).get("LocationConstraint")
                # None or empty string means us-east-1
                region = location if location else "us-east-1"
                # Handle special case for EU (Ireland)
                if region == "EU": region = "eu-west-1"
            except ClientError:
                region = "us-east-1" # Fallback

            # Get regional resident client
            s3_regional = self._client("s3", region=region)
            
            resource = {
                "resource_type": "aws_s3_bucket",
                "resource_id": self._hash_id(f"s3:{name}"), # Stable ID
                "resource_name": name,
                "region": region,
                "created": bucket.get("CreationDate", "").isoformat() if hasattr(bucket.get("CreationDate", ""), "isoformat") else str(bucket.get("CreationDate", "")),
                "config": {},
            }

            # Encryption
            try:
                enc = s3_regional.get_bucket_encryption(Bucket=name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                resource["config"]["encryption"] = {
                    "enabled": True,
                    "algorithm": rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] if rules else "none",
                }
            except ClientError:
                resource["config"]["encryption"] = {"enabled": False, "algorithm": "none"}

            # Versioning
            try:
                ver = s3_regional.get_bucket_versioning(Bucket=name)
                resource["config"]["versioning"] = ver.get("Status", "Disabled")
            except ClientError:
                resource["config"]["versioning"] = "Unknown"

            # Public access block
            try:
                pub = s3_regional.get_public_access_block(Bucket=name)
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
                log = s3_regional.get_bucket_logging(Bucket=name)
                resource["config"]["logging"] = bool(log.get("LoggingEnabled"))
            except ClientError:
                resource["config"]["logging"] = False

            results.append(resource)

        return results

    # ── EC2 Security Groups ───────────────────────────────────────────────────

    def scan_security_groups(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all EC2 security groups with ingress/egress rules."""
        ec2 = self._client("ec2", region=region)
        results = []

        try:
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        except (ClientError, BotoCoreError) as e:
            return [{"resource_type": "security_group", "error": str(e), "region": region or self.region}]

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

    # ── EC2 Instances ─────────────────────────────────────────────────────────
    
    def scan_ec2_instances(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """List EC2 instances in a specific region."""
        ec2 = self._client("ec2", region)
        results = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        name = ""
                        for tag in instance.get("Tags", []):
                            if tag["Key"] == "Name":
                                name = tag["Value"]
                                break
                        
                        results.append({
                            "resource_type": "aws_ec2_instance",
                            "resource_id": self._hash_id(instance["InstanceId"]),
                            "resource_name": name or instance["InstanceId"],
                            "region": region or self.region,
                            "config": {
                                "instance_id": instance["InstanceId"], # Include original ID in config
                                "instance_type": instance["InstanceType"],
                                "state": instance["State"]["Name"],
                                "vpc_id": instance.get("VpcId", ""),
                                "iam_instance_profile": instance.get("IamInstanceProfile", {}).get("Arn", ""),
                                "public_ip": instance.get("PublicIpAddress", ""),
                                "private_ip": instance.get("PrivateIpAddress", ""),
                                "security_groups": [sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
                            }
                        })
        except Exception as e:
            return [{"error": str(e), "resource_type": "aws_ec2_instance"}]
        return results

    # ── VPCs ──────────────────────────────────────────────────────────────────
    
    def scan_vpcs(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """List VPCs in a specific region."""
        ec2 = self._client("ec2", region)
        results = []
        try:
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            for vpc in vpcs:
                name = ""
                for tag in vpc.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                        break
                
                results.append({
                    "resource_type": "aws_vpc",
                    "resource_id": self._hash_id(vpc["VpcId"]),
                    "resource_name": name or vpc["VpcId"],
                    "region": region or self.region,
                    "config": {
                        "cidr_block": vpc["CidrBlock"],
                        "is_default": vpc.get("IsDefault", False),
                        "state": vpc["State"],
                    }
                })
        except Exception as e:
            return [{"error": str(e), "resource_type": "aws_vpc"}]
        return results

    # ── RDS Instances ─────────────────────────────────────────────────────────
    
    def scan_rds_instances(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """List RDS instances in a specific region."""
        rds = self._client("rds", region)
        results = []
        try:
            instances = rds.describe_db_instances().get("DBInstances", [])
            for db in instances:
                results.append({
                    "resource_type": "aws_rds_instance",
                    "resource_id": self._hash_id(db["DBInstanceIdentifier"]),
                    "resource_name": db["DBInstanceIdentifier"],
                    "region": region or self.region,
                    "config": {
                        "engine": db["Engine"],
                        "publicly_accessible": db.get("PubliclyAccessible", False),
                        "storage_encrypted": db.get("StorageEncrypted", False),
                        "multi_az": db.get("MultiAZ", False),
                        "backup_retention": db.get("BackupRetentionPeriod", 0),
                    }
                })
        except Exception as e:
            return [{"error": str(e), "resource_type": "aws_rds_instance"}]
        return results

    # ── Lambda Functions ──────────────────────────────────────────────────────
    
    def scan_lambda_functions(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """List Lambda functions in a specific region."""
        lam = self._client("lambda", region)
        results = []
        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for func in page.get("Functions", []):
                    results.append({
                        "resource_type": "aws_lambda_function",
                        "resource_id": self._hash_id(func["FunctionName"]),
                        "resource_name": func["FunctionName"],
                        "region": region or self.region,
                        "config": {
                            "runtime": func.get("Runtime", ""),
                            "handler": func.get("Handler", ""),
                            "role": func.get("Role", ""),
                            "last_modified": func.get("LastModified", ""),
                        }
                    })
        except Exception as e:
            return [{"error": str(e), "resource_type": "aws_lambda_function"}]
        return results

    def scan_iam_policies(self) -> List[Dict[str, Any]]:
        """List customer-managed IAM policies with their permissions."""
        iam = self._client("iam")
        results = []

        try:
            policies = iam.list_policies(Scope="Local", MaxItems=50).get("Policies", [])
        except (ClientError, BotoCoreError) as e:
            return [{"resource_type": "iam_policy", "error": str(e), "region": "global"}]

        for pol in policies:
            resource = {
                "resource_type": "aws_iam_policy",
                "resource_id": self._hash_id(pol["PolicyId"]),
                "resource_name": pol["PolicyName"],
                "region": "global",
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
                "region": "global",
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

    def fetch_cloudtrail_events(self, max_events: int = 100, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch recent CloudTrail events for security analysis."""
        ct = self._client("cloudtrail", region=region)
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

    # ── Full Inventory Discovery ──────────────────────────────────────────────

    def scan_all_resources(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Discover ALL resources in a region using Resource Groups Tagging API.
        This captures resources not covered by specific scanners.
        """
        tagging = self._client("resourcegroupstaggingapi", region=region)
        results = []
        
        try:
            paginator = tagging.get_paginator("get_resources")
            for page in paginator.paginate():
                for res in page.get("ResourceTagMappingList", []):
                    arn = res.get("ResourceARN", "")
                    # Extract service and type from ARN
                    # arn:aws:service:region:account:type/id
                    parts = arn.split(":")
                    if len(parts) > 5:
                        service = parts[2]
                        resource_part = parts[5]
                        res_type = f"aws_{service}_{resource_part.split('/')[0]}"
                    else:
                        res_type = "aws_unknown_resource"

                    results.append({
                        "resource_type": res_type,
                        "resource_id": self._hash_id(arn),
                        "resource_name": arn.split("/")[-1] if "/" in arn else arn.split(":")[-1],
                        "region": region or self.region,
                        "config": {
                            "arn": arn,
                            "tags": {t["Key"]: t["Value"] for t in res.get("Tags", [])}
                        }
                    })
        except Exception as e:
            return [{"resource_type": "aws_inventory", "error": str(e), "region": region or self.region}]
            
        return results

    # ── Full Scan ─────────────────────────────────────────────────────────────

    def run_full_scan(self, regions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run a complete scan of all supported AWS resource types across multiple regions."""
        if regions == ["all"] or not regions:
            scan_regions = self.get_available_regions()
        else:
            scan_regions = regions or [self.region]

        results = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "regions_scanned": scan_regions,
            "primary_region": self.region,
            "resources": [],
            "events": [],
            "summary": {
                "s3_buckets": 0,
                "security_groups": 0,
                "ec2_instances": 0,
                "vpcs": 0,
                "rds_instances": 0,
                "lambda_functions": 0,
                "iam_policies": 0,
                "iam_users": 0,
                "cloudtrail_events": 0,
                "regions_count": len(scan_regions),
            },
        }

        # 1. Global Services (Scan Once)
        # S3 Buckets
        s3_resources = self.scan_s3_buckets()
        results["resources"].extend(s3_resources)
        results["summary"]["s3_buckets"] = len([r for r in s3_resources if "error" not in r])

        # IAM Policies
        iam_resources = self.scan_iam_policies()
        results["resources"].extend(iam_resources)
        results["summary"]["iam_policies"] = len([r for r in iam_resources if "error" not in r])

        # IAM Users
        user_resources = self.scan_iam_users()
        results["resources"].extend(user_resources)
        results["summary"]["iam_users"] = len([r for r in user_resources if "error" not in r])

        # 2. Regional Services (Loop through regions)
        for reg in scan_regions:
            # Full Inventory Discovery (Captured first to avoid missing "unsupported" types)
            inventory = self.scan_all_resources(region=reg)
            results["resources"].extend(inventory)
            
            # Specific Scanners (Provide more detail for key types)
            instances = self.scan_ec2_instances(region=reg)
            results["resources"].extend(instances)
            results["summary"]["ec2_instances"] += len([r for r in instances if "error" not in r])

            vpcs = self.scan_vpcs(region=reg)
            results["resources"].extend(vpcs)
            results["summary"]["vpcs"] += len([r for r in vpcs if "error" not in r])

            sg_resources = self.scan_security_groups(region=reg)
            for r in sg_resources:
                if "error" not in r:
                    r["region"] = reg
            results["resources"].extend(sg_resources)
            results["summary"]["security_groups"] += len([r for r in sg_resources if "error" not in r])

            rds = self.scan_rds_instances(region=reg)
            results["resources"].extend(rds)
            results["summary"]["rds_instances"] += len([r for r in rds if "error" not in r])

            lambdas = self.scan_lambda_functions(region=reg)
            results["resources"].extend(lambdas)
            results["summary"]["lambda_functions"] += len([r for r in lambdas if "error" not in r])

            # CloudTrail Events
            events = self.fetch_cloudtrail_events(region=reg)
            for e in events:
                if "error" not in e:
                    e["region"] = reg
            results["events"].extend(events)
            results["summary"]["cloudtrail_events"] += len([e for e in events if "error" not in e])

        # 3. Deduping and Cleanup
        # Remove duplicates based on resource_id (keeping the richest metadata version)
        unique_resources = {}
        for res in results["resources"]:
            rid = res.get("resource_id")
            if not rid: continue
            
            # If we already have it, check if the new one has more "config" depth
            if rid in unique_resources:
                if len(json.dumps(res.get("config", {}))) > len(json.dumps(unique_resources[rid].get("config", {}))):
                    unique_resources[rid] = res
            else:
                unique_resources[rid] = res
        
        results["resources"] = list(unique_resources.values())
        # Sort by resource_id to ensure order consistency
        results["resources"].sort(key=lambda x: x.get("resource_id", ""))
        results["summary"]["total_resources"] = len(results["resources"])
        results["summary"]["total_resources"] = len(results["resources"])

        return results

    # ── Privacy Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _mask_account_id(account_id: str) -> str:
        """Mask AWS account ID for display (show last 4 digits)."""
        if len(account_id) >= 4:
            return "****" + account_id[-4:]
        return "****"

    def get_organization_accounts(self) -> List[Dict]:
        """Fetch list of all accounts in the AWS Organization."""
        try:
            client = self._client("organizations")
            accounts = []
            paginator = client.get_paginator("list_accounts")
            for page in paginator.paginate():
                for account in page["Accounts"]:
                    accounts.append({
                        "id": account["Id"],
                        "name": account["Name"],
                        "email": account["Email"],
                        "status": account["Status"],
                        "arn": account["Arn"]
                    })
            return accounts
        except Exception as e:
            # If not an organization master account, this will fail
            return [{"id": "current", "name": "Current Account", "error": str(e)}]

    def assume_role_scanner(self, account_id: str, role_name: str = "GuardianScannerRole") -> 'AWSScanner':
        """Assume a role in a child account and return a new scanner for that account."""
        try:
            sts = self._client("sts")
            role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="GuardianDiscoverySession"
            )
            creds = response["Credentials"]
            return AWSScanner(
                access_key=creds["AccessKeyId"],
                secret_key=creds["SecretAccessKey"],
                session_token=creds["SessionToken"],
                region=self.region
            )
        except Exception as e:
            print(f"Error assuming role in {account_id}: {e}")
            return None

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
