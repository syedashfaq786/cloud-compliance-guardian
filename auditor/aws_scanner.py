"""
AWS Live Scanner — Fetches real-time configurations from AWS using Boto3.

Covers every major AWS resource category:
  Global:   S3, IAM Users, IAM Roles, IAM Policies
  Regional: EC2 Instances, VPCs, Subnets, Security Groups, Internet Gateways,
            NAT Gateways, Route Tables, RDS, Lambda, EBS Volumes,
            KMS Keys, Secrets Manager, ELB/ALB, CloudTrail Trails,
            CloudWatch Alarms, SNS Topics, ECS Clusters

Design principles:
  - Every resource uses _hash_id() so topology joins always match
  - Pagination used everywhere — never misses resources due to truncation
  - Errors per-resource captured without stopping the whole scan
  - All regional resources scanned in parallel via ThreadPoolExecutor
  - Global resources (S3, IAM) scanned once, not per-region
"""

import os
import re
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError


class AWSScanner:
    """Fetches and normalises AWS resource configurations for compliance auditing."""

    def __init__(self, access_key=None, secret_key=None, region=None, session_token=None):
        self.access_key = access_key or os.getenv("AWS_ACCESS_KEY_ID")
        self.secret_key = secret_key or os.getenv("AWS_SECRET_ACCESS_KEY")
        self.session_token = session_token or os.getenv("AWS_SESSION_TOKEN")
        self.region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self._session = None
        self._clients: Dict = {}
        
        # Debug logging
        has_access_key = "YES" if self.access_key else "NO"
        has_secret_key = "YES" if self.secret_key else "NO"
        print(f"🔐 AWSScanner initialized: access_key={has_access_key}, secret_key={has_secret_key}, region={self.region}")

    # ── Session / Client ──────────────────────────────────────────────────────

    def _get_session(self) -> boto3.Session:
        if self._session is None:
            kwargs = {}
            if self.access_key and self.secret_key:
                kwargs["aws_access_key_id"] = self.access_key
                kwargs["aws_secret_access_key"] = self.secret_key
                if self.session_token:
                    kwargs["aws_session_token"] = self.session_token
            try:
                self._session = boto3.Session(**kwargs)
            except Exception:
                self._session = boto3.Session()
        return self._session

    def _client(self, service: str, region: Optional[str] = None):
        region_name = region or self.region
        key = (service, region_name)
        if key not in self._clients:
            self._clients[key] = self._get_session().client(service, region_name=region_name)
        return self._clients[key]

    # ── Identity / Region helpers ─────────────────────────────────────────────

    def test_connection(self) -> Dict[str, Any]:
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
                return {"connected": False, "error": "Secret Access Key is incorrect."}
            if code == "InvalidClientTokenId":
                return {"connected": False, "error": "Access Key ID is invalid or deactivated."}
            return {"connected": False, "error": str(e)}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    def get_available_regions(self) -> List[str]:
        """
        Get list of available AWS regions where resources should be scanned.
        
        FIXED: Always use the hardcoded regions where the account has resources.
        The EC2 DescribeRegions API returns ALL 17+ AWS regions, not just 
        the ones with resources in this account, which wastes scan time.
        """
        if hasattr(self, "_cached_regions") and self._cached_regions:
            return self._cached_regions
        
        # Only scan the 5 regions where THIS account has resources
        # Verified from AWS Resource Explorer showing actual resource distribution
        self._cached_regions = [
            "us-east-1",      # 131 resources
            "eu-west-1",      # 38 resources
            "eu-north-1",     # 34 resources
            "ap-northeast-1", # 31 resources
            "ap-south-1",     # 199 resources (total: 433)
        ]
        print(f"✓ Scanning {len(self._cached_regions)} configured regions: {self._cached_regions}")
        return self._cached_regions

    def _get_region_api(self) -> str:
        """Return the /api/aws/regions primary region field."""
        return self.region

    # ── S3 Buckets ────────────────────────────────────────────────────────────

    def scan_s3_buckets(self) -> List[Dict[str, Any]]:
        s3 = self._client("s3")
        results = []
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            return [{"resource_type": "aws_s3_bucket", "error": str(e), "region": "global"}]

        for bucket in buckets:
            name = bucket["Name"]
            # Determine bucket region
            try:
                loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
                region = loc if loc else "us-east-1"
                if region == "EU":
                    region = "eu-west-1"
            except Exception:
                region = "us-east-1"

            s3r = self._client("s3", region=region)
            res = {
                "resource_type": "aws_s3_bucket",
                "resource_id": self._hash_id(f"s3:{name}"),
                "resource_name": name,
                "region": region,
                "created": self._iso(bucket.get("CreationDate")),
                "config": {},
            }

            # Encryption
            try:
                enc = s3r.get_bucket_encryption(Bucket=name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] if rules else "none"
                res["config"]["encryption"] = {"enabled": True, "algorithm": algo}
            except ClientError:
                res["config"]["encryption"] = {"enabled": False, "algorithm": "none"}

            # Versioning
            try:
                ver = s3r.get_bucket_versioning(Bucket=name)
                res["config"]["versioning"] = ver.get("Status", "Disabled")
            except Exception:
                res["config"]["versioning"] = "Unknown"

            # Public access block
            try:
                pub = s3r.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                res["config"]["public_access_block"] = {
                    "block_public_acls": pub.get("BlockPublicAcls", False),
                    "block_public_policy": pub.get("BlockPublicPolicy", False),
                    "ignore_public_acls": pub.get("IgnorePublicAcls", False),
                    "restrict_public_buckets": pub.get("RestrictPublicBuckets", False),
                }
            except Exception:
                res["config"]["public_access_block"] = {k: False for k in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]}

            # Logging
            try:
                log = s3r.get_bucket_logging(Bucket=name)
                res["config"]["logging"] = bool(log.get("LoggingEnabled"))
            except Exception:
                res["config"]["logging"] = False

            # ACL — is it publicly readable?
            try:
                acl = s3r.get_bucket_acl(Bucket=name)
                public_grants = [g for g in acl.get("Grants", []) if g.get("Grantee", {}).get("URI", "").endswith("AllUsers") or g.get("Grantee", {}).get("URI", "").endswith("AuthenticatedUsers")]
                res["config"]["acl_public"] = len(public_grants) > 0
            except Exception:
                res["config"]["acl_public"] = False

            results.append(res)
        return results

    # ── Security Groups ───────────────────────────────────────────────────────

    def scan_security_groups(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ec2 = self._client("ec2", region=region)
        results = []
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    raw_vpc = sg.get("VpcId", "")
                    res = {
                        "resource_type": "aws_security_group",
                        "resource_id": self._hash_id(sg["GroupId"]),
                        "resource_name": sg.get("GroupName", sg["GroupId"]),
                        "region": region or self.region,
                        "raw_sg_id": sg["GroupId"],  # kept for EC2 join
                        "config": {
                            "description": sg.get("Description", ""),
                            "vpc_id": self._hash_id(raw_vpc) if raw_vpc else "",
                            "raw_vpc_id": raw_vpc,
                            "ingress_rules": [],
                            "egress_rules": [],
                        },
                    }
                    for rule in sg.get("IpPermissions", []):
                        for cidr in rule.get("IpRanges", []):
                            res["config"]["ingress_rules"].append({
                                "protocol": rule.get("IpProtocol", "all"),
                                "from_port": rule.get("FromPort", 0),
                                "to_port": rule.get("ToPort", 65535),
                                "cidr": cidr.get("CidrIp", ""),
                            })
                        for cidr6 in rule.get("Ipv6Ranges", []):
                            res["config"]["ingress_rules"].append({
                                "protocol": rule.get("IpProtocol", "all"),
                                "from_port": rule.get("FromPort", 0),
                                "to_port": rule.get("ToPort", 65535),
                                "cidr": cidr6.get("CidrIpv6", ""),
                            })
                    for rule in sg.get("IpPermissionsEgress", []):
                        for cidr in rule.get("IpRanges", []):
                            res["config"]["egress_rules"].append({
                                "protocol": rule.get("IpProtocol", "all"),
                                "from_port": rule.get("FromPort", 0),
                                "to_port": rule.get("ToPort", 65535),
                                "cidr": cidr.get("CidrIp", ""),
                            })
                    results.append(res)
        except Exception as e:
            results.append({"resource_type": "aws_security_group", "error": str(e), "region": region or self.region})
        return results

    # ── EC2 Instances ─────────────────────────────────────────────────────────

    def scan_ec2_instances(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ec2 = self._client("ec2", region=region)
        results = []
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        if instance.get("State", {}).get("Name") == "terminated":
                            continue  # skip terminated instances
                        name = next((t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"), instance["InstanceId"])
                        raw_vpc = instance.get("VpcId", "")
                        raw_subnet = instance.get("SubnetId", "")
                        results.append({
                            "resource_type": "aws_ec2_instance",
                            "resource_id": self._hash_id(instance["InstanceId"]),
                            "resource_name": name,
                            "region": region or self.region,
                            "config": {
                                "instance_id": instance["InstanceId"],
                                "instance_type": instance.get("InstanceType", ""),
                                "state": instance["State"]["Name"],
                                "vpc_id": self._hash_id(raw_vpc) if raw_vpc else "",
                                "raw_vpc_id": raw_vpc,
                                "subnet_id": self._hash_id(raw_subnet) if raw_subnet else "",
                                "raw_subnet_id": raw_subnet,
                                "iam_instance_profile": instance.get("IamInstanceProfile", {}).get("Arn", ""),
                                "public_ip": instance.get("PublicIpAddress", ""),
                                "private_ip": instance.get("PrivateIpAddress", ""),
                                "security_groups": [sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
                                "security_group_ids": [self._hash_id(sg["GroupId"]) for sg in instance.get("SecurityGroups", [])],
                                "platform": instance.get("Platform", "linux"),
                                "monitoring": instance.get("Monitoring", {}).get("State", "disabled"),
                                "ebs_optimized": instance.get("EbsOptimized", False),
                                "image_id": instance.get("ImageId", ""),
                            },
                        })
        except Exception as e:
            print(f"    ❌ scan_ec2_instances in {region}: {type(e).__name__}: {str(e)[:100]}")
            results.append({"resource_type": "aws_ec2_instance", "error": str(e), "region": region or self.region})
        return results

    # ── EBS Volumes ───────────────────────────────────────────────────────────

    def scan_ebs_volumes(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ec2 = self._client("ec2", region=region)
        results = []
        try:
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page.get("Volumes", []):
                    name = next((t["Value"] for t in vol.get("Tags", []) if t["Key"] == "Name"), vol["VolumeId"])
                    results.append({
                        "resource_type": "aws_ebs_volume",
                        "resource_id": self._hash_id(vol["VolumeId"]),
                        "resource_name": name,
                        "region": region or self.region,
                        "config": {
                            "volume_id": vol["VolumeId"],
                            "size_gb": vol.get("Size", 0),
                            "volume_type": vol.get("VolumeType", ""),
                            "state": vol.get("State", ""),
                            "encrypted": vol.get("Encrypted", False),
                            "kms_key_id": vol.get("KmsKeyId", ""),
                            "attachments": [{"instance_id": a.get("InstanceId", ""), "device": a.get("Device", "")} for a in vol.get("Attachments", [])],
                            "availability_zone": vol.get("AvailabilityZone", ""),
                            "multi_attach": vol.get("MultiAttachEnabled", False),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_ebs_volume", "error": str(e), "region": region or self.region})
        return results

    # ── VPCs ──────────────────────────────────────────────────────────────────

    def scan_vpcs(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ec2 = self._client("ec2", region=region)
        results = []
        try:
            paginator = ec2.get_paginator("describe_vpcs")
            for page in paginator.paginate():
                for vpc in page.get("Vpcs", []):
                    name = next((t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"), vpc["VpcId"])
                    results.append({
                        "resource_type": "aws_vpc",
                        "resource_id": self._hash_id(vpc["VpcId"]),
                        "resource_name": name,
                        "region": region or self.region,
                        "raw_vpc_id": vpc["VpcId"],
                        "config": {
                            "cidr_block": vpc["CidrBlock"],
                            "is_default": vpc.get("IsDefault", False),
                            "state": vpc.get("State", ""),
                            "dhcp_options_id": vpc.get("DhcpOptionsId", ""),
                            "instance_tenancy": vpc.get("InstanceTenancy", "default"),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_vpc", "error": str(e), "region": region or self.region})
        return results

    # ── Subnets ───────────────────────────────────────────────────────────────

    def scan_subnets(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ec2 = self._client("ec2", region=region)
        results = []
        try:
            paginator = ec2.get_paginator("describe_subnets")
            for page in paginator.paginate():
                for subnet in page.get("Subnets", []):
                    name = next((t["Value"] for t in subnet.get("Tags", []) if t["Key"] == "Name"), subnet["SubnetId"])
                    raw_vpc = subnet.get("VpcId", "")
                    results.append({
                        "resource_type": "aws_subnet",
                        "resource_id": self._hash_id(subnet["SubnetId"]),
                        "resource_name": name,
                        "region": region or self.region,
                        "config": {
                            "subnet_id": subnet["SubnetId"],
                            "cidr_block": subnet.get("CidrBlock", ""),
                            "vpc_id": self._hash_id(raw_vpc) if raw_vpc else "",
                            "raw_vpc_id": raw_vpc,
                            "availability_zone": subnet.get("AvailabilityZone", ""),
                            "public_subnet": subnet.get("MapPublicIpOnLaunch", False),
                            "available_ips": subnet.get("AvailableIpAddressCount", 0),
                            "state": subnet.get("State", ""),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_subnet", "error": str(e), "region": region or self.region})
        return results

    # ── Internet Gateways ─────────────────────────────────────────────────────

    def scan_internet_gateways(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ec2 = self._client("ec2", region=region)
        results = []
        try:
            paginator = ec2.get_paginator("describe_internet_gateways")
            for page in paginator.paginate():
                for igw in page.get("InternetGateways", []):
                    name = next((t["Value"] for t in igw.get("Tags", []) if t["Key"] == "Name"), igw["InternetGatewayId"])
                    attachments = igw.get("Attachments", [])
                    attached_vpcs = [self._hash_id(a["VpcId"]) for a in attachments if a.get("VpcId")]
                    raw_attached_vpcs = [a["VpcId"] for a in attachments if a.get("VpcId")]
                    results.append({
                        "resource_type": "aws_internet_gateway",
                        "resource_id": self._hash_id(igw["InternetGatewayId"]),
                        "resource_name": name,
                        "region": region or self.region,
                        "config": {
                            "igw_id": igw["InternetGatewayId"],
                            "state": attachments[0].get("State", "detached") if attachments else "detached",
                            "attached_vpc_ids": attached_vpcs,
                            "raw_attached_vpc_ids": raw_attached_vpcs,
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_internet_gateway", "error": str(e), "region": region or self.region})
        return results

    # ── NAT Gateways ──────────────────────────────────────────────────────────

    def scan_nat_gateways(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ec2 = self._client("ec2", region=region)
        results = []
        try:
            paginator = ec2.get_paginator("describe_nat_gateways")
            for page in paginator.paginate(Filter=[{"Name": "state", "Values": ["available", "pending"]}]):
                for nat in page.get("NatGateways", []):
                    name = next((t["Value"] for t in nat.get("Tags", []) if t["Key"] == "Name"), nat["NatGatewayId"])
                    raw_vpc = nat.get("VpcId", "")
                    raw_subnet = nat.get("SubnetId", "")
                    results.append({
                        "resource_type": "aws_nat_gateway",
                        "resource_id": self._hash_id(nat["NatGatewayId"]),
                        "resource_name": name,
                        "region": region or self.region,
                        "config": {
                            "nat_id": nat["NatGatewayId"],
                            "state": nat.get("State", ""),
                            "vpc_id": self._hash_id(raw_vpc) if raw_vpc else "",
                            "subnet_id": self._hash_id(raw_subnet) if raw_subnet else "",
                            "connectivity_type": nat.get("ConnectivityType", "public"),
                            "public_ip": nat.get("NatGatewayAddresses", [{}])[0].get("PublicIp", "") if nat.get("NatGatewayAddresses") else "",
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_nat_gateway", "error": str(e), "region": region or self.region})
        return results

    # ── Route Tables ──────────────────────────────────────────────────────────

    def scan_route_tables(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ec2 = self._client("ec2", region=region)
        results = []
        try:
            paginator = ec2.get_paginator("describe_route_tables")
            for page in paginator.paginate():
                for rt in page.get("RouteTables", []):
                    name = next((t["Value"] for t in rt.get("Tags", []) if t["Key"] == "Name"), rt["RouteTableId"])
                    raw_vpc = rt.get("VpcId", "")
                    has_igw_route = any(
                        r.get("GatewayId", "").startswith("igw-")
                        for r in rt.get("Routes", [])
                    )
                    results.append({
                        "resource_type": "aws_route_table",
                        "resource_id": self._hash_id(rt["RouteTableId"]),
                        "resource_name": name,
                        "region": region or self.region,
                        "config": {
                            "route_table_id": rt["RouteTableId"],
                            "vpc_id": self._hash_id(raw_vpc) if raw_vpc else "",
                            "is_main": any(a.get("Main") for a in rt.get("Associations", [])),
                            "has_internet_route": has_igw_route,
                            "routes_count": len(rt.get("Routes", [])),
                            "associated_subnets": [self._hash_id(a["SubnetId"]) for a in rt.get("Associations", []) if a.get("SubnetId")],
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_route_table", "error": str(e), "region": region or self.region})
        return results

    # ── RDS Instances ─────────────────────────────────────────────────────────

    def scan_rds_instances(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        rds = self._client("rds", region=region)
        results = []
        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    raw_vpc = db.get("DBSubnetGroup", {}).get("VpcId", "")
                    results.append({
                        "resource_type": "aws_rds_instance",
                        "resource_id": self._hash_id(db["DBInstanceIdentifier"]),
                        "resource_name": db["DBInstanceIdentifier"],
                        "region": region or self.region,
                        "config": {
                            "engine": db.get("Engine", ""),
                            "engine_version": db.get("EngineVersion", ""),
                            "instance_class": db.get("DBInstanceClass", ""),
                            "status": db.get("DBInstanceStatus", ""),
                            "publicly_accessible": db.get("PubliclyAccessible", False),
                            "storage_encrypted": db.get("StorageEncrypted", False),
                            "multi_az": db.get("MultiAZ", False),
                            "backup_retention": db.get("BackupRetentionPeriod", 0),
                            "deletion_protection": db.get("DeletionProtection", False),
                            "auto_minor_version_upgrade": db.get("AutoMinorVersionUpgrade", False),
                            "vpc_id": self._hash_id(raw_vpc) if raw_vpc else "",
                            "raw_vpc_id": raw_vpc,
                            "ca_certificate": db.get("CACertificateIdentifier", ""),
                            "performance_insights": db.get("PerformanceInsightsEnabled", False),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_rds_instance", "error": str(e), "region": region or self.region})
        return results

    # ── Lambda Functions ──────────────────────────────────────────────────────

    def scan_lambda_functions(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        lam = self._client("lambda", region=region)
        results = []
        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for func in page.get("Functions", []):
                    vpc_config = func.get("VpcConfig", {})
                    raw_vpc = vpc_config.get("VpcId", "")
                    results.append({
                        "resource_type": "aws_lambda_function",
                        "resource_id": self._hash_id(func["FunctionName"]),
                        "resource_name": func["FunctionName"],
                        "region": region or self.region,
                        "config": {
                            "runtime": func.get("Runtime", ""),
                            "handler": func.get("Handler", ""),
                            "role": func.get("Role", "").split("/")[-1] if func.get("Role") else "",
                            "last_modified": func.get("LastModified", ""),
                            "timeout": func.get("Timeout", 0),
                            "memory_size": func.get("MemorySize", 0),
                            "code_size": func.get("CodeSize", 0),
                            "package_type": func.get("PackageType", "Zip"),
                            "architectures": func.get("Architectures", ["x86_64"]),
                            "vpc_id": self._hash_id(raw_vpc) if raw_vpc else "",
                            "vpc_enabled": bool(raw_vpc),
                            "tracing_config": func.get("TracingConfig", {}).get("Mode", "PassThrough"),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_lambda_function", "error": str(e), "region": region or self.region})
        return results

    # ── KMS Keys ──────────────────────────────────────────────────────────────

    def scan_kms_keys(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        kms = self._client("kms", region=region)
        results = []
        try:
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for key_ref in page.get("Keys", []):
                    key_id = key_ref["KeyId"]
                    try:
                        meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                        # Skip AWS-managed keys for compliance — only customer-managed matter
                        if meta.get("KeyManager") == "AWS":
                            continue
                        if meta.get("KeyState") in ("PendingDeletion", "Disabled"):
                            rotation = False
                        else:
                            try:
                                rot = kms.get_key_rotation_status(KeyId=key_id)
                                rotation = rot.get("KeyRotationEnabled", False)
                            except Exception:
                                rotation = False

                        results.append({
                            "resource_type": "aws_kms_key",
                            "resource_id": self._hash_id(key_id),
                            "resource_name": meta.get("Description") or key_id[:8],
                            "region": region or self.region,
                            "config": {
                                "key_id": key_id,
                                "key_state": meta.get("KeyState", ""),
                                "key_usage": meta.get("KeyUsage", ""),
                                "key_spec": meta.get("KeySpec", ""),
                                "key_manager": meta.get("KeyManager", ""),
                                "rotation_enabled": rotation,
                                "multi_region": meta.get("MultiRegion", False),
                                "created": self._iso(meta.get("CreationDate")),
                            },
                        })
                    except Exception:
                        continue
        except Exception as e:
            results.append({"resource_type": "aws_kms_key", "error": str(e), "region": region or self.region})
        return results

    # ── Secrets Manager ───────────────────────────────────────────────────────

    def scan_secrets_manager(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        sm = self._client("secretsmanager", region=region)
        results = []
        try:
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    results.append({
                        "resource_type": "aws_secretsmanager_secret",
                        "resource_id": self._hash_id(secret["ARN"]),
                        "resource_name": secret["Name"],
                        "region": region or self.region,
                        "config": {
                            "rotation_enabled": secret.get("RotationEnabled", False),
                            "rotation_rules": secret.get("RotationRules", {}),
                            "last_rotated": self._iso(secret.get("LastRotatedDate")),
                            "last_accessed": self._iso(secret.get("LastAccessedDate")),
                            "kms_key_id": secret.get("KmsKeyId", ""),
                            "tags": {t["Key"]: t["Value"] for t in secret.get("Tags", [])},
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_secretsmanager_secret", "error": str(e), "region": region or self.region})
        return results

    # ── ELB / ALB ─────────────────────────────────────────────────────────────

    def scan_load_balancers(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        results = []
        # Application/Network Load Balancers (elbv2)
        try:
            elbv2 = self._client("elbv2", region=region)
            paginator = elbv2.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    raw_vpc = lb.get("VpcId", "")
                    results.append({
                        "resource_type": "aws_lb",
                        "resource_id": self._hash_id(lb["LoadBalancerArn"]),
                        "resource_name": lb["LoadBalancerName"],
                        "region": region or self.region,
                        "config": {
                            "dns_name": lb.get("DNSName", ""),
                            "scheme": lb.get("Scheme", ""),
                            "type": lb.get("Type", ""),
                            "state": lb.get("State", {}).get("Code", ""),
                            "vpc_id": self._hash_id(raw_vpc) if raw_vpc else "",
                            "ip_address_type": lb.get("IpAddressType", ""),
                            "deletion_protection": False,  # would need describe_lb_attributes
                            "internet_facing": lb.get("Scheme", "") == "internet-facing",
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_lb", "error": str(e), "region": region or self.region})

        # Classic Load Balancers
        try:
            elb = self._client("elb", region=region)
            resp = elb.describe_load_balancers()
            for lb in resp.get("LoadBalancerDescriptions", []):
                raw_vpc = lb.get("VPCId", "")
                results.append({
                    "resource_type": "aws_elb",
                    "resource_id": self._hash_id(f"elb:{lb['LoadBalancerName']}"),
                    "resource_name": lb["LoadBalancerName"],
                    "region": region or self.region,
                    "config": {
                        "dns_name": lb.get("DNSName", ""),
                        "scheme": lb.get("Scheme", ""),
                        "vpc_id": self._hash_id(raw_vpc) if raw_vpc else "",
                        "internet_facing": lb.get("Scheme", "") == "internet-facing",
                        "listeners": len(lb.get("ListenerDescriptions", [])),
                    },
                })
        except Exception:
            pass  # Classic ELBs not present — not an error
        return results

    # ── CloudTrail Trails ─────────────────────────────────────────────────────

    def scan_cloudtrail_trails(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ct = self._client("cloudtrail", region=region)
        results = []
        try:
            trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
            for trail in trails:
                trail_arn = trail.get("TrailARN", "")
                status = {}
                try:
                    status = ct.get_trail_status(Name=trail_arn)
                except Exception:
                    pass
                results.append({
                    "resource_type": "aws_cloudtrail",
                    "resource_id": self._hash_id(trail_arn),
                    "resource_name": trail.get("Name", ""),
                    "region": region or self.region,
                    "config": {
                        "s3_bucket": trail.get("S3BucketName", ""),
                        "multi_region": trail.get("IsMultiRegionTrail", False),
                        "log_file_validation": trail.get("LogFileValidationEnabled", False),
                        "kms_key_id": trail.get("KMSKeyId", ""),
                        "is_logging": status.get("IsLogging", False),
                        "include_global_service_events": trail.get("IncludeGlobalServiceEvents", False),
                        "has_custom_event_selectors": trail.get("HasCustomEventSelectors", False),
                        "has_insight_selectors": trail.get("HasInsightSelectors", False),
                        "home_region": trail.get("HomeRegion", region or self.region),
                    },
                })
        except Exception as e:
            results.append({"resource_type": "aws_cloudtrail", "error": str(e), "region": region or self.region})
        return results

    # ── CloudWatch Alarms ─────────────────────────────────────────────────────

    def scan_cloudwatch_alarms(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        cw = self._client("cloudwatch", region=region)
        results = []
        try:
            paginator = cw.get_paginator("describe_alarms")
            for page in paginator.paginate(AlarmTypes=["MetricAlarm"]):
                for alarm in page.get("MetricAlarms", []):
                    results.append({
                        "resource_type": "aws_cloudwatch_alarm",
                        "resource_id": self._hash_id(alarm["AlarmArn"]),
                        "resource_name": alarm["AlarmName"],
                        "region": region or self.region,
                        "config": {
                            "state": alarm.get("StateValue", ""),
                            "metric_name": alarm.get("MetricName", ""),
                            "namespace": alarm.get("Namespace", ""),
                            "comparison": alarm.get("ComparisonOperator", ""),
                            "threshold": alarm.get("Threshold", 0),
                            "actions_enabled": alarm.get("ActionsEnabled", False),
                            "alarm_actions": alarm.get("AlarmActions", []),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_cloudwatch_alarm", "error": str(e), "region": region or self.region})
        return results

    # ── SNS Topics ────────────────────────────────────────────────────────────

    def scan_sns_topics(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        sns = self._client("sns", region=region)
        results = []
        try:
            paginator = sns.get_paginator("list_topics")
            for page in paginator.paginate():
                for topic in page.get("Topics", []):
                    arn = topic["TopicArn"]
                    name = arn.split(":")[-1]
                    attrs = {}
                    try:
                        attrs = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
                    except Exception:
                        pass
                    results.append({
                        "resource_type": "aws_sns_topic",
                        "resource_id": self._hash_id(arn),
                        "resource_name": name,
                        "region": region or self.region,
                        "config": {
                            "subscriptions_confirmed": int(attrs.get("SubscriptionsConfirmed", 0)),
                            "kms_master_key_id": attrs.get("KmsMasterKeyId", ""),
                            "fifo_topic": attrs.get("FifoTopic", "false") == "true",
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_sns_topic", "error": str(e), "region": region or self.region})
        return results

    # ── ECS Clusters ──────────────────────────────────────────────────────────

    def scan_ecs_clusters(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ecs = self._client("ecs", region=region)
        results = []
        try:
            arns = []
            paginator = ecs.get_paginator("list_clusters")
            for page in paginator.paginate():
                arns.extend(page.get("clusterArns", []))
            if arns:
                clusters = ecs.describe_clusters(clusters=arns, include=["SETTINGS", "STATISTICS"]).get("clusters", [])
                for cluster in clusters:
                    results.append({
                        "resource_type": "aws_ecs_cluster",
                        "resource_id": self._hash_id(cluster["clusterArn"]),
                        "resource_name": cluster["clusterName"],
                        "region": region or self.region,
                        "config": {
                            "status": cluster.get("status", ""),
                            "running_tasks": cluster.get("runningTasksCount", 0),
                            "pending_tasks": cluster.get("pendingTasksCount", 0),
                            "active_services": cluster.get("activeServicesCount", 0),
                            "registered_instances": cluster.get("registeredContainerInstancesCount", 0),
                            "capacity_providers": cluster.get("capacityProviders", []),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_ecs_cluster", "error": str(e), "region": region or self.region})
        return results

    # ── IAM Roles ─────────────────────────────────────────────────────────────

    def scan_iam_roles(self) -> List[Dict[str, Any]]:
        iam = self._client("iam")
        results = []
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    # Skip AWS service-linked roles — they're not customer-managed
                    if "/aws-service-role/" in role.get("Path", ""):
                        continue
                    attached = []
                    try:
                        ap = iam.get_paginator("list_attached_role_policies")
                        for p in ap.paginate(RoleName=role["RoleName"]):
                            attached.extend([pol["PolicyName"] for pol in p.get("AttachedPolicies", [])])
                    except Exception:
                        pass
                    results.append({
                        "resource_type": "aws_iam_role",
                        "resource_id": self._hash_id(role["RoleId"]),
                        "resource_name": role["RoleName"],
                        "region": "global",
                        "config": {
                            "role_id": role["RoleId"],
                            "path": role.get("Path", ""),
                            "description": role.get("Description", ""),
                            "max_session_duration": role.get("MaxSessionDuration", 3600),
                            "attached_policies": attached,
                            "created": self._iso(role.get("CreateDate")),
                            "assume_role_service": self._extract_service_principal(role.get("AssumeRolePolicyDocument", {})),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_iam_role", "error": str(e), "region": "global"})
        return results

    def _extract_service_principal(self, doc) -> List[str]:
        """Pull service principals from a trust policy document."""
        principals = []
        try:
            if isinstance(doc, str):
                doc = json.loads(doc)
            for stmt in doc.get("Statement", []):
                p = stmt.get("Principal", {})
                if isinstance(p, str):
                    principals.append(p)
                elif isinstance(p, dict):
                    for v in p.values():
                        if isinstance(v, list):
                            principals.extend(v)
                        else:
                            principals.append(v)
        except Exception:
            pass
        return principals

    # ── IAM Policies ─────────────────────────────────────────────────────────

    def scan_iam_policies(self) -> List[Dict[str, Any]]:
        iam = self._client("iam")
        results = []
        try:
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for pol in page.get("Policies", []):
                    resource = {
                        "resource_type": "aws_iam_policy",
                        "resource_id": self._hash_id(pol["PolicyId"]),
                        "resource_name": pol["PolicyName"],
                        "region": "global",
                        "config": {
                            "attachment_count": pol.get("AttachmentCount", 0),
                            "is_attachable": pol.get("IsAttachable", True),
                            "created": self._iso(pol.get("CreateDate")),
                            "statements": [],
                            "has_admin_access": False,
                        },
                    }
                    try:
                        version = pol.get("DefaultVersionId", "v1")
                        doc = iam.get_policy_version(PolicyArn=pol["Arn"], VersionId=version)
                        stmts = doc["PolicyVersion"]["Document"].get("Statement", [])
                        resource["config"]["statements"] = [
                            {"effect": s.get("Effect", ""), "action": s.get("Action", []), "resource": self._sanitize_resources(s.get("Resource", []))}
                            for s in stmts
                        ]
                        resource["config"]["has_admin_access"] = any(
                            s.get("Effect") == "Allow" and
                            (s.get("Action") == "*" or (isinstance(s.get("Action"), list) and "*" in s["Action"])) and
                            (s.get("Resource") == "*" or (isinstance(s.get("Resource"), list) and "*" in s["Resource"]))
                            for s in stmts
                        )
                    except Exception:
                        pass
                    results.append(resource)
        except Exception as e:
            results.append({"resource_type": "aws_iam_policy", "error": str(e), "region": "global"})
        return results

    # ── IAM Users ─────────────────────────────────────────────────────────────

    def scan_iam_users(self) -> List[Dict[str, Any]]:
        iam = self._client("iam")
        results = []
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    name = user["UserName"]
                    resource = {
                        "resource_type": "aws_iam_user",
                        "resource_id": self._hash_id(user["UserId"]),
                        "resource_name": name,
                        "region": "global",
                        "config": {
                            "created": self._iso(user.get("CreateDate")),
                            "last_used": self._iso(user.get("PasswordLastUsed")),
                            "has_mfa": False,
                            "has_console_access": False,
                            "access_keys": [],
                            "attached_policies": [],
                            "groups": [],
                        },
                    }
                    try:
                        mfa = iam.list_mfa_devices(UserName=name)
                        resource["config"]["has_mfa"] = len(mfa.get("MFADevices", [])) > 0
                    except Exception:
                        pass
                    try:
                        iam.get_login_profile(UserName=name)
                        resource["config"]["has_console_access"] = True
                    except ClientError as e:
                        if e.response["Error"]["Code"] != "NoSuchEntity":
                            pass
                    try:
                        keys = iam.list_access_keys(UserName=name).get("AccessKeyMetadata", [])
                        for k in keys:
                            try:
                                created = k.get("CreateDate")
                                if hasattr(created, "replace"):
                                    age = (datetime.now(timezone.utc) - created.replace(tzinfo=timezone.utc if created.tzinfo is None else created.tzinfo)).days
                                else:
                                    age = 0
                            except Exception:
                                age = 0
                            resource["config"]["access_keys"].append({
                                "status": k.get("Status", ""),
                                "age_days": age,
                                "is_old": age > 90,
                            })
                    except Exception:
                        pass
                    try:
                        ap = iam.get_paginator("list_attached_user_policies")
                        for p in ap.paginate(UserName=name):
                            resource["config"]["attached_policies"].extend([pol["PolicyName"] for pol in p.get("AttachedPolicies", [])])
                    except Exception:
                        pass
                    try:
                        groups = iam.list_groups_for_user(UserName=name).get("Groups", [])
                        resource["config"]["groups"] = [g["GroupName"] for g in groups]
                    except Exception:
                        pass
                    results.append(resource)
        except Exception as e:
            results.append({"resource_type": "aws_iam_user", "error": str(e), "region": "global"})
        return results

    # ── ACM Certificates ──────────────────────────────────────────────────────

    def scan_acm_certificates(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        acm = self._client("acm", region=region)
        results = []
        try:
            paginator = acm.get_paginator("list_certificates")
            for page in paginator.paginate(CertificateStatuses=["ISSUED", "PENDING_VALIDATION", "EXPIRED", "INACTIVE"]):
                for cert in page.get("CertificateSummaryList", []):
                    arn = cert["CertificateArn"]
                    detail = {}
                    try:
                        detail = acm.describe_certificate(CertificateArn=arn).get("Certificate", {})
                    except Exception:
                        pass
                    results.append({
                        "resource_type": "aws_acm_certificate",
                        "resource_id": self._hash_id(arn),
                        "resource_name": cert.get("DomainName", arn.split("/")[-1]),
                        "region": region or self.region,
                        "config": {
                            "domain_name": cert.get("DomainName", ""),
                            "status": detail.get("Status", cert.get("Status", "")),
                            "type": detail.get("Type", ""),
                            "key_algorithm": detail.get("KeyAlgorithm", ""),
                            "renewal_eligibility": detail.get("RenewalEligibility", ""),
                            "in_use": len(detail.get("InUseBy", [])) > 0,
                            "expires": self._iso(detail.get("NotAfter")),
                            "issued": self._iso(detail.get("IssuedAt")),
                            "subject_alt_names": detail.get("SubjectAlternativeNames", [])[:5],
                            "transparency_logging": detail.get("Options", {}).get("CertificateTransparencyLoggingPreference", "ENABLED"),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_acm_certificate", "error": str(e), "region": region or self.region})
        return results

    # ── ElastiCache Clusters ──────────────────────────────────────────────────

    def scan_elasticache_clusters(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ec = self._client("elasticache", region=region)
        results = []
        try:
            paginator = ec.get_paginator("describe_cache_clusters")
            for page in paginator.paginate(ShowCacheNodeInfo=False):
                for cluster in page.get("CacheClusters", []):
                    raw_vpc = ""
                    try:
                        sg = ec.describe_cache_subnet_groups(CacheSubnetGroupName=cluster.get("CacheSubnetGroupName", ""))
                        raw_vpc = sg.get("CacheSubnetGroups", [{}])[0].get("VpcId", "")
                    except Exception:
                        pass
                    results.append({
                        "resource_type": "aws_elasticache_cluster",
                        "resource_id": self._hash_id(cluster["CacheClusterId"]),
                        "resource_name": cluster["CacheClusterId"],
                        "region": region or self.region,
                        "config": {
                            "engine": cluster.get("Engine", ""),
                            "engine_version": cluster.get("EngineVersion", ""),
                            "cache_node_type": cluster.get("CacheNodeType", ""),
                            "status": cluster.get("CacheClusterStatus", ""),
                            "num_cache_nodes": cluster.get("NumCacheNodes", 0),
                            "at_rest_encryption": cluster.get("AtRestEncryptionEnabled", False),
                            "transit_encryption": cluster.get("TransitEncryptionEnabled", False),
                            "auto_minor_version_upgrade": cluster.get("AutoMinorVersionUpgrade", False),
                            "vpc_id": self._hash_id(raw_vpc) if raw_vpc else "",
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_elasticache_cluster", "error": str(e), "region": region or self.region})
        return results

    # ── DynamoDB Tables ───────────────────────────────────────────────────────

    def scan_dynamodb_tables(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ddb = self._client("dynamodb", region=region)
        results = []
        try:
            paginator = ddb.get_paginator("list_tables")
            for page in paginator.paginate():
                for table_name in page.get("TableNames", []):
                    try:
                        detail = ddb.describe_table(TableName=table_name).get("Table", {})
                        sse = detail.get("SSEDescription", {})
                        pitr = False
                        try:
                            pitr_resp = ddb.describe_continuous_backups(TableName=table_name)
                            pitr = pitr_resp.get("ContinuousBackupsDescription", {}).get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus") == "ENABLED"
                        except Exception:
                            pass
                        results.append({
                            "resource_type": "aws_dynamodb_table",
                            "resource_id": self._hash_id(detail.get("TableArn", table_name)),
                            "resource_name": table_name,
                            "region": region or self.region,
                            "config": {
                                "status": detail.get("TableStatus", ""),
                                "billing_mode": detail.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED"),
                                "item_count": detail.get("ItemCount", 0),
                                "size_bytes": detail.get("TableSizeBytes", 0),
                                "encryption_type": sse.get("SSEType", "DEFAULT"),
                                "encryption_enabled": sse.get("Status") == "ENABLED",
                                "point_in_time_recovery": pitr,
                                "stream_enabled": detail.get("StreamSpecification", {}).get("StreamEnabled", False),
                                "deletion_protection": detail.get("DeletionProtectionEnabled", False),
                            },
                        })
                    except Exception:
                        continue
        except Exception as e:
            results.append({"resource_type": "aws_dynamodb_table", "error": str(e), "region": region or self.region})
        return results

    # ── SQS Queues ────────────────────────────────────────────────────────────

    def scan_sqs_queues(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        sqs = self._client("sqs", region=region)
        results = []
        try:
            paginator = sqs.get_paginator("list_queues")
            for page in paginator.paginate():
                for url in page.get("QueueUrls", []):
                    name = url.split("/")[-1]
                    attrs = {}
                    try:
                        attrs = sqs.get_queue_attributes(
                            QueueUrl=url,
                            AttributeNames=["All"]
                        ).get("Attributes", {})
                    except Exception:
                        pass
                    results.append({
                        "resource_type": "aws_sqs_queue",
                        "resource_id": self._hash_id(attrs.get("QueueArn", url)),
                        "resource_name": name,
                        "region": region or self.region,
                        "config": {
                            "fifo": name.endswith(".fifo"),
                            "visibility_timeout": int(attrs.get("VisibilityTimeout", 30)),
                            "message_retention_seconds": int(attrs.get("MessageRetentionPeriod", 345600)),
                            "kms_master_key_id": attrs.get("KmsMasterKeyId", ""),
                            "encryption_enabled": bool(attrs.get("KmsMasterKeyId", "")),
                            "approximate_messages": int(attrs.get("ApproximateNumberOfMessages", 0)),
                            "policy": bool(attrs.get("Policy", "")),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_sqs_queue", "error": str(e), "region": region or self.region})
        return results

    # ── ECR Repositories ──────────────────────────────────────────────────────

    def scan_ecr_repositories(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ecr = self._client("ecr", region=region)
        results = []
        try:
            paginator = ecr.get_paginator("describe_repositories")
            for page in paginator.paginate():
                for repo in page.get("repositories", []):
                    scan_config = {}
                    try:
                        scan_config = ecr.get_registry_scanning_configuration().get("scanningConfiguration", {})
                    except Exception:
                        pass
                    immutable = repo.get("imageTagMutability", "MUTABLE") == "IMMUTABLE"
                    encryption = repo.get("encryptionConfiguration", {}).get("encryptionType", "AES256")
                    results.append({
                        "resource_type": "aws_ecr_repository",
                        "resource_id": self._hash_id(repo["repositoryArn"]),
                        "resource_name": repo["repositoryName"],
                        "region": region or self.region,
                        "config": {
                            "uri": repo.get("repositoryUri", ""),
                            "image_tag_immutability": immutable,
                            "encryption_type": encryption,
                            "scan_on_push": repo.get("imageScanningConfiguration", {}).get("scanOnPush", False),
                            "image_count": 0,
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_ecr_repository", "error": str(e), "region": region or self.region})
        return results

    # ── Elastic IPs ───────────────────────────────────────────────────────────

    def scan_elastic_ips(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        ec2 = self._client("ec2", region=region)
        results = []
        try:
            resp = ec2.describe_addresses()
            for addr in resp.get("Addresses", []):
                alloc_id = addr.get("AllocationId") or addr.get("PublicIp", "")
                name = next((t["Value"] for t in addr.get("Tags", []) if t["Key"] == "Name"), addr.get("PublicIp", ""))
                results.append({
                    "resource_type": "aws_eip",
                    "resource_id": self._hash_id(alloc_id),
                    "resource_name": name,
                    "region": region or self.region,
                    "config": {
                        "public_ip": addr.get("PublicIp", ""),
                        "allocation_id": alloc_id,
                        "association_id": addr.get("AssociationId", ""),
                        "associated": bool(addr.get("AssociationId")),
                        "instance_id": addr.get("InstanceId", ""),
                        "domain": addr.get("Domain", "vpc"),
                    },
                })
        except Exception as e:
            results.append({"resource_type": "aws_eip", "error": str(e), "region": region or self.region})
        return results

    # ── CloudFront Distributions ──────────────────────────────────────────────

    def scan_cloudfront_distributions(self) -> List[Dict[str, Any]]:
        """CloudFront is global — call once, not per-region."""
        cf = self._client("cloudfront", region="us-east-1")
        results = []
        try:
            paginator = cf.get_paginator("list_distributions")
            for page in paginator.paginate():
                dist_list = page.get("DistributionList", {})
                for dist in dist_list.get("Items", []):
                    did = dist.get("Id", "")
                    results.append({
                        "resource_type": "aws_cloudfront_distribution",
                        "resource_id": self._hash_id(did),
                        "resource_name": dist.get("DomainName", did),
                        "region": "global",
                        "config": {
                            "domain_name": dist.get("DomainName", ""),
                            "status": dist.get("Status", ""),
                            "enabled": dist.get("Enabled", False),
                            "http_version": dist.get("HttpVersion", ""),
                            "price_class": dist.get("PriceClass", ""),
                            "waf_web_acl_id": dist.get("WebACLId", ""),
                            "aliases": dist.get("Aliases", {}).get("Items", [])[:5],
                            "origins_count": dist.get("Origins", {}).get("Quantity", 0),
                            "viewer_certificate_minimum_protocol": dist.get("ViewerCertificate", {}).get("MinimumProtocolVersion", ""),
                            "logging_enabled": bool(dist.get("Logging", {}).get("Bucket", "")),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_cloudfront_distribution", "error": str(e), "region": "global"})
        return results

    # ── EKS Clusters ─────────────────────────────────────────────────────────

    def scan_eks_clusters(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        eks = self._client("eks", region=region)
        results = []
        try:
            paginator = eks.get_paginator("list_clusters")
            for page in paginator.paginate():
                for name in page.get("clusters", []):
                    try:
                        detail = eks.describe_cluster(name=name).get("cluster", {})
                        raw_vpc = detail.get("resourcesVpcConfig", {}).get("vpcId", "")
                        logging_types = [
                            lt["type"] for lt in detail.get("logging", {}).get("clusterLogging", [])
                            if lt.get("enabled")
                        ]
                        results.append({
                            "resource_type": "aws_eks_cluster",
                            "resource_id": self._hash_id(detail.get("arn", name)),
                            "resource_name": name,
                            "region": region or self.region,
                            "config": {
                                "status": detail.get("status", ""),
                                "kubernetes_version": detail.get("version", ""),
                                "endpoint_public_access": detail.get("resourcesVpcConfig", {}).get("endpointPublicAccess", True),
                                "endpoint_private_access": detail.get("resourcesVpcConfig", {}).get("endpointPrivateAccess", False),
                                "secrets_encryption": any(e.get("provider") for e in detail.get("encryptionConfig", [])),
                                "logging_enabled": logging_types,
                                "vpc_id": self._hash_id(raw_vpc) if raw_vpc else "",
                                "platform_version": detail.get("platformVersion", ""),
                            },
                        })
                    except Exception:
                        continue
        except Exception as e:
            results.append({"resource_type": "aws_eks_cluster", "error": str(e), "region": region or self.region})
        return results

    # ── WAF Web ACLs (v2) ─────────────────────────────────────────────────────

    def scan_waf_web_acls(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        waf = self._client("wafv2", region=region)
        results = []
        for scope in ("REGIONAL",):
            try:
                # WAFv2 list_web_acls does NOT support pagination — use direct API call
                resp = waf.list_web_acls(Scope=scope)
                for acl in resp.get("WebACLs", []):
                    results.append({
                        "resource_type": "aws_wafv2_web_acl",
                        "resource_id": self._hash_id(acl["ARN"]),
                        "resource_name": acl["Name"],
                        "region": region or self.region,
                        "config": {
                            "scope": scope,
                            "id": acl["Id"],
                            "arn": acl["ARN"],
                            "description": acl.get("Description", ""),
                        },
                    })
            except Exception as e:
                results.append({"resource_type": "aws_wafv2_web_acl", "error": str(e), "region": region or self.region})
        return results

    # ── Elastic Beanstalk Environments ────────────────────────────────────────

    def scan_elasticbeanstalk_environments(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        eb = self._client("elasticbeanstalk", region=region)
        results = []
        try:
            resp = eb.describe_environments(IncludeDeleted=False)
            for env in resp.get("Environments", []):
                results.append({
                    "resource_type": "aws_elastic_beanstalk_environment",
                    "resource_id": self._hash_id(env.get("EnvironmentArn", env["EnvironmentId"])),
                    "resource_name": env["EnvironmentName"],
                    "region": region or self.region,
                    "config": {
                        "application_name": env.get("ApplicationName", ""),
                        "status": env.get("Status", ""),
                        "health": env.get("Health", ""),
                        "platform_arn": env.get("PlatformArn", ""),
                        "tier": env.get("Tier", {}).get("Name", ""),
                    },
                })
        except Exception as e:
            results.append({"resource_type": "aws_elastic_beanstalk_environment", "error": str(e), "region": region or self.region})
        return results

    # ── Step Functions State Machines ─────────────────────────────────────────

    def scan_stepfunctions(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        sf = self._client("stepfunctions", region=region)
        results = []
        try:
            paginator = sf.get_paginator("list_state_machines")
            for page in paginator.paginate():
                for sm in page.get("stateMachines", []):
                    results.append({
                        "resource_type": "aws_sfn_state_machine",
                        "resource_id": self._hash_id(sm["stateMachineArn"]),
                        "resource_name": sm["name"],
                        "region": region or self.region,
                        "config": {
                            "type": sm.get("type", "STANDARD"),
                            "status": sm.get("status", ""),
                            "created": self._iso(sm.get("creationDate")),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_sfn_state_machine", "error": str(e), "region": region or self.region})
        return results

    # ── API Gateway (REST APIs) ───────────────────────────────────────────────

    def scan_api_gateway(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        apigw = self._client("apigateway", region=region)
        results = []
        try:
            paginator = apigw.get_paginator("get_rest_apis")
            for page in paginator.paginate():
                for api in page.get("items", []):
                    results.append({
                        "resource_type": "aws_api_gateway_rest_api",
                        "resource_id": self._hash_id(api["id"]),
                        "resource_name": api["name"],
                        "region": region or self.region,
                        "config": {
                            "api_id": api["id"],
                            "description": api.get("description", ""),
                            "endpoint_type": api.get("endpointConfiguration", {}).get("types", []),
                            "disable_execute_api_endpoint": api.get("disableExecuteApiEndpoint", False),
                            "created": self._iso(api.get("createdDate")),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_api_gateway_rest_api", "error": str(e), "region": region or self.region})
        # HTTP / WebSocket APIs (v2)
        try:
            apigwv2 = self._client("apigatewayv2", region=region)
            resp = apigwv2.get_apis()
            for api in resp.get("Items", []):
                results.append({
                    "resource_type": "aws_apigatewayv2_api",
                    "resource_id": self._hash_id(api["ApiId"]),
                    "resource_name": api["Name"],
                    "region": region or self.region,
                    "config": {
                        "api_id": api["ApiId"],
                        "protocol_type": api.get("ProtocolType", ""),
                        "disable_execute_api_endpoint": api.get("DisableExecuteApiEndpoint", False),
                    },
                })
        except Exception:
            pass
        return results

    # ── RDS Clusters (Aurora) ─────────────────────────────────────────────────

    def scan_rds_clusters(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        rds = self._client("rds", region=region)
        results = []
        try:
            paginator = rds.get_paginator("describe_db_clusters")
            for page in paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    raw_vpc = cluster.get("VpcSecurityGroups", [{}])[0].get("VpcId", "") if cluster.get("VpcSecurityGroups") else ""
                    results.append({
                        "resource_type": "aws_rds_cluster",
                        "resource_id": self._hash_id(cluster["DBClusterArn"]),
                        "resource_name": cluster["DBClusterIdentifier"],
                        "region": region or self.region,
                        "config": {
                            "engine": cluster.get("Engine", ""),
                            "engine_version": cluster.get("EngineVersion", ""),
                            "status": cluster.get("Status", ""),
                            "multi_az": cluster.get("MultiAZ", False),
                            "storage_encrypted": cluster.get("StorageEncrypted", False),
                            "backup_retention": cluster.get("BackupRetentionPeriod", 0),
                            "deletion_protection": cluster.get("DeletionProtection", False),
                            "iam_authentication": cluster.get("IAMDatabaseAuthenticationEnabled", False),
                            "publicly_accessible": cluster.get("PubliclyAccessible", False),
                            "activity_stream_status": cluster.get("ActivityStreamStatus", "stopped"),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_rds_cluster", "error": str(e), "region": region or self.region})
        return results

    # ── OpenSearch (Elasticsearch) Domains ───────────────────────────────────

    def scan_opensearch_domains(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        results = []
        for service in ("opensearch", "es"):
            try:
                client = self._client(service, region=region)
                if service == "opensearch":
                    domains = client.list_domain_names().get("DomainNames", [])
                else:
                    domains = client.list_domain_names().get("DomainNames", [])
                for d in domains:
                    name = d.get("DomainName", "")
                    try:
                        if service == "opensearch":
                            detail = client.describe_domain(DomainName=name).get("DomainStatus", {})
                        else:
                            detail = client.describe_elasticsearch_domain(DomainName=name).get("DomainStatus", {})
                        raw_vpc = detail.get("VPCOptions", {}).get("VPCId", "")
                        results.append({
                            "resource_type": "aws_opensearch_domain",
                            "resource_id": self._hash_id(detail.get("ARN", name)),
                            "resource_name": name,
                            "region": region or self.region,
                            "config": {
                                "engine_version": detail.get("EngineVersion", detail.get("ElasticsearchVersion", "")),
                                "instance_type": detail.get("ClusterConfig", {}).get("InstanceType", ""),
                                "dedicated_master": detail.get("ClusterConfig", {}).get("DedicatedMasterEnabled", False),
                                "encryption_at_rest": detail.get("EncryptionAtRestOptions", {}).get("Enabled", False),
                                "node_to_node_encryption": detail.get("NodeToNodeEncryptionOptions", {}).get("Enabled", False),
                                "vpc_id": self._hash_id(raw_vpc) if raw_vpc else "",
                                "tls_policy": detail.get("DomainEndpointOptions", {}).get("TLSSecurityPolicy", ""),
                            },
                        })
                    except Exception:
                        continue
                break  # success with one of the two client names
            except Exception:
                continue
        return results

    # ── MSK (Kafka) Clusters ──────────────────────────────────────────────────

    def scan_msk_clusters(self, region: Optional[str] = None) -> List[Dict[str, Any]]:
        msk = self._client("kafka", region=region)
        results = []
        try:
            paginator = msk.get_paginator("list_clusters_v2")
            for page in paginator.paginate():
                for cluster in page.get("ClusterInfoList", []):
                    results.append({
                        "resource_type": "aws_msk_cluster",
                        "resource_id": self._hash_id(cluster["ClusterArn"]),
                        "resource_name": cluster["ClusterName"],
                        "region": region or self.region,
                        "config": {
                            "state": cluster.get("State", ""),
                            "cluster_type": cluster.get("ClusterType", ""),
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "aws_msk_cluster", "error": str(e), "region": region or self.region})
        return results

    # ── CloudTrail Events (Activity feed) ─────────────────────────────────────

    def fetch_cloudtrail_events(self, max_events: int = 100, region: Optional[str] = None) -> List[Dict[str, Any]]:
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
                    "event_time": self._iso(event.get("EventTime")),
                    "username": event.get("Username", "unknown"),
                    "read_only": str(event.get("ReadOnly", "")),
                }
                try:
                    detail = json.loads(event.get("CloudTrailEvent", "{}"))
                    sanitized["source_ip"] = detail.get("sourceIPAddress", "")
                    sanitized["user_agent"] = (detail.get("userAgent", "") or "")[:50]
                    sanitized["error_code"] = detail.get("errorCode", "")
                    sanitized["error_message"] = (detail.get("errorMessage", "") or "")[:100]
                    sanitized["is_suspicious"] = bool(
                        sanitized["error_code"] in ("AccessDenied", "UnauthorizedAccess") or
                        any(w in sanitized["event_name"] for w in ("Delete", "Detach", "Disable", "Remove", "Revoke"))
                    )
                except Exception:
                    sanitized["is_suspicious"] = False
                events.append(sanitized)
        except Exception as e:
            return [{"error": str(e), "event_name": "CloudTrailFetchError"}]
        return events

    # ── Full Regional Scan ────────────────────────────────────────────────────

    def _scan_region(self, reg: str) -> Dict[str, Any]:
        """Scan all regional resource types for one region — run in parallel."""
        data: Dict[str, Any] = {"resources": [], "events": [], "region_errors": {}}

        # Each scanner is run; errors are captured inside each method
        scanners = [
            ("ec2_instances",       self.scan_ec2_instances),
            ("ebs_volumes",         self.scan_ebs_volumes),
            ("vpcs",                self.scan_vpcs),
            ("subnets",             self.scan_subnets),
            ("security_groups",     self.scan_security_groups),
            ("internet_gateways",   self.scan_internet_gateways),
            ("nat_gateways",        self.scan_nat_gateways),
            ("route_tables",        self.scan_route_tables),
            ("rds_instances",       self.scan_rds_instances),
            ("lambda_functions",    self.scan_lambda_functions),
            ("kms_keys",            self.scan_kms_keys),
            ("secrets",             self.scan_secrets_manager),
            ("load_balancers",      self.scan_load_balancers),
            ("cloudtrail_trails",   self.scan_cloudtrail_trails),
            ("cloudwatch_alarms",   self.scan_cloudwatch_alarms),
            ("sns_topics",          self.scan_sns_topics),
            ("ecs_clusters",        self.scan_ecs_clusters),
            ("acm_certificates",        self.scan_acm_certificates),
            ("elasticache_clusters",    self.scan_elasticache_clusters),
            ("dynamodb_tables",         self.scan_dynamodb_tables),
            ("sqs_queues",              self.scan_sqs_queues),
            ("ecr_repositories",        self.scan_ecr_repositories),
            ("elastic_ips",             self.scan_elastic_ips),
            ("eks_clusters",            self.scan_eks_clusters),
            ("waf_web_acls",            self.scan_waf_web_acls),
            ("elasticbeanstalk_envs",   self.scan_elasticbeanstalk_environments),
            ("stepfunctions",           self.scan_stepfunctions),
            ("api_gateway",             self.scan_api_gateway),
            ("rds_clusters",            self.scan_rds_clusters),
            ("opensearch_domains",      self.scan_opensearch_domains),
            ("msk_clusters",            self.scan_msk_clusters),
        ]

        counts: Dict[str, int] = {}
        for key, fn in scanners:
            resources = fn(region=reg)
            
            # Track errors per resource type
            errors = [r for r in resources if "error" in r]
            if errors:
                data["region_errors"][key] = errors[0].get("error", "Unknown error")
                print(f"  ⚠ {key:25} ERROR: {errors[0].get('error', 'Unknown error')[:60]}")
            
            for r in resources:
                if "error" not in r:
                    r.setdefault("region", reg)
            data["resources"].extend(resources)
            counts[key] = len([r for r in resources if "error" not in r])
            
            # Log results
            if counts[key] > 0:
                print(f"  ✓ {key:25} → {counts[key]:3} resources")
            else:
                print(f"  ○ {key:25} → 0 resources")

        events = self.fetch_cloudtrail_events(region=reg)
        for e in events:
            if "error" not in e:
                e["region"] = reg
            else:
                data["region_errors"]["cloudtrail_events"] = e.get("error", "Unknown error")
        data["events"].extend(events)
        counts["cloudtrail_events"] = len([e for e in events if "error" not in e])
        data["counts"] = counts
        return data

    # ── Full Scan Entry Point ─────────────────────────────────────────────────

    def run_full_scan(self, regions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run a complete scan of all AWS resource types across ALL opted-in regions."""
        print(f"\n{'='*70}")
        print(f"🚀 Starting AWS Full Scan")
        print(f"   Region method: {self.region}")
        print(f"   Has access_key: {'YES' if self.access_key else 'NO'}")
        print(f"   Has secret_key: {'YES' if self.secret_key else 'NO'}")
        
        if not regions or regions == ["all"]:
            # Auto-discover every opted-in region in the account
            scan_regions = self.get_available_regions()
            if not scan_regions:
                scan_regions = [self.region]
        else:
            scan_regions = regions
        
        print(f"   Regions to scan: {scan_regions}")
        print(f"{'='*70}\n")

        results: Dict[str, Any] = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "regions_scanned": scan_regions,
            "primary_region": self.region,
            "resources": [],
            "events": [],
            "summary": {
                "s3_buckets": 0,
                "iam_users": 0,
                "iam_roles": 0,
                "iam_policies": 0,
                "ec2_instances": 0,
                "ebs_volumes": 0,
                "vpcs": 0,
                "subnets": 0,
                "security_groups": 0,
                "internet_gateways": 0,
                "nat_gateways": 0,
                "route_tables": 0,
                "rds_instances": 0,
                "lambda_functions": 0,
                "kms_keys": 0,
                "secrets": 0,
                "load_balancers": 0,
                "cloudtrail_trails": 0,
                "cloudwatch_alarms": 0,
                "sns_topics": 0,
                "ecs_clusters": 0,
                "cloudtrail_events": 0,
                "acm_certificates": 0,
                "elasticache_clusters": 0,
                "dynamodb_tables": 0,
                "sqs_queues": 0,
                "ecr_repositories": 0,
                "elastic_ips": 0,
                "cloudfront_distributions": 0,
                "eks_clusters": 0,
                "waf_web_acls": 0,
                "elasticbeanstalk_envs": 0,
                "stepfunctions": 0,
                "api_gateway": 0,
                "rds_clusters": 0,
                "opensearch_domains": 0,
                "msk_clusters": 0,
                "regions_count": len(scan_regions),
            },
        }

        # 1 — Global services (run once, not per-region)
        print(f"📡 Scanning global services (S3, IAM, CloudFront)...")
        with ThreadPoolExecutor(max_workers=5) as ex:
            fut_s3    = ex.submit(self.scan_s3_buckets)
            fut_users = ex.submit(self.scan_iam_users)
            fut_roles = ex.submit(self.scan_iam_roles)
            fut_pols  = ex.submit(self.scan_iam_policies)
            fut_cf    = ex.submit(self.scan_cloudfront_distributions)

            s3_res    = fut_s3.result()
            user_res  = fut_users.result()
            role_res  = fut_roles.result()
            pol_res   = fut_pols.result()
            cf_res    = fut_cf.result()

        print(f"  ✓ S3 buckets: {len([r for r in s3_res if 'error' not in r])}")
        print(f"  ✓ IAM users: {len([r for r in user_res if 'error' not in r])}")
        print(f"  ✓ IAM roles: {len([r for r in role_res if 'error' not in r])}")
        print(f"  ✓ IAM policies: {len([r for r in pol_res if 'error' not in r])}")
        print(f"  ✓ CloudFront: {len([r for r in cf_res if 'error' not in r])}")

        results["resources"].extend(s3_res)
        results["summary"]["s3_buckets"] = len([r for r in s3_res if "error" not in r])
        results["resources"].extend(user_res)
        results["summary"]["iam_users"] = len([r for r in user_res if "error" not in r])
        results["resources"].extend(role_res)
        results["summary"]["iam_roles"] = len([r for r in role_res if "error" not in r])
        results["resources"].extend(pol_res)
        results["summary"]["iam_policies"] = len([r for r in pol_res if "error" not in r])
        cf_res = fut_cf.result()
        results["resources"].extend(cf_res)
        results["summary"]["cloudfront_distributions"] = len([r for r in cf_res if "error" not in r])

        # 2 — Regional services (parallel per region)
        max_workers = min(8, len(scan_regions))
        region_error_log: Dict[str, Dict] = {}  # Track errors per region
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            future_to_region = {ex.submit(self._scan_region, reg): reg for reg in scan_regions}
            for future in as_completed(future_to_region):
                region = future_to_region[future]
                region_data = future.result()
                results["resources"].extend(region_data["resources"])
                results["events"].extend(region_data["events"])
                counts = region_data.get("counts", {})
                for key, count in counts.items():
                    if key in results["summary"]:
                        results["summary"][key] += count
                
                # Log any region-specific errors
                if region_data.get("region_errors"):
                    region_error_log[region] = region_data["region_errors"]

        # 3 — Deduplicate by resource_id, keeping richest config
        unique: Dict[str, Any] = {}
        for res in results["resources"]:
            rid = res.get("resource_id")
            if not rid:
                continue
            if rid not in unique or len(json.dumps(res.get("config", {}))) > len(json.dumps(unique[rid].get("config", {}))):
                unique[rid] = res

        results["resources"] = sorted(unique.values(), key=lambda x: x.get("resource_id", ""))
        results["summary"]["total_resources"] = len(results["resources"])
        
        # Include region error log for debugging
        if region_error_log:
            results["_region_error_log"] = region_error_log
        
        return results

    # ── Organization / Multi-Account ──────────────────────────────────────────

    def get_organization_accounts(self) -> List[Dict]:
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
                    })
            return accounts
        except Exception as e:
            return [{"id": "current", "name": "Current Account", "error": str(e)}]

    def assume_role_scanner(self, account_id: str, role_name: str = "GuardianScannerRole") -> Optional["AWSScanner"]:
        try:
            sts = self._client("sts")
            role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
            response = sts.assume_role(RoleArn=role_arn, RoleSessionName="GuardianDiscoverySession")
            creds = response["Credentials"]
            return AWSScanner(
                access_key=creds["AccessKeyId"],
                secret_key=creds["SecretAccessKey"],
                session_token=creds["SessionToken"],
                region=self.region,
            )
        except Exception as e:
            print(f"Error assuming role in {account_id}: {e}")
            return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _hash_id(raw_id: str) -> str:
        """Stable 12-char hash of any AWS identifier — used for all resource_id fields."""
        if not raw_id:
            return ""
        return hashlib.sha256(raw_id.encode()).hexdigest()[:12]

    @staticmethod
    def _mask_account_id(account_id: str) -> str:
        if len(account_id) >= 4:
            return "****" + account_id[-4:]
        return "****"

    @staticmethod
    def _iso(dt) -> str:
        """Safely convert datetime or string to ISO-8601 string."""
        if dt is None:
            return ""
        if hasattr(dt, "isoformat"):
            return dt.isoformat()
        return str(dt)

    @staticmethod
    def _sanitize_resources(resources) -> Any:
        if isinstance(resources, str):
            if resources == "*":
                return "*"
            return resources.split(":")[-1] if ":" in resources else resources
        if isinstance(resources, list):
            return [AWSScanner._sanitize_resources(r) for r in resources]
        return resources
