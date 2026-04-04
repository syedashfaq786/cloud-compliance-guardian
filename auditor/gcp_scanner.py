"""
GCP Live Scanner — Fetches real-time configurations from Google Cloud using GCP SDKs.

Covers:
  - Compute Instances (VMs)
  - VPC Networks + Subnets
  - Firewall Rules
  - Cloud Storage Buckets (encryption, public access, versioning, logging)
  - Cloud SQL Instances (SSL, public IP, backup, authorized networks)
  - GKE Clusters (RBAC, network policy, private cluster, shielded nodes)
  - IAM Policy Bindings (project-level)
  - Service Accounts
  - Cloud KMS Key Rings and Keys
  - Cloud Load Balancers (forwarding rules)
  - Pub/Sub Topics
  - Cloud Run Services

Design:
  - resource_id is always _hash_id(gcp_resource_name) for topology joins
  - raw name preserved in config for cross-resource linkage
  - Errors captured per-resource without stopping the whole scan
  - All scanners run in parallel via ThreadPoolExecutor
"""

import os
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

try:
    from google.oauth2 import service_account
    from google.auth import default as gauth_default
    from googleapiclient import discovery
    from google.cloud import storage as gcs
    from google.cloud import container_v1
    from google.cloud import kms_v1
    from google.cloud.sql.connector import Connector as SqlConnector
    import google.auth
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

# GCP uses REST APIs via googleapiclient for many services
# We build service objects lazily and cache them


class GCPScanner:
    """Fetches and normalises GCP resource configurations for compliance auditing."""

    def __init__(self, project_id: Optional[str] = None):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT_ID")
        self._credentials = None
        self._services: Dict[str, Any] = {}

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _get_credentials(self):
        if self._credentials is None:
            key_file = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
            if key_file and os.path.exists(key_file):
                self._credentials, _ = google.auth.load_credentials_from_file(key_file)
            else:
                self._credentials, _ = gauth_default()
        return self._credentials

    def _service(self, api: str, version: str):
        key = f"{api}:{version}"
        if key not in self._services:
            self._services[key] = discovery.build(
                api, version,
                credentials=self._get_credentials(),
                cache_discovery=False,
            )
        return self._services[key]

    def test_connection(self) -> Dict[str, Any]:
        if not GCP_AVAILABLE:
            return {"connected": False, "error": "GCP SDK not installed. Run: pip install google-cloud-storage google-cloud-container google-cloud-kms google-auth-httplib2 google-api-python-client"}
        if not self.project_id:
            return {"connected": False, "error": "GCP Project ID not configured"}
        try:
            svc = self._service("cloudresourcemanager", "v3")
            svc.projects().get(name=f"projects/{self.project_id}").execute()
            return {"connected": True, "project_id": self.project_id}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    # ── Compute Instances ─────────────────────────────────────────────────────

    def scan_compute_instances(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            compute = self._service("compute", "v1")
            # aggregatedList covers all zones in one call
            request = compute.instances().aggregatedList(project=self.project_id)
            while request:
                resp = request.execute()
                for zone_name, zone_data in resp.get("items", {}).items():
                    for inst in zone_data.get("instances", []):
                        zone = zone_name.replace("zones/", "")
                        network_ifaces = inst.get("networkInterfaces", [])
                        has_public_ip = any(
                            len(iface.get("accessConfigs", [])) > 0
                            for iface in network_ifaces
                        )
                        service_accounts = [sa.get("email", "") for sa in inst.get("serviceAccounts", [])]
                        disks = inst.get("disks", [])
                        all_disks_encrypted = all(
                            d.get("diskEncryptionKey") is not None for d in disks
                        ) if disks else False
                        results.append({
                            "resource_type": "google_compute_instance",
                            "resource_id": self._hash_id(inst["selfLink"]),
                            "resource_name": inst["name"],
                            "region": zone,
                            "config": {
                                "raw_name": inst["selfLink"],
                                "machine_type": inst.get("machineType", "").split("/")[-1],
                                "status": inst.get("status", ""),
                                "zone": zone,
                                "has_public_ip": has_public_ip,
                                "service_accounts": service_accounts,
                                "default_sa": any("compute@developer" in sa for sa in service_accounts),
                                "all_disks_encrypted": all_disks_encrypted,
                                "shielded_vm": inst.get("shieldedInstanceConfig", {}).get("enableSecureBoot", False),
                                "os_login": inst.get("metadata", {}).get("items", [{}])[0].get("key") == "enable-oslogin",
                                "deletion_protection": inst.get("deletionProtection", False),
                                "labels": inst.get("labels", {}),
                            },
                        })
                request = compute.instances().aggregatedList_next(request, resp)
        except Exception as e:
            results.append({"resource_type": "google_compute_instance", "error": str(e)})
        return results

    # ── VPC Networks ──────────────────────────────────────────────────────────

    def scan_networks(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            compute = self._service("compute", "v1")
            resp = compute.networks().list(project=self.project_id).execute()
            for network in resp.get("items", []):
                subnets = network.get("subnetworks", [])
                results.append({
                    "resource_type": "google_compute_network",
                    "resource_id": self._hash_id(network["selfLink"]),
                    "resource_name": network["name"],
                    "region": "global",
                    "config": {
                        "raw_name": network["selfLink"],
                        "auto_create_subnetworks": network.get("autoCreateSubnetworks", False),
                        "routing_mode": network.get("routingConfig", {}).get("routingMode", ""),
                        "subnet_count": len(subnets),
                        "subnet_refs": [self._hash_id(s) for s in subnets],
                        "description": network.get("description", ""),
                        "mtu": network.get("mtu", 0),
                    },
                })
        except Exception as e:
            results.append({"resource_type": "google_compute_network", "error": str(e)})
        return results

    # ── Subnets ───────────────────────────────────────────────────────────────

    def scan_subnets(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            compute = self._service("compute", "v1")
            request = compute.subnetworks().aggregatedList(project=self.project_id)
            while request:
                resp = request.execute()
                for region_name, region_data in resp.get("items", {}).items():
                    for subnet in region_data.get("subnetworks", []):
                        region = region_name.replace("regions/", "")
                        results.append({
                            "resource_type": "google_compute_subnetwork",
                            "resource_id": self._hash_id(subnet["selfLink"]),
                            "resource_name": subnet["name"],
                            "region": region,
                            "config": {
                                "raw_name": subnet["selfLink"],
                                "network": self._hash_id(subnet.get("network", "")),
                                "ip_cidr_range": subnet.get("ipCidrRange", ""),
                                "private_google_access": subnet.get("privateIpGoogleAccess", False),
                                "flow_logs": subnet.get("enableFlowLogs", False),
                                "purpose": subnet.get("purpose", "PRIVATE"),
                            },
                        })
                request = compute.subnetworks().aggregatedList_next(request, resp)
        except Exception as e:
            results.append({"resource_type": "google_compute_subnetwork", "error": str(e)})
        return results

    # ── Firewall Rules ────────────────────────────────────────────────────────

    def scan_firewall_rules(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            compute = self._service("compute", "v1")
            resp = compute.firewalls().list(project=self.project_id).execute()
            for fw in resp.get("items", []):
                source_ranges = fw.get("sourceRanges", [])
                allowed = fw.get("allowed", [])
                ports = []
                for a in allowed:
                    ports.extend(a.get("ports", ["all"]) or ["all"])
                    if not a.get("ports"):
                        ports.append("all")
                results.append({
                    "resource_type": "google_compute_firewall",
                    "resource_id": self._hash_id(fw["selfLink"]),
                    "resource_name": fw["name"],
                    "region": "global",
                    "config": {
                        "raw_name": fw["selfLink"],
                        "direction": fw.get("direction", "INGRESS"),
                        "action": "allow" if fw.get("allowed") else "deny",
                        "source_ranges": source_ranges,
                        "allowed_ports": ports,
                        "target_tags": fw.get("targetTags", []),
                        "disabled": fw.get("disabled", False),
                        "open_to_internet": "0.0.0.0/0" in source_ranges or "::/0" in source_ranges,
                        "allows_ssh": any(
                            "22" in p or p == "all"
                            for p in ports
                        ) and ("0.0.0.0/0" in source_ranges),
                        "allows_rdp": any(
                            "3389" in p or p == "all"
                            for p in ports
                        ) and ("0.0.0.0/0" in source_ranges),
                        "priority": fw.get("priority", 1000),
                    },
                })
        except Exception as e:
            results.append({"resource_type": "google_compute_firewall", "error": str(e)})
        return results

    # ── Cloud Storage Buckets ─────────────────────────────────────────────────

    def scan_storage_buckets(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            client = gcs.Client(project=self.project_id, credentials=self._get_credentials())
            for bucket in client.list_buckets():
                # Reload to get full metadata
                bucket.reload()
                iam_policy = {}
                public_access = False
                try:
                    policy = bucket.get_iam_policy(requested_policy_version=3)
                    for binding in policy.bindings:
                        if "allUsers" in binding["members"] or "allAuthenticatedUsers" in binding["members"]:
                            public_access = True
                            break
                except Exception:
                    pass
                results.append({
                    "resource_type": "google_storage_bucket",
                    "resource_id": self._hash_id(f"gs://{bucket.name}"),
                    "resource_name": bucket.name,
                    "region": bucket.location or "global",
                    "config": {
                        "raw_name": f"gs://{bucket.name}",
                        "storage_class": bucket.storage_class or "",
                        "location_type": bucket.location_type or "",
                        "versioning_enabled": bucket.versioning_enabled or False,
                        "public_access_prevention": getattr(bucket, "iam_configuration", {}).get("publicAccessPrevention", "inherited") if hasattr(bucket, "iam_configuration") else "unknown",
                        "uniform_bucket_level_access": bucket.iam_configuration.uniform_bucket_level_access_enabled if hasattr(bucket, "iam_configuration") else False,
                        "public_iam": public_access,
                        "logging": bucket.get_logging() is not None,
                        "encryption_key": bucket.default_kms_key_name or "",
                        "retention_period": bucket.retention_period or 0,
                        "labels": bucket.labels or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "google_storage_bucket", "error": str(e)})
        return results

    # ── Cloud SQL ─────────────────────────────────────────────────────────────

    def scan_sql_instances(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            sqladmin = self._service("sqladmin", "v1beta4")
            resp = sqladmin.instances().list(project=self.project_id).execute()
            for inst in resp.get("items", []):
                settings = inst.get("settings", {})
                ip_config = settings.get("ipConfiguration", {})
                authorized_networks = ip_config.get("authorizedNetworks", [])
                open_networks = [n for n in authorized_networks if n.get("value") in ("0.0.0.0/0", "::/0")]
                backup_config = settings.get("backupConfiguration", {})
                results.append({
                    "resource_type": "google_sql_database_instance",
                    "resource_id": self._hash_id(inst["selfLink"]),
                    "resource_name": inst["name"],
                    "region": inst.get("region", ""),
                    "config": {
                        "raw_name": inst["selfLink"],
                        "database_version": inst.get("databaseVersion", ""),
                        "state": inst.get("state", ""),
                        "tier": settings.get("tier", ""),
                        "public_ip": ip_config.get("ipv4Enabled", False),
                        "ssl_required": ip_config.get("requireSsl", False),
                        "authorized_networks": len(authorized_networks),
                        "open_to_internet": len(open_networks) > 0,
                        "backup_enabled": backup_config.get("enabled", False),
                        "backup_binary_log": backup_config.get("binaryLogEnabled", False),
                        "storage_auto_resize": settings.get("storageAutoResize", False),
                        "deletion_protection": settings.get("deletionProtectionEnabled", False),
                        "database_flags": {f["name"]: f.get("value") for f in settings.get("databaseFlags", [])},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "google_sql_database_instance", "error": str(e)})
        return results

    # ── GKE Clusters ──────────────────────────────────────────────────────────

    def scan_gke_clusters(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            client = container_v1.ClusterManagerClient(credentials=self._get_credentials())
            resp = client.list_clusters(parent=f"projects/{self.project_id}/locations/-")
            for cluster in resp.clusters:
                results.append({
                    "resource_type": "google_container_cluster",
                    "resource_id": self._hash_id(cluster.self_link),
                    "resource_name": cluster.name,
                    "region": cluster.location,
                    "config": {
                        "raw_name": cluster.self_link,
                        "status": container_v1.Cluster.Status(cluster.status).name,
                        "kubernetes_version": cluster.current_master_version,
                        "node_count": cluster.current_node_count,
                        "private_cluster": cluster.private_cluster_config.enable_private_nodes if cluster.private_cluster_config else False,
                        "network_policy": cluster.network_policy.enabled if cluster.network_policy else False,
                        "legacy_abac": cluster.legacy_abac.enabled if cluster.legacy_abac else False,
                        "shielded_nodes": cluster.shielded_nodes.enabled if cluster.shielded_nodes else False,
                        "binary_authorization": cluster.binary_authorization.enabled if cluster.binary_authorization else False,
                        "workload_identity": cluster.workload_identity_config.workload_pool != "" if cluster.workload_identity_config else False,
                        "dataplane_v2": cluster.dataplane_v2_config.enabled if cluster.dataplane_v2_config else False,
                        "release_channel": cluster.release_channel.channel if cluster.release_channel else "UNSPECIFIED",
                        "autopilot": cluster.autopilot.enabled if cluster.autopilot else False,
                    },
                })
        except Exception as e:
            results.append({"resource_type": "google_container_cluster", "error": str(e)})
        return results

    # ── IAM Policy ────────────────────────────────────────────────────────────

    def scan_iam_policies(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            crm = self._service("cloudresourcemanager", "v3")
            resp = crm.projects().getIamPolicy(
                resource=f"projects/{self.project_id}",
                body={"options": {"requestedPolicyVersion": 3}}
            ).execute()
            for binding in resp.get("bindings", []):
                role = binding.get("role", "")
                members = binding.get("members", [])
                results.append({
                    "resource_type": "google_project_iam_binding",
                    "resource_id": self._hash_id(f"iam:{self.project_id}:{role}"),
                    "resource_name": role.split("/")[-1],
                    "region": "global",
                    "config": {
                        "role": role,
                        "member_count": len(members),
                        "has_allUsers": "allUsers" in members,
                        "has_allAuthenticatedUsers": "allAuthenticatedUsers" in members,
                        "is_primitive_role": role in ("roles/owner", "roles/editor", "roles/viewer"),
                        "is_owner": role == "roles/owner",
                        "members": members[:20],  # cap for storage
                    },
                })
        except Exception as e:
            results.append({"resource_type": "google_project_iam_binding", "error": str(e)})
        return results

    # ── Service Accounts ──────────────────────────────────────────────────────

    def scan_service_accounts(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            iam = self._service("iam", "v1")
            resp = iam.projects().serviceAccounts().list(
                name=f"projects/{self.project_id}"
            ).execute()
            for sa in resp.get("accounts", []):
                # Check for user-managed keys (risky)
                keys = []
                try:
                    kr = iam.projects().serviceAccounts().keys().list(
                        name=sa["name"],
                        keyTypes=["USER_MANAGED"]
                    ).execute()
                    keys = kr.get("keys", [])
                except Exception:
                    pass
                results.append({
                    "resource_type": "google_service_account",
                    "resource_id": self._hash_id(sa["uniqueId"]),
                    "resource_name": sa.get("displayName") or sa["email"].split("@")[0],
                    "region": "global",
                    "config": {
                        "email": sa["email"],
                        "disabled": sa.get("disabled", False),
                        "user_managed_keys": len(keys),
                        "has_user_managed_keys": len(keys) > 0,
                        "description": sa.get("description", ""),
                    },
                })
        except Exception as e:
            results.append({"resource_type": "google_service_account", "error": str(e)})
        return results

    # ── KMS Key Rings and Keys ────────────────────────────────────────────────

    def scan_kms_keys(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            kms = kms_v1.KeyManagementServiceClient(credentials=self._get_credentials())
            parent = f"projects/{self.project_id}/locations/-"
            for key_ring in kms.list_key_rings(parent=parent):
                for key in kms.list_crypto_keys(parent=key_ring.name):
                    rotation_period = None
                    if key.rotation_period:
                        rotation_period = key.rotation_period.seconds // 86400  # days
                    results.append({
                        "resource_type": "google_kms_crypto_key",
                        "resource_id": self._hash_id(key.name),
                        "resource_name": key.name.split("/")[-1],
                        "region": key_ring.name.split("/locations/")[1].split("/")[0],
                        "config": {
                            "raw_name": key.name,
                            "key_ring": key_ring.name.split("/")[-1],
                            "purpose": kms_v1.CryptoKey.CryptoKeyPurpose(key.purpose).name,
                            "rotation_period_days": rotation_period,
                            "rotation_enabled": rotation_period is not None,
                            "protection_level": kms_v1.ProtectionLevel(
                                key.version_template.protection_level
                            ).name if key.version_template else "SOFTWARE",
                            "algorithm": kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm(
                                key.version_template.algorithm
                            ).name if key.version_template else "",
                        },
                    })
        except Exception as e:
            results.append({"resource_type": "google_kms_crypto_key", "error": str(e)})
        return results

    # ── Load Balancers (Forwarding Rules) ─────────────────────────────────────

    def scan_load_balancers(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            compute = self._service("compute", "v1")
            request = compute.forwardingRules().aggregatedList(project=self.project_id)
            while request:
                resp = request.execute()
                for region_name, region_data in resp.get("items", {}).items():
                    for rule in region_data.get("forwardingRules", []):
                        region = region_name.replace("regions/", "")
                        results.append({
                            "resource_type": "google_compute_forwarding_rule",
                            "resource_id": self._hash_id(rule["selfLink"]),
                            "resource_name": rule["name"],
                            "region": region,
                            "config": {
                                "raw_name": rule["selfLink"],
                                "ip_address": rule.get("IPAddress", ""),
                                "ip_protocol": rule.get("IPProtocol", ""),
                                "port_range": rule.get("portRange", ""),
                                "load_balancing_scheme": rule.get("loadBalancingScheme", ""),
                                "network_tier": rule.get("networkTier", ""),
                                "is_global": rule.get("loadBalancingScheme", "") in ("EXTERNAL", "EXTERNAL_MANAGED"),
                            },
                        })
                request = compute.forwardingRules().aggregatedList_next(request, resp)
        except Exception as e:
            results.append({"resource_type": "google_compute_forwarding_rule", "error": str(e)})
        return results

    # ── Pub/Sub Topics ────────────────────────────────────────────────────────

    def scan_pubsub_topics(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            pubsub = self._service("pubsub", "v1")
            resp = pubsub.projects().topics().list(
                project=f"projects/{self.project_id}"
            ).execute()
            for topic in resp.get("topics", []):
                name = topic["name"].split("/")[-1]
                results.append({
                    "resource_type": "google_pubsub_topic",
                    "resource_id": self._hash_id(topic["name"]),
                    "resource_name": name,
                    "region": "global",
                    "config": {
                        "raw_name": topic["name"],
                        "kms_key_name": topic.get("kmsKeyName", ""),
                        "message_retention_duration": topic.get("messageRetentionDuration", ""),
                        "labels": topic.get("labels", {}),
                    },
                })
        except Exception as e:
            results.append({"resource_type": "google_pubsub_topic", "error": str(e)})
        return results

    # ── Cloud Run Services ────────────────────────────────────────────────────

    def scan_cloud_run_services(self) -> List[Dict[str, Any]]:
        results = []
        if not GCP_AVAILABLE or not self.project_id:
            return results
        try:
            run = self._service("run", "v2")
            resp = run.projects().locations().services().list(
                parent=f"projects/{self.project_id}/locations/-"
            ).execute()
            for svc in resp.get("services", []):
                name = svc["name"].split("/")[-1]
                results.append({
                    "resource_type": "google_cloud_run_service",
                    "resource_id": self._hash_id(svc["name"]),
                    "resource_name": name,
                    "region": svc["name"].split("/locations/")[1].split("/")[0] if "/locations/" in svc["name"] else "global",
                    "config": {
                        "raw_name": svc["name"],
                        "uri": svc.get("uri", ""),
                        "ingress": svc.get("ingress", ""),
                        "public": svc.get("ingress", "") == "INGRESS_TRAFFIC_ALL",
                        "labels": svc.get("labels", {}),
                    },
                })
        except Exception as e:
            results.append({"resource_type": "google_cloud_run_service", "error": str(e)})
        return results

    # ── Full Scan ─────────────────────────────────────────────────────────────

    def run_full_scan(self) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "project_id": self.project_id,
            "resources": [],
            "summary": {
                "compute_instances": 0,
                "vpc_networks": 0,
                "subnets": 0,
                "firewall_rules": 0,
                "storage_buckets": 0,
                "sql_instances": 0,
                "gke_clusters": 0,
                "iam_bindings": 0,
                "service_accounts": 0,
                "kms_keys": 0,
                "load_balancers": 0,
                "pubsub_topics": 0,
                "cloud_run_services": 0,
                "total_resources": 0,
            },
        }

        scan_map = {
            "compute_instances":  self.scan_compute_instances,
            "vpc_networks":       self.scan_networks,
            "subnets":            self.scan_subnets,
            "firewall_rules":     self.scan_firewall_rules,
            "storage_buckets":    self.scan_storage_buckets,
            "sql_instances":      self.scan_sql_instances,
            "gke_clusters":       self.scan_gke_clusters,
            "iam_bindings":       self.scan_iam_policies,
            "service_accounts":   self.scan_service_accounts,
            "kms_keys":           self.scan_kms_keys,
            "load_balancers":     self.scan_load_balancers,
            "pubsub_topics":      self.scan_pubsub_topics,
            "cloud_run_services": self.scan_cloud_run_services,
        }

        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(fn): key for key, fn in scan_map.items()}
            for future in as_completed(futures):
                key = futures[future]
                found = future.result()
                results["resources"].extend(found)
                results["summary"][key] = len([r for r in found if "error" not in r])

        # Deduplicate by resource_id
        unique: Dict[str, Any] = {}
        for res in results["resources"]:
            rid = res.get("resource_id")
            if not rid:
                continue
            if rid not in unique or len(json.dumps(res.get("config", {}))) > len(json.dumps(unique[rid].get("config", {}))):
                unique[rid] = res

        results["resources"] = sorted(unique.values(), key=lambda x: x.get("resource_name", ""))
        results["summary"]["total_resources"] = len(results["resources"])
        return results

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _hash_id(raw_id: str) -> str:
        if not raw_id:
            return ""
        return hashlib.sha256(str(raw_id).encode()).hexdigest()[:12]
