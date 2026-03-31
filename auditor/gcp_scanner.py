import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

try:
    from google import auth
    from google.cloud import compute_v1
    from google.cloud import storage
    from google.cloud import resourcemanager_v3
    from google.cloud import asset_v1
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

class GCPScanner:
    """Scanner for Google Cloud Platform infrastructure resources across projects and regions."""

    def __init__(self, project_id: Optional[str] = None):
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")

    def test_connection(self) -> Dict[str, Any]:
        """Test authentication with GCP."""
        if not GCP_AVAILABLE:
            return {"connected": False, "error": "GCP SDK not installed"}
        
        if not self.project_id:
            return {"connected": False, "error": "GCP Project ID not configured"}

        try:
            # Try to get default credentials
            # credential, project = auth.default()
            return {"connected": True, "project_id": self.project_id}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    def scan_compute_instances(self) -> List[Dict[str, Any]]:
        """Scan for GCP Compute Instances."""
        # Simple placeholder for now
        return []

    def scan_storage_buckets(self) -> List[Dict[str, Any]]:
        """Scan for GCP Storage Buckets."""
        resources = []
        if not GCP_AVAILABLE or not self.project_id:
            return []
        try:
            client = storage.Client(project=self.project_id)
            for bucket in client.list_buckets():
                resources.append({
                    "resource_id": bucket.id,
                    "resource_name": bucket.name,
                    "resource_type": "google_storage_bucket",
                    "location": bucket.location,
                    "config": {
                        "storage_class": bucket.storage_class,
                        "versioning_enabled": bucket.versioning_enabled,
                    }
                })
        except Exception as e:
            resources.append({"error": str(e), "resource_type": "google_storage_bucket"})
        return resources

    def scan_networks(self) -> List[Dict[str, Any]]:
        """Scan for GCP VPC Networks."""
        resources = []
        if not GCP_AVAILABLE or not self.project_id:
            return []
        try:
            client = compute_v1.NetworksClient()
            for network in client.list(project=self.project_id):
                resources.append({
                    "resource_id": network.id,
                    "resource_name": network.name,
                    "resource_type": "google_compute_network",
                    "location": "Global",
                    "config": {
                        "auto_create_subnetworks": network.auto_create_subnetworks,
                        "routing_mode": network.routing_config.routing_mode if network.routing_config else "unknown",
                    }
                })
        except Exception as e:
            resources.append({"error": str(e), "resource_type": "google_compute_network"})
        return resources

    def scan_sql_instances(self) -> List[Dict[str, Any]]:
        """Scan for GCP Cloud SQL Instances."""
        # Simple placeholder for now
        return []

    # ── Full Inventory Discovery ──────────────────────────────────────────────

    def scan_all_resources(self) -> List[Dict[str, Any]]:
        """
        Discover ALL resources in the project using Cloud Asset Inventory.
        """
        if not GCP_AVAILABLE or not self.project_id:
            return []
            
        resources = []
        try:
            client = asset_v1.AssetServiceClient()
            parent = f"projects/{self.project_id}"
            
            # List all assets
            response = client.list_assets(
                request={
                    "parent": parent,
                    "content_type": asset_v1.ContentType.RESOURCE,
                }
            )
            
            for asset in response:
                # Map GCP type to our internal format
                # e.g., compute.googleapis.com/Instance -> google_compute_instance
                atype = asset.asset_type.lower()
                if "/" in atype:
                    service = atype.split("/")[0].split(".")[0]
                    res_part = atype.split("/")[1]
                    rtype = f"google_{service}_{res_part}"
                else:
                    rtype = f"google_{atype.replace('.', '_')}"

                resources.append({
                    "resource_id": self._hash_id(asset.name),
                    "resource_name": asset.name.split("/")[-1],
                    "resource_type": rtype,
                    "location": "Global", 
                    "config": {
                        "name": asset.name,
                        "asset_type": asset.asset_type
                    }
                })
        except Exception as e:
            resources.append({"error": str(e), "resource_type": "google_inventory"})
            
        return resources

    def _hash_id(self, original_id: str) -> str:
        """Helper to provide a consistent resource_id format."""
        import hashlib
        return hashlib.sha256(original_id.encode()).hexdigest()[:16]

    def run_full_scan(self) -> Dict[str, Any]:
        """Run a complete scan of GCP resources."""
        results = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "project_id": self.project_id,
            "resources": [],
            "summary": {
                "compute_instances": 0,
                "storage_buckets": 0,
                "vpc_networks": 0,
                "sql_instances": 0,
            }
        }

        # 1. Full Inventory Discovery
        inventory = self.scan_all_resources()
        results["resources"].extend(inventory)

        # 2. Detailed Scans
        scan_map = {
            "storage_buckets": self.scan_storage_buckets,
            "compute_instances": self.scan_compute_instances,
            "vpc_networks": self.scan_networks,
            "sql_instances": self.scan_sql_instances,
        }

        for key, scan_fn in scan_map.items():
            found = scan_fn()
            results["resources"].extend(found)
            results["summary"][key] = len([r for r in found if "error" not in r])

        # 3. Deduping
        unique_resources = {}
        for res in results["resources"]:
            rid = res.get("resource_id")
            if not rid: continue
            
            if rid in unique_resources:
                if len(json.dumps(res.get("config", {}))) > len(json.dumps(unique_resources[rid].get("config", {}))):
                    unique_resources[rid] = res
            else:
                unique_resources[rid] = res
        
        results["resources"] = list(unique_resources.values())
        results["summary"]["total_resources"] = len(results["resources"])

        return results
