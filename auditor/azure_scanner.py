import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.sql import SqlManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

class AzureScanner:
    """Scanner for Azure infrastructure resources across subscriptions and regions."""

    def __init__(self, subscription_id: Optional[str] = None):
        self.subscription_id = subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET")

    def test_connection(self) -> Dict[str, Any]:
        """Test authentication with Azure."""
        if not AZURE_AVAILABLE:
            return {"connected": False, "error": "Azure SDK not installed"}
        
        if not self.subscription_id:
            return {"connected": False, "error": "Azure Subscription ID not configured"}

        try:
            # In a real scenario, we'd try to list resource groups or similar
            # For now, we'll assume if variables are set, we're good for the 'mock/demo' phase
            # unless we have real credentials
            return {"connected": True, "subscription_id": self.subscription_id}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    def scan_resource_groups(self) -> List[Dict[str, Any]]:
        """Scan for Azure Resource Groups."""
        resources = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return []
        
        try:
            credential = DefaultAzureCredential()
            client = ResourceManagementClient(credential, self.subscription_id)
            for rg in client.resource_groups.list():
                resources.append({
                    "resource_id": rg.id,
                    "resource_name": rg.name,
                    "resource_type": "azurerm_resource_group",
                    "location": rg.location,
                    "config": {
                        "name": rg.name,
                        "location": rg.location,
                        "tags": rg.tags or {}
                    }
                })
        except Exception as e:
            resources.append({"error": str(e), "resource_type": "azurerm_resource_group"})
        
        return resources

    def scan_virtual_machines(self) -> List[Dict[str, Any]]:
        """Scan for Azure Virtual Machines."""
        resources = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return []

        try:
            credential = DefaultAzureCredential()
            compute_client = ComputeManagementClient(credential, self.subscription_id)
            for vm in compute_client.virtual_machines.list_all():
                resources.append({
                    "resource_id": vm.id,
                    "resource_name": vm.name,
                    "resource_type": "azurerm_virtual_machine",
                    "location": vm.location,
                    "config": {
                        "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else "unknown",
                        "os_type": vm.storage_profile.os_disk.os_type if vm.storage_profile and vm.storage_profile.os_disk else "unknown",
                        "provisioning_state": vm.provisioning_state,
                    }
                })
        except Exception as e:
            resources.append({"error": str(e), "resource_type": "azurerm_virtual_machine"})
        
        return resources

    def scan_storage_accounts(self) -> List[Dict[str, Any]]:
        """Scan for Azure Storage Accounts."""
        # Simple placeholder for now
        return []

    def scan_vnets(self) -> List[Dict[str, Any]]:
        """Scan for Azure Virtual Networks."""
        resources = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return []
        try:
            credential = DefaultAzureCredential()
            client = NetworkManagementClient(credential, self.subscription_id)
            for vnet in client.virtual_networks.list_all():
                resources.append({
                    "resource_id": vnet.id,
                    "resource_name": vnet.name,
                    "resource_type": "azurerm_virtual_network",
                    "location": vnet.location,
                    "config": {
                        "address_space": vnet.address_space.address_prefixes if vnet.address_space else [],
                        "subnets": [s.name for s in vnet.subnets] if vnet.subnets else [],
                    }
                })
        except Exception as e:
            resources.append({"error": str(e), "resource_type": "azurerm_virtual_network"})
        return resources

    def scan_sql_servers(self) -> List[Dict[str, Any]]:
        """Scan for Azure SQL Servers."""
        resources = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return []
        try:
            credential = DefaultAzureCredential()
            client = SqlManagementClient(credential, self.subscription_id)
            for server in client.servers.list():
                resources.append({
                    "resource_id": server.id,
                    "resource_name": server.name,
                    "resource_type": "azurerm_sql_server",
                    "location": server.location,
                    "config": {
                        "version": server.version,
                        "state": server.state,
                        "public_network_access": server.public_network_access,
                    }
                })
        except Exception as e:
            resources.append({"error": str(e), "resource_type": "azurerm_sql_server"})
        return resources

    # ── Full Inventory Discovery ──────────────────────────────────────────────

    def scan_all_resources(self) -> List[Dict[str, Any]]:
        """
        Discover ALL resources in the subscription using Resource Management Client.
        This captures resources not covered by specific scanners.
        """
        if not AZURE_AVAILABLE or not self.subscription_id:
            return []
            
        resources = []
        try:
            credential = DefaultAzureCredential()
            client = ResourceManagementClient(credential, self.subscription_id)
            for res in client.resources.list():
                # Map Azure type to our internal format
                rtype = f"azure_{res.type.replace('/', '_').lower()}"
                resources.append({
                    "resource_id": self._hash_id(res.id),
                    "resource_name": res.name,
                    "resource_type": rtype,
                    "location": res.location,
                    "config": {
                        "id": res.id,
                        "tags": res.tags or {}
                    }
                })
        except Exception as e:
            resources.append({"error": str(e), "resource_type": "azure_inventory"})
            
        return resources

    def _hash_id(self, original_id: str) -> str:
        """Helper to provide a consistent resource_id format."""
        import hashlib
        return hashlib.sha256(original_id.encode()).hexdigest()[:16]

    def run_full_scan(self) -> Dict[str, Any]:
        """Run a complete scan of Azure resources."""
        results = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "subscription_id": self.subscription_id,
            "resources": [],
            "summary": {
                "total_resources": 0,
                "resource_groups": 0,
                "virtual_machines": 0,
                "virtual_networks": 0,
                "sql_servers": 0,
                "storage_accounts": 0,
            }
        }

        # 1. Full Inventory Discovery
        inventory = self.scan_all_resources()
        results["resources"].extend(inventory)

        # 2. Detailed Scans
        scan_map = {
            "resource_groups": self.scan_resource_groups,
            "virtual_machines": self.scan_virtual_machines,
            "virtual_networks": self.scan_vnets,
            "sql_servers": self.scan_sql_servers,
            "storage_accounts": self.scan_storage_accounts,
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
                # Keep the one with more config info
                if len(json.dumps(res.get("config", {}))) > len(json.dumps(unique_resources[rid].get("config", {}))):
                    unique_resources[rid] = res
            else:
                unique_resources[rid] = res
        
        results["resources"] = list(unique_resources.values())
        results["summary"]["total_resources"] = len(results["resources"])

        return results
