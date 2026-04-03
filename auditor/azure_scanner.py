"""
Azure Live Scanner — Fetches real-time configurations from Azure using the Azure SDK.

Covers:
  - Resource Groups
  - Virtual Machines + Managed Disks
  - Virtual Networks, Subnets, NSGs, Public IPs, Load Balancers
  - Storage Accounts (encryption, public access, logging)
  - SQL Servers (firewall rules, auditing, TLS)
  - Key Vaults (soft-delete, purge protection)
  - App Services (HTTPS-only, identity)
  - AKS Clusters (RBAC, encryption, network plugin)
  - Role Assignments (RBAC)

Design:
  - All scan methods are independent and safe to call in parallel
  - Errors per-resource captured without stopping the whole scan
  - resource_id is always _hash_id(azure_resource_id) for topology joins
  - raw_id preserved in config for cross-resource linkage
"""

import os
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

try:
    from azure.identity import ClientSecretCredential, DefaultAzureCredential
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.sql import SqlManagementClient
    from azure.mgmt.keyvault import KeyVaultManagementClient
    from azure.mgmt.web import WebSiteManagementClient
    from azure.mgmt.containerservice import ContainerServiceClient
    from azure.mgmt.authorization import AuthorizationManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False


class AzureScanner:
    """Fetches and normalises Azure resource configurations for compliance auditing."""

    def __init__(self, subscription_id: Optional[str] = None):
        self.subscription_id = subscription_id or os.getenv("AZURE_SUBSCRIPTION_ID")
        self.tenant_id = os.getenv("AZURE_TENANT_ID")
        self.client_id = os.getenv("AZURE_CLIENT_ID")
        self.client_secret = os.getenv("AZURE_CLIENT_SECRET")
        self._credential = None

    # ── Auth ──────────────────────────────────────────────────────────────────

    def _get_credential(self):
        if self._credential is None:
            if self.tenant_id and self.client_id and self.client_secret:
                self._credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                )
            else:
                self._credential = DefaultAzureCredential()
        return self._credential

    def test_connection(self) -> Dict[str, Any]:
        if not AZURE_AVAILABLE:
            return {"connected": False, "error": "Azure SDK not installed. Run: pip install azure-mgmt-resource azure-identity"}
        if not self.subscription_id:
            return {"connected": False, "error": "Azure Subscription ID not configured"}
        try:
            cred = self._get_credential()
            client = ResourceManagementClient(cred, self.subscription_id)
            # Light call to verify credentials work
            next(iter(client.resource_groups.list()), None)
            return {
                "connected": True,
                "subscription_id": self.subscription_id,
                "tenant_id": self.tenant_id or "default",
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}

    # ── Resource Groups ───────────────────────────────────────────────────────

    def scan_resource_groups(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            client = ResourceManagementClient(self._get_credential(), self.subscription_id)
            for rg in client.resource_groups.list():
                results.append({
                    "resource_type": "azurerm_resource_group",
                    "resource_id": self._hash_id(rg.id),
                    "resource_name": rg.name,
                    "region": rg.location,
                    "config": {
                        "raw_id": rg.id,
                        "location": rg.location,
                        "provisioning_state": rg.properties.provisioning_state if rg.properties else "",
                        "tags": rg.tags or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_resource_group", "error": str(e)})
        return results

    # ── Virtual Machines ──────────────────────────────────────────────────────

    def scan_virtual_machines(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            compute = ComputeManagementClient(self._get_credential(), self.subscription_id)
            for vm in compute.virtual_machines.list_all():
                storage_profile = vm.storage_profile
                os_disk = storage_profile.os_disk if storage_profile else None
                nic_refs = []
                if vm.network_profile and vm.network_profile.network_interfaces:
                    nic_refs = [nic.id for nic in vm.network_profile.network_interfaces if nic.id]
                results.append({
                    "resource_type": "azurerm_virtual_machine",
                    "resource_id": self._hash_id(vm.id),
                    "resource_name": vm.name,
                    "region": vm.location,
                    "config": {
                        "raw_id": vm.id,
                        "vm_size": vm.hardware_profile.vm_size if vm.hardware_profile else "",
                        "os_type": os_disk.os_type if os_disk else "",
                        "provisioning_state": vm.provisioning_state or "",
                        "disable_password_auth": (
                            vm.os_profile.linux_configuration.disable_password_authentication
                            if vm.os_profile and vm.os_profile.linux_configuration else None
                        ),
                        "network_interface_ids": nic_refs,
                        "identity_type": vm.identity.type if vm.identity else "None",
                        "tags": vm.tags or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_virtual_machine", "error": str(e)})
        return results

    # ── Managed Disks ─────────────────────────────────────────────────────────

    def scan_managed_disks(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            compute = ComputeManagementClient(self._get_credential(), self.subscription_id)
            for disk in compute.disks.list():
                results.append({
                    "resource_type": "azurerm_managed_disk",
                    "resource_id": self._hash_id(disk.id),
                    "resource_name": disk.name,
                    "region": disk.location,
                    "config": {
                        "raw_id": disk.id,
                        "size_gb": disk.disk_size_gb or 0,
                        "disk_state": disk.disk_state or "",
                        "sku": disk.sku.name if disk.sku else "",
                        "encryption_type": disk.encryption.type if disk.encryption else "",
                        "network_access_policy": disk.network_access_policy or "",
                        "os_type": disk.os_type or "",
                        "tags": disk.tags or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_managed_disk", "error": str(e)})
        return results

    # ── Virtual Networks ──────────────────────────────────────────────────────

    def scan_virtual_networks(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            net = NetworkManagementClient(self._get_credential(), self.subscription_id)
            for vnet in net.virtual_networks.list_all():
                subnets = []
                for sn in (vnet.subnets or []):
                    subnets.append({
                        "name": sn.name,
                        "address_prefix": sn.address_prefix or "",
                        "id": self._hash_id(sn.id) if sn.id else "",
                        "raw_id": sn.id or "",
                        "nsg_id": self._hash_id(sn.network_security_group.id)
                            if sn.network_security_group and sn.network_security_group.id else "",
                    })
                results.append({
                    "resource_type": "azurerm_virtual_network",
                    "resource_id": self._hash_id(vnet.id),
                    "resource_name": vnet.name,
                    "region": vnet.location,
                    "config": {
                        "raw_id": vnet.id,
                        "address_space": vnet.address_space.address_prefixes if vnet.address_space else [],
                        "dns_servers": vnet.dhcp_options.dns_servers if vnet.dhcp_options else [],
                        "enable_ddos_protection": vnet.enable_ddos_protection or False,
                        "subnets": subnets,
                        "tags": vnet.tags or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_virtual_network", "error": str(e)})
        return results

    # ── Network Security Groups ───────────────────────────────────────────────

    def scan_nsgs(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            net = NetworkManagementClient(self._get_credential(), self.subscription_id)
            for nsg in net.network_security_groups.list_all():
                inbound = []
                for rule in (nsg.security_rules or []):
                    if rule.direction == "Inbound":
                        inbound.append({
                            "name": rule.name,
                            "priority": rule.priority,
                            "access": rule.access,
                            "protocol": rule.protocol,
                            "source": rule.source_address_prefix or "",
                            "destination_port": rule.destination_port_range or "",
                        })
                results.append({
                    "resource_type": "azurerm_network_security_group",
                    "resource_id": self._hash_id(nsg.id),
                    "resource_name": nsg.name,
                    "region": nsg.location,
                    "config": {
                        "raw_id": nsg.id,
                        "inbound_rules": inbound,
                        "inbound_count": len(inbound),
                        "has_unrestricted_ssh": any(
                            r["access"] == "Allow"
                            and r["source"] in ("*", "Internet", "0.0.0.0/0")
                            and r["destination_port"] in ("22", "*", "0-65535")
                            for r in inbound
                        ),
                        "has_unrestricted_rdp": any(
                            r["access"] == "Allow"
                            and r["source"] in ("*", "Internet", "0.0.0.0/0")
                            and r["destination_port"] in ("3389", "*", "0-65535")
                            for r in inbound
                        ),
                        "tags": nsg.tags or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_network_security_group", "error": str(e)})
        return results

    # ── Public IPs ────────────────────────────────────────────────────────────

    def scan_public_ips(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            net = NetworkManagementClient(self._get_credential(), self.subscription_id)
            for pip in net.public_ip_addresses.list_all():
                results.append({
                    "resource_type": "azurerm_public_ip",
                    "resource_id": self._hash_id(pip.id),
                    "resource_name": pip.name,
                    "region": pip.location,
                    "config": {
                        "raw_id": pip.id,
                        "ip_address": pip.ip_address or "",
                        "allocation_method": pip.public_ip_allocation_method or "",
                        "sku": pip.sku.name if pip.sku else "",
                        "idle_timeout": pip.idle_timeout_in_minutes or 0,
                        "tags": pip.tags or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_public_ip", "error": str(e)})
        return results

    # ── Load Balancers ────────────────────────────────────────────────────────

    def scan_load_balancers(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            net = NetworkManagementClient(self._get_credential(), self.subscription_id)
            for lb in net.load_balancers.list_all():
                results.append({
                    "resource_type": "azurerm_lb",
                    "resource_id": self._hash_id(lb.id),
                    "resource_name": lb.name,
                    "region": lb.location,
                    "config": {
                        "raw_id": lb.id,
                        "sku": lb.sku.name if lb.sku else "",
                        "frontend_ips": len(lb.frontend_ip_configurations or []),
                        "backend_pools": len(lb.backend_address_pools or []),
                        "load_balancing_rules": len(lb.load_balancing_rules or []),
                        "tags": lb.tags or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_lb", "error": str(e)})
        return results

    # ── Storage Accounts ──────────────────────────────────────────────────────

    def scan_storage_accounts(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            storage = StorageManagementClient(self._get_credential(), self.subscription_id)
            for acc in storage.storage_accounts.list():
                rg = acc.id.split("/resourceGroups/")[1].split("/")[0]
                blob_props = {}
                try:
                    bp = storage.blob_services.get_service_properties(rg, acc.name)
                    blob_props = {
                        "logging_read": bp.logging.read if bp.logging else False,
                        "logging_write": bp.logging.write if bp.logging else False,
                        "logging_delete": bp.logging.delete if bp.logging else False,
                        "versioning_enabled": bp.is_versioning_enabled or False,
                    }
                except Exception:
                    pass
                results.append({
                    "resource_type": "azurerm_storage_account",
                    "resource_id": self._hash_id(acc.id),
                    "resource_name": acc.name,
                    "region": acc.location,
                    "config": {
                        "raw_id": acc.id,
                        "account_kind": acc.kind or "",
                        "sku": acc.sku.name if acc.sku else "",
                        "https_only": acc.enable_https_traffic_only or False,
                        "public_network_access": str(acc.public_network_access or "Enabled"),
                        "allow_blob_public_access": acc.allow_blob_public_access or False,
                        "minimum_tls_version": acc.minimum_tls_version or "",
                        "encryption_key_source": acc.encryption.key_source if acc.encryption else "",
                        "infrastructure_encryption": acc.encryption.require_infrastructure_encryption if acc.encryption else False,
                        "blob_logging": blob_props,
                        "tags": acc.tags or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_storage_account", "error": str(e)})
        return results

    # ── SQL Servers ───────────────────────────────────────────────────────────

    def scan_sql_servers(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            sql = SqlManagementClient(self._get_credential(), self.subscription_id)
            for server in sql.servers.list():
                rg = server.id.split("/resourceGroups/")[1].split("/")[0]
                fw_rules = []
                try:
                    for rule in sql.firewall_rules.list_by_server(rg, server.name):
                        fw_rules.append({
                            "name": rule.name,
                            "start_ip": rule.start_ip_address,
                            "end_ip": rule.end_ip_address,
                        })
                except Exception:
                    pass
                auditing = {}
                try:
                    ap = sql.server_blob_auditing_policies.get(rg, server.name)
                    auditing = {"state": ap.state, "retention_days": ap.retention_days or 0}
                except Exception:
                    pass
                results.append({
                    "resource_type": "azurerm_sql_server",
                    "resource_id": self._hash_id(server.id),
                    "resource_name": server.name,
                    "region": server.location,
                    "config": {
                        "raw_id": server.id,
                        "version": server.version or "",
                        "state": server.state or "",
                        "public_network_access": str(server.public_network_access or "Enabled"),
                        "admin_login": server.administrator_login or "",
                        "minimal_tls_version": server.minimal_tls_version or "",
                        "firewall_rules": fw_rules,
                        "allow_all_ips": any(
                            r["start_ip"] == "0.0.0.0" and r["end_ip"] == "255.255.255.255"
                            for r in fw_rules
                        ),
                        "auditing": auditing,
                        "tags": server.tags or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_sql_server", "error": str(e)})
        return results

    # ── Key Vaults ────────────────────────────────────────────────────────────

    def scan_key_vaults(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            kv = KeyVaultManagementClient(self._get_credential(), self.subscription_id)
            for vault in kv.vaults.list():
                props = vault.properties
                results.append({
                    "resource_type": "azurerm_key_vault",
                    "resource_id": self._hash_id(vault.id),
                    "resource_name": vault.name,
                    "region": vault.location,
                    "config": {
                        "raw_id": vault.id,
                        "sku": props.sku.name if props and props.sku else "",
                        "soft_delete_enabled": props.enable_soft_delete if props else False,
                        "purge_protection_enabled": props.enable_purge_protection if props else False,
                        "public_network_access": str(props.public_network_access if props else "Enabled"),
                        "vault_uri": props.vault_uri if props else "",
                        "access_policies_count": len(props.access_policies or []) if props else 0,
                        "tags": vault.tags or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_key_vault", "error": str(e)})
        return results

    # ── App Services ──────────────────────────────────────────────────────────

    def scan_app_services(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            web = WebSiteManagementClient(self._get_credential(), self.subscription_id)
            for app in web.web_apps.list():
                results.append({
                    "resource_type": "azurerm_app_service",
                    "resource_id": self._hash_id(app.id),
                    "resource_name": app.name,
                    "region": app.location,
                    "config": {
                        "raw_id": app.id,
                        "state": app.state or "",
                        "default_host_name": app.default_host_name or "",
                        "https_only": app.https_only or False,
                        "kind": app.kind or "",
                        "identity_type": app.identity.type if app.identity else "None",
                        "tags": app.tags or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_app_service", "error": str(e)})
        return results

    # ── AKS Clusters ──────────────────────────────────────────────────────────

    def scan_aks_clusters(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            acs = ContainerServiceClient(self._get_credential(), self.subscription_id)
            for cluster in acs.managed_clusters.list():
                results.append({
                    "resource_type": "azurerm_kubernetes_cluster",
                    "resource_id": self._hash_id(cluster.id),
                    "resource_name": cluster.name,
                    "region": cluster.location,
                    "config": {
                        "raw_id": cluster.id,
                        "kubernetes_version": cluster.kubernetes_version or "",
                        "provisioning_state": cluster.provisioning_state or "",
                        "node_count": sum(p.count or 0 for p in (cluster.agent_pool_profiles or [])),
                        "rbac_enabled": cluster.enable_rbac or False,
                        "network_plugin": cluster.network_profile.network_plugin if cluster.network_profile else "",
                        "disk_encryption": cluster.disk_encryption_set_id is not None,
                        "identity_type": cluster.identity.type if cluster.identity else "None",
                        "tags": cluster.tags or {},
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_kubernetes_cluster", "error": str(e)})
        return results

    # ── Role Assignments ──────────────────────────────────────────────────────

    def scan_role_assignments(self) -> List[Dict[str, Any]]:
        results = []
        if not AZURE_AVAILABLE or not self.subscription_id:
            return results
        try:
            auth = AuthorizationManagementClient(self._get_credential(), self.subscription_id)
            scope = f"/subscriptions/{self.subscription_id}"
            for ra in auth.role_assignments.list_for_scope(scope):
                results.append({
                    "resource_type": "azurerm_role_assignment",
                    "resource_id": self._hash_id(ra.id),
                    "resource_name": ra.name or "",
                    "region": "global",
                    "config": {
                        "raw_id": ra.id,
                        "principal_id": ra.principal_id or "",
                        "principal_type": ra.principal_type or "",
                        "role_definition_id": (ra.role_definition_id or "").split("/")[-1],
                        "scope": ra.scope or "",
                    },
                })
        except Exception as e:
            results.append({"resource_type": "azurerm_role_assignment", "error": str(e)})
        return results

    # ── Full Scan ─────────────────────────────────────────────────────────────

    def run_full_scan(self) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "subscription_id": self.subscription_id,
            "resources": [],
            "summary": {
                "resource_groups": 0,
                "virtual_machines": 0,
                "managed_disks": 0,
                "virtual_networks": 0,
                "network_security_groups": 0,
                "public_ips": 0,
                "load_balancers": 0,
                "storage_accounts": 0,
                "sql_servers": 0,
                "key_vaults": 0,
                "app_services": 0,
                "aks_clusters": 0,
                "role_assignments": 0,
                "total_resources": 0,
            },
        }

        scan_map = {
            "resource_groups":          self.scan_resource_groups,
            "virtual_machines":         self.scan_virtual_machines,
            "managed_disks":            self.scan_managed_disks,
            "virtual_networks":         self.scan_virtual_networks,
            "network_security_groups":  self.scan_nsgs,
            "public_ips":               self.scan_public_ips,
            "load_balancers":           self.scan_load_balancers,
            "storage_accounts":         self.scan_storage_accounts,
            "sql_servers":              self.scan_sql_servers,
            "key_vaults":               self.scan_key_vaults,
            "app_services":             self.scan_app_services,
            "aks_clusters":             self.scan_aks_clusters,
            "role_assignments":         self.scan_role_assignments,
        }

        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(fn): key for key, fn in scan_map.items()}
            for future in as_completed(futures):
                key = futures[future]
                found = future.result()
                results["resources"].extend(found)
                results["summary"][key] = len([r for r in found if "error" not in r])

        # Deduplicate
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
        return hashlib.sha256(raw_id.encode()).hexdigest()[:12]
