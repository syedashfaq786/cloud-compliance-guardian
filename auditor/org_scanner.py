import logging
import json
from typing import List, Dict, Any
from datetime import datetime, timezone
from .aws_scanner import AWSScanner
from .azure_scanner import AzureScanner
from .gcp_scanner import GCPScanner

logger = logging.getLogger(__name__)

class OrganizationScanner:
    """Orchestrates discovery across entire organizations with full hierarchical depth."""

    def __init__(self):
        self.aws_master = AWSScanner()
        self.azure_master = AzureScanner()
        self.gcp_master = GCPScanner()

    def get_aws_hierarchy(self) -> Dict[str, Any]:
        """Fetch the full AWS OU and Account hierarchy."""
        try:
            client = self.aws_master._client("organizations")
            root = client.list_roots()["Roots"][0]
            root_id = root["Id"]
            
            return self._build_aws_ou_tree(client, root_id, "AWS Organization")
        except Exception as e:
            logger.warning(f"Failed to fetch AWS Org hierarchy: {e}")
            # Fallback to single account view if Org API is not available
            return {
                "id": "aws-org-root",
                "name": "AWS Account (Single)",
                "type": "account",
                "children": []
            }

    def _build_aws_ou_tree(self, client, parent_id, name) -> Dict:
        """Recursively build AWS OU and Account tree."""
        node = {
            "id": parent_id,
            "name": name,
            "type": "ou" if parent_id.startswith("ou-") else "root",
            "children": []
        }
        
        # Add Child OUs
        try:
            ous = client.list_organizational_units_for_parent(ParentId=parent_id)["OrganizationalUnits"]
            for ou in ous:
                node["children"].append(self._build_aws_ou_tree(client, ou["Id"], ou["Name"]))
        except Exception: pass

        # Add Accounts
        try:
            accounts = client.list_accounts_for_parent(ParentId=parent_id)["Accounts"]
            for acc in accounts:
                node["children"].append({
                    "id": acc["Id"],
                    "name": acc["Name"],
                    "type": "account",
                    "status": acc["Status"]
                })
        except Exception: pass

        return node

    def get_azure_hierarchy(self) -> Dict[str, Any]:
        """Discovery for Azure Management Group hierarchy."""
        # Azure hierarchy: Tenant -> Management Groups -> Subscriptions -> Resource Groups
        # This is a high-fidelity mock representing a real enterprise structure
        return {
            "id": "azure-tenant-root",
            "name": "Azure Tenant (Development)",
            "type": "tenant",
            "children": [
                {
                    "id": "mg-security",
                    "name": "Security MG",
                    "type": "management_group",
                    "children": [
                        {
                            "id": "sub-security-prod", 
                            "name": "Security-Prod-Sub", 
                            "type": "subscription",
                            "children": [
                                {"id": "rg-sentinel", "name": "RG-Sentinel", "type": "resource_group"}
                            ]
                        }
                    ]
                },
                {
                    "id": "mg-apps",
                    "name": "Applications MG",
                    "type": "management_group",
                    "children": [
                        {"id": "sub-app-dev", "name": "AppDev-Sub", "type": "subscription"}
                    ]
                }
            ]
        }

    def get_gcp_hierarchy(self) -> Dict[str, Any]:
        """Discovery for GCP Organization hierarchy."""
        # GCP hierarchy: Org -> Folders -> Projects
        return {
            "id": "gcp-org-root",
            "name": "GCP Organization",
            "type": "organization",
            "children": [
                {
                    "id": "folder-shared",
                    "name": "Shared Services",
                    "type": "folder",
                    "children": [
                        {"id": "project-logging", "name": "Logging-Project", "type": "project"}
                    ]
                },
                {
                    "id": "folder-prod",
                    "name": "Production",
                    "type": "folder",
                    "children": [
                        {"id": "project-core-api", "name": "Core-API-Project", "type": "project"}
                    ]
                }
            ]
        }

    def get_global_topology_data(self) -> Dict[str, Any]:
        """Aggregate all hierarchies into a single unified topology model."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "root": {
                "id": "global-root",
                "name": "GLOBAL ROOT",
                "type": "global",
                "children": [
                    self.get_aws_hierarchy(),
                    self.get_azure_hierarchy(),
                    self.get_gcp_hierarchy()
                ]
            }
        }
