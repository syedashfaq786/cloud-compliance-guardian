"""
HCL Parser — Multi-file Terraform directory scanner.

Recursively finds all .tf files, parses them using python-hcl2,
and groups resources by type for analysis.
"""

import os
import json
import hcl2
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class TerraformResource:
    """Represents a single Terraform resource."""
    resource_type: str
    resource_name: str
    config: Dict[str, Any]
    file_path: str
    line_number: int = 0

    @property
    def address(self) -> str:
        return f"{self.resource_type}.{self.resource_name}"


@dataclass
class ParseResult:
    """Result of parsing a Terraform directory."""
    resources: List[TerraformResource] = field(default_factory=list)
    variables: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    providers: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, str]] = field(default_factory=list)
    files_scanned: int = 0

    def resources_by_type(self) -> Dict[str, List[TerraformResource]]:
        """Group resources by their type."""
        grouped = {}
        for r in self.resources:
            grouped.setdefault(r.resource_type, []).append(r)
        return grouped

    @property
    def resource_count(self) -> int:
        return len(self.resources)

    @property
    def resource_types(self) -> List[str]:
        return list(set(r.resource_type for r in self.resources))


class HCLParser:
    """Parses Terraform HCL files from a directory."""

    TERRAFORM_EXTENSIONS = {".tf"}

    def __init__(self, directory: str):
        self.directory = Path(directory).resolve()
        if not self.directory.exists():
            raise FileNotFoundError(f"Directory not found: {self.directory}")
        if not self.directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {self.directory}")

    def find_tf_files(self) -> List[Path]:
        """Recursively find all .tf files in the directory."""
        tf_files = []
        for ext in self.TERRAFORM_EXTENSIONS:
            tf_files.extend(self.directory.rglob(f"*{ext}"))
        return sorted(tf_files)

    def parse_file(self, file_path: Path) -> Dict[str, Any]:
        """Parse a single .tf file into a Python dict."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return hcl2.load(f)
        except Exception as e:
            return {"__error__": str(e), "__file__": str(file_path)}

    def extract_resources(
        self, parsed: Dict[str, Any], file_path: str
    ) -> List[TerraformResource]:
        """Extract resource blocks from parsed HCL."""
        resources = []
        for resource_block in parsed.get("resource", []):
            for resource_type, instances in resource_block.items():
                for instance in instances if isinstance(instances, list) else [instances]:
                    for resource_name, config in instance.items():
                        resources.append(
                            TerraformResource(
                                resource_type=resource_type,
                                resource_name=resource_name,
                                config=config if isinstance(config, dict) else {},
                                file_path=file_path,
                            )
                        )
        return resources

    def extract_variables(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Extract variable blocks from parsed HCL."""
        variables = {}
        for var_block in parsed.get("variable", []):
            for var_name, var_config in var_block.items():
                variables[var_name] = var_config
        return variables

    def extract_outputs(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Extract output blocks from parsed HCL."""
        outputs = {}
        for output_block in parsed.get("output", []):
            for output_name, output_config in output_block.items():
                outputs[output_name] = output_config
        return outputs

    def extract_providers(self, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Extract provider blocks from parsed HCL."""
        providers = {}
        for provider_block in parsed.get("provider", []):
            for provider_name, provider_config in provider_block.items():
                providers[provider_name] = provider_config
        return providers

    def parse_directory(self) -> ParseResult:
        """Parse all .tf files in the directory and return a unified result."""
        result = ParseResult()
        tf_files = self.find_tf_files()
        result.files_scanned = len(tf_files)

        for tf_file in tf_files:
            parsed = self.parse_file(tf_file)
            rel_path = str(tf_file.relative_to(self.directory))

            if "__error__" in parsed:
                result.errors.append({
                    "file": rel_path,
                    "error": parsed["__error__"]
                })
                continue

            result.resources.extend(
                self.extract_resources(parsed, rel_path)
            )
            result.variables.update(self.extract_variables(parsed))
            result.outputs.update(self.extract_outputs(parsed))
            result.providers.update(self.extract_providers(parsed))

        return result

    def get_raw_content(self, file_path: str) -> str:
        """Read raw file content for a .tf file (for AI analysis)."""
        full_path = self.directory / file_path
        if full_path.exists():
            return full_path.read_text(encoding="utf-8")
        return ""


def parse_terraform(directory: str) -> ParseResult:
    """Convenience function to parse a Terraform directory."""
    parser = HCLParser(directory)
    return parser.parse_directory()
