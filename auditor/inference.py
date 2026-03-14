"""
Inference Wrapper — Chain-of-Thought prompting to Cisco Sec-8B via Ollama/vLLM.

Constructs structured prompts embedding Terraform configs + CIS rules,
sends to a local model endpoint, and parses JSON responses.
"""

import json
import os
import time
import requests
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from .cis_rules import CISRule, get_rules_for_resource_type, Severity
from .parser import TerraformResource


@dataclass
class ViolationFinding:
    """A single compliance violation found by the model."""
    rule_id: str
    rule_title: str
    severity: str
    resource_address: str
    resource_type: str
    file_path: str
    description: str
    remediation_hcl: str = ""
    reasoning: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "resource_address": self.resource_address,
            "resource_type": self.resource_type,
            "file_path": self.file_path,
            "description": self.description,
            "remediation_hcl": self.remediation_hcl,
            "reasoning": self.reasoning,
            "confidence": self.confidence,
        }


SYSTEM_PROMPT = """You are a senior cloud security engineer specializing in CIS Benchmark compliance auditing for AWS Terraform infrastructure.

YOUR ROLE:
- Analyze Terraform resource configurations for CIS Benchmark violations
- Provide specific CIS rule IDs for each finding
- Generate valid, copy-paste-ready HCL remediation code
- Use chain-of-thought reasoning to explain your analysis
- Distinguish between legitimately open services and actual security holes

OUTPUT FORMAT:
You MUST respond with valid JSON only. No markdown, no explanation outside JSON.
{
  "violations": [
    {
      "rule_id": "CIS rule ID (e.g., 4.1)",
      "rule_title": "Short title of the CIS rule",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "resource_address": "resource_type.resource_name",
      "description": "What is wrong and why it matters",
      "reasoning": "Step-by-step reasoning of your analysis",
      "remediation_hcl": "Complete HCL code block to fix the issue",
      "confidence": 0.95
    }
  ],
  "summary": "Brief overall assessment",
  "compliant_resources": ["list of resources that passed all checks"]
}"""


class InferenceClient:
    """Client for communicating with the Sec-8B model via Ollama or vLLM."""

    BACKEND_OLLAMA = "ollama"
    BACKEND_VLLM = "vllm"

    def __init__(
        self,
        endpoint: Optional[str] = None,
        model: Optional[str] = None,
        backend: Optional[str] = None,
        timeout: int = 120,
        max_retries: int = 3,
    ):
        self.endpoint = endpoint or os.getenv("SEC8B_ENDPOINT", "http://localhost:11434")
        self.model = model or os.getenv("SEC8B_MODEL", "cisco-sec-8b")
        self.backend = backend or os.getenv("SEC8B_BACKEND", self.BACKEND_OLLAMA)
        self.timeout = timeout
        self.max_retries = max_retries

    def _build_analysis_prompt(
        self,
        resource: TerraformResource,
        applicable_rules: List[CISRule],
        raw_hcl: str = "",
    ) -> str:
        rules_context = "\n".join([
            f"  - {r.display_id}: {r.title}\n"
            f"    Description: {r.description}\n"
            f"    Severity: {r.severity.value}\n"
            f"    Remediation Hint: {r.remediation_hint}"
            for r in applicable_rules
        ])

        config_json = json.dumps(resource.config, indent=2, default=str)

        prompt = (
            "ANALYZE THE FOLLOWING TERRAFORM RESOURCE FOR CIS BENCHMARK COMPLIANCE.\n\n"
            f"RESOURCE: {resource.address}\n"
            f"TYPE: {resource.resource_type}\n"
            f"FILE: {resource.file_path}\n\n"
            f"RESOURCE CONFIGURATION:\n```json\n{config_json}\n```\n"
        )

        if raw_hcl:
            prompt += f"\nRAW HCL SOURCE:\n```hcl\n{raw_hcl}\n```\n"

        prompt += (
            f"\nAPPLICABLE CIS BENCHMARK RULES:\n{rules_context}\n\n"
            "INSTRUCTIONS:\n"
            "1. Think step-by-step about each applicable CIS rule\n"
            "2. Check if the resource configuration violates each rule\n"
            "3. Consider context — an open port 443 for web is different from open port 22\n"
            "4. For each violation, provide the CIS rule ID, description, reasoning, and remediation HCL\n"
            "5. If the resource is compliant, say so explicitly\n\n"
            "Respond with valid JSON only."
        )
        return prompt

    def _build_batch_prompt(
        self,
        resources: List[TerraformResource],
        rules_map: Dict[str, List[CISRule]],
    ) -> str:
        sections = []
        for resource in resources:
            applicable_rules = rules_map.get(resource.resource_type, [])
            config_json = json.dumps(resource.config, indent=2, default=str)
            rules_text = ", ".join([f"{r.display_id}" for r in applicable_rules])
            sections.append(
                f"### {resource.address} (File: {resource.file_path})\n"
                f"Type: {resource.resource_type}\n"
                f"Applicable Rules: {rules_text}\n"
                f"Config:\n```json\n{config_json}\n```"
            )

        return (
            "BATCH TERRAFORM CIS BENCHMARK COMPLIANCE AUDIT\n\n"
            "Analyze ALL of the following resources for CIS Benchmark violations.\n\n"
            + "\n\n".join(sections)
            + "\n\nFor each violation, include resource_address.\n"
            "Think step-by-step. Respond with valid JSON only."
        )

    def _call_ollama(self, user_prompt: str) -> str:
        url = f"{self.endpoint}/api/generate"
        payload = {
            "model": self.model,
            "prompt": user_prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 4096,
            },
        }
        response = requests.post(url, json=payload, timeout=self.timeout)
        response.raise_for_status()
        return response.json().get("response", "{}")

    def _call_vllm(self, user_prompt: str) -> str:
        url = f"{self.endpoint}/v1/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
            "top_p": 0.9,
            "max_tokens": 4096,
        }
        response = requests.post(url, json=payload, timeout=self.timeout)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def _call_model(self, prompt: str) -> str:
        if self.backend == self.BACKEND_VLLM:
            return self._call_vllm(prompt)
        return self._call_ollama(prompt)

    def _parse_response(self, raw_response: str) -> Dict[str, Any]:
        """Parse the model's JSON response with error recovery."""
        # Try direct JSON parse
        try:
            return json.loads(raw_response)
        except json.JSONDecodeError:
            pass

        # Try extracting JSON from markdown code block
        if "```json" in raw_response:
            start = raw_response.index("```json") + 7
            end = raw_response.index("```", start)
            try:
                return json.loads(raw_response[start:end].strip())
            except (json.JSONDecodeError, ValueError):
                pass

        # Try extracting first { ... } block
        try:
            start = raw_response.index("{")
            depth = 0
            for i in range(start, len(raw_response)):
                if raw_response[i] == "{":
                    depth += 1
                elif raw_response[i] == "}":
                    depth -= 1
                    if depth == 0:
                        return json.loads(raw_response[start : i + 1])
        except (ValueError, json.JSONDecodeError):
            pass

        return {"violations": [], "summary": "Failed to parse model response", "raw": raw_response}

    def _response_to_findings(
        self, parsed: Dict[str, Any], resource: Optional[TerraformResource] = None
    ) -> List[ViolationFinding]:
        findings = []
        for v in parsed.get("violations", []):
            findings.append(
                ViolationFinding(
                    rule_id=v.get("rule_id", "unknown"),
                    rule_title=v.get("rule_title", ""),
                    severity=v.get("severity", "MEDIUM"),
                    resource_address=v.get("resource_address", resource.address if resource else "unknown"),
                    resource_type=v.get("resource_type", resource.resource_type if resource else "unknown"),
                    file_path=v.get("file_path", resource.file_path if resource else "unknown"),
                    description=v.get("description", ""),
                    remediation_hcl=v.get("remediation_hcl", ""),
                    reasoning=v.get("reasoning", ""),
                    confidence=v.get("confidence", 0.0),
                )
            )
        return findings

    def analyze_resource(
        self,
        resource: TerraformResource,
        raw_hcl: str = "",
    ) -> List[ViolationFinding]:
        """Analyze a single resource for CIS compliance violations."""
        applicable_rules = get_rules_for_resource_type(resource.resource_type)
        if not applicable_rules:
            return []

        prompt = self._build_analysis_prompt(resource, applicable_rules, raw_hcl)

        for attempt in range(self.max_retries):
            try:
                raw = self._call_model(prompt)
                parsed = self._parse_response(raw)
                return self._response_to_findings(parsed, resource)
            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries - 1:
                    return [
                        ViolationFinding(
                            rule_id="ERROR",
                            rule_title="Inference Error",
                            severity="INFO",
                            resource_address=resource.address,
                            resource_type=resource.resource_type,
                            file_path=resource.file_path,
                            description=f"Failed to analyze: {str(e)}",
                        )
                    ]
                time.sleep(2 ** attempt)

        return []

    def analyze_batch(
        self,
        resources: List[TerraformResource],
        batch_size: int = 5,
    ) -> List[ViolationFinding]:
        """Analyze multiple resources in batches."""
        all_findings = []
        rules_map = {}
        for resource in resources:
            if resource.resource_type not in rules_map:
                rules_map[resource.resource_type] = get_rules_for_resource_type(
                    resource.resource_type
                )

        # Filter to resources with applicable rules
        auditable = [r for r in resources if rules_map.get(r.resource_type)]

        for i in range(0, len(auditable), batch_size):
            batch = auditable[i : i + batch_size]
            prompt = self._build_batch_prompt(batch, rules_map)

            for attempt in range(self.max_retries):
                try:
                    raw = self._call_model(prompt)
                    parsed = self._parse_response(raw)
                    all_findings.extend(self._response_to_findings(parsed))
                    break
                except requests.exceptions.RequestException:
                    if attempt == self.max_retries - 1:
                        for r in batch:
                            all_findings.append(
                                ViolationFinding(
                                    rule_id="ERROR",
                                    rule_title="Inference Error",
                                    severity="INFO",
                                    resource_address=r.address,
                                    resource_type=r.resource_type,
                                    file_path=r.file_path,
                                    description="Batch analysis failed after retries",
                                )
                            )
                    time.sleep(2 ** attempt)

        return all_findings

    def health_check(self) -> bool:
        """Check if the model endpoint is reachable."""
        try:
            if self.backend == self.BACKEND_OLLAMA:
                r = requests.get(f"{self.endpoint}/api/tags", timeout=5)
            else:
                r = requests.get(f"{self.endpoint}/v1/models", timeout=5)
            return r.status_code == 200
        except requests.exceptions.RequestException:
            return False
