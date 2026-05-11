"""
Directory Audit Module — Semantic Intent Scanner v0.3

Scans a skill directory for attack surfaces beyond SKILL.md.

The semantic evaluator reads the right files for the wrong threat model
if it only reads SKILL.md. This module addresses the two documented
attack surfaces the semantic layer misses:

1. Bundled test files (*.test.ts, *.spec.js, conftest.py)
   Documented by Gecko Security researcher Jeevan Jutla, May 2026.
   Test files execute via Jest/Vitest/pytest with full local permissions.
   No agent is invoked. The payload fires in beforeAll() silently.

2. Project-scoped config files (.mcp.json, .claude/settings.json)
   Documented by Adversa AI TrustFall disclosure, May 2026 (CVE pending).
   Config files can silently enable attacker-controlled MCP servers
   when a developer trusts a cloned repo directory.

Neither attack surface is inspected by any publicly documented scanner
as of May 2026.
"""

import json
import re
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# File classification
# ---------------------------------------------------------------------------

# Files that should never exist in a skill directory
SUSPICIOUS_PATTERNS = [
    "*.test.ts",
    "*.test.js",
    "*.test.py",
    "*.spec.ts",
    "*.spec.js",
    "*.spec.py",
    "conftest.py",
    "jest.config.*",
    "vitest.config.*",
    "*.config.ts",
    "*.config.js",
    "*.config.py",
]

# Directories that indicate bundled test infrastructure
SUSPICIOUS_DIRS = [
    "__tests__",
    "__pycache__",
    "node_modules",
    ".github",
]

# Config files that can silently enable MCP servers or override permissions
CONFIG_FILES = [
    ".mcp.json",
    ".claude/settings.json",
    ".cursor/settings.json",
    ".agents/settings.json",
    "settings.json",
]

# Patterns indicating dangerous operations in non-instruction files
DANGEROUS_PATTERNS = {
    "credential_access": [
        r"process\.env",
        r"os\.environ",
        r"~\/\.ssh",
        r"~\/\.aws",
        r"~\/\.config",
        r"id_rsa",
        r"credentials",
        r"api[_\s]?key",
        r"secret",
        r"token",
        r"password",
        r"\.env",
    ],
    "network_exfiltration": [
        r"fetch\s*\(",
        r"axios\.",
        r"http\.get",
        r"http\.post",
        r"requests\.get",
        r"requests\.post",
        r"curl",
        r"wget",
        r"socket\.",
        r"net\.",
    ],
    "shell_execution": [
        r"child_process",
        r"exec\s*\(",
        r"spawn\s*\(",
        r"eval\s*\(",
        r"subprocess",
        r"os\.system",
        r"shell=True",
        r"\|\s*bash",
        r"\|\s*sh",
    ],
    "filesystem_access": [
        r"fs\.read",
        r"fs\.write",
        r"open\s*\(",
        r"readFile",
        r"writeFile",
        r"glob\s*\(",
        r"find\s+/",
        r"Path\s*\(",
    ],
}

# MCP config settings that enable dangerous behavior
DANGEROUS_MCP_SETTINGS = [
    "enableAllProjectMcpServers",
    "enabledMcpjsonServers",
    "bypassPermissions",
    "permissions.allow",
    "allowedTools",
]


# ---------------------------------------------------------------------------
# Audit functions
# ---------------------------------------------------------------------------

def audit_directory(skill_dir: str | Path) -> dict[str, Any]:
    """
    Perform a full directory audit of a skill package.
    Returns findings across all non-instruction attack surfaces.
    """
    skill_path = Path(skill_dir)

    if not skill_path.exists():
        return {"error": f"Directory not found: {skill_dir}"}

    if not skill_path.is_dir():
        return {"error": f"Not a directory: {skill_dir}"}

    findings = {
        "directory": str(skill_path),
        "suspicious_files": [],
        "config_findings": [],
        "overall_directory_risk": "low",
    }

    # Scan for suspicious files
    for pattern in SUSPICIOUS_PATTERNS:
        for match in skill_path.rglob(pattern):
            if _is_excluded(match):
                continue
            file_findings = _audit_file(match)
            findings["suspicious_files"].append(file_findings)

    # Scan for suspicious directories
    for dir_name in SUSPICIOUS_DIRS:
        for match in skill_path.rglob(dir_name):
            if match.is_dir():
                findings["suspicious_files"].append({
                    "path": str(match.relative_to(skill_path)),
                    "type": "suspicious_directory",
                    "risk": "medium",
                    "reason": f"Directory '{dir_name}' has no legitimate purpose in a skill package.",
                    "dangerous_patterns": [],
                })

    # Scan config files
    for config_name in CONFIG_FILES:
        config_path = skill_path / config_name
        if config_path.exists():
            config_findings = _audit_config(config_path, skill_path)
            if config_findings:
                findings["config_findings"].append(config_findings)

    # Calculate overall directory risk
    findings["overall_directory_risk"] = _calculate_directory_risk(findings)

    return findings


def _is_excluded(path: Path) -> bool:
    """Exclude paths that are clearly not part of the skill package."""
    excluded = {".git", "node_modules", "__pycache__", ".venv", "venv"}
    return any(part in excluded for part in path.parts)


def _audit_file(file_path: Path) -> dict[str, Any]:
    """Audit a single suspicious file for dangerous patterns."""
    finding = {
        "path": str(file_path),
        "type": _classify_file(file_path),
        "risk": "medium",
        "reason": _explain_file_risk(file_path),
        "dangerous_patterns": [],
    }

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        patterns_found = _scan_content(content)
        finding["dangerous_patterns"] = patterns_found

        if patterns_found:
            # Escalate risk if dangerous patterns found
            categories = [p["category"] for p in patterns_found]
            if "network_exfiltration" in categories and "credential_access" in categories:
                finding["risk"] = "critical"
                finding["reason"] += " Contains both credential access and network exfiltration patterns — consistent with data theft."
            elif "network_exfiltration" in categories or "credential_access" in categories:
                finding["risk"] = "high"
                finding["reason"] += f" Contains {', '.join(set(categories))} patterns."
            elif patterns_found:
                finding["risk"] = "medium"
                finding["reason"] += f" Contains {', '.join(set(categories))} patterns."

    except (IOError, OSError):
        finding["reason"] += " (Could not read file contents.)"

    return finding


def _classify_file(file_path: Path) -> str:
    """Classify a file by its role in the attack surface."""
    name = file_path.name.lower()
    suffix = file_path.suffix.lower()

    if "conftest" in name:
        return "pytest_plugin"
    if ".test." in name or ".spec." in name:
        return "test_file"
    if "jest.config" in name or "vitest.config" in name:
        return "test_runner_config"
    if suffix in (".json",):
        return "config_file"
    return "suspicious_file"


def _explain_file_risk(file_path: Path) -> str:
    """Generate a human-readable explanation of why this file is suspicious."""
    file_type = _classify_file(file_path)

    explanations = {
        "pytest_plugin": (
            "conftest.py is auto-executed by pytest during test collection. "
            "Code in this file runs before any tests, with full local permissions, "
            "whether or not the tests pass."
        ),
        "test_file": (
            "Test files are auto-discovered by Jest, Vitest, and Mocha via recursive "
            "glob patterns. Code in beforeAll() blocks executes silently during test "
            "runs, with full access to environment variables and the filesystem."
        ),
        "test_runner_config": (
            "Test runner config files can override glob patterns, add setup files, "
            "and configure execution hooks — potentially enabling malicious code "
            "to run during legitimate test operations."
        ),
        "config_file": (
            "Configuration files can override security settings, enable MCP servers, "
            "and modify agent behavior without explicit user consent."
        ),
        "suspicious_directory": (
            "This directory type has no legitimate purpose inside a skill package."
        ),
    }

    return explanations.get(file_type, "This file type has no legitimate purpose in a skill package.")


def _scan_content(content: str) -> list[dict]:
    """Scan file content for dangerous operation patterns."""
    findings = []
    seen = set()

    for category, patterns in DANGEROUS_PATTERNS.items():
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                key = f"{category}:{pattern}"
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "category": category,
                        "pattern": pattern,
                        "match_count": len(matches),
                    })

    return findings


def _audit_config(config_path: Path, skill_path: Path) -> dict[str, Any] | None:
    """Audit a config file for dangerous MCP or permission settings."""
    finding = {
        "path": str(config_path.relative_to(skill_path)),
        "type": "config_file",
        "risk": "medium",
        "dangerous_settings": [],
        "reason": "",
    }

    try:
        content = config_path.read_text(encoding="utf-8", errors="ignore")

        # Check for dangerous MCP settings
        dangerous_found = []
        for setting in DANGEROUS_MCP_SETTINGS:
            if setting in content:
                dangerous_found.append(setting)

        if dangerous_found:
            finding["dangerous_settings"] = dangerous_found
            finding["risk"] = "high"
            finding["reason"] = (
                f"Config file contains settings that can silently enable "
                f"attacker-controlled MCP servers or bypass permission checks: "
                f"{', '.join(dangerous_found)}. "
                f"Documented attack vector: TrustFall (Adversa AI, May 2026)."
            )
            return finding

        # Even without dangerous settings, flag the presence of config files
        finding["reason"] = (
            "Config file present in skill package. Review manually to verify "
            "no MCP servers are enabled or permissions modified without explicit "
            "user consent."
        )
        finding["risk"] = "low"
        return finding

    except (IOError, OSError, json.JSONDecodeError):
        return None


def _calculate_directory_risk(findings: dict) -> str:
    """Calculate overall directory risk from all findings."""
    risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    max_risk = 0

    for file_finding in findings.get("suspicious_files", []):
        risk = risk_order.get(file_finding.get("risk", "low"), 0)
        max_risk = max(max_risk, risk)

    for config_finding in findings.get("config_findings", []):
        risk = risk_order.get(config_finding.get("risk", "low"), 0)
        max_risk = max(max_risk, risk)

    return ["low", "medium", "high", "critical"][max_risk]
