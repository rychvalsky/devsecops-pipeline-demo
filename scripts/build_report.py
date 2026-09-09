"""Merge every scanner's output into one Markdown security report.

Each pipeline stage drops a machine-readable file (SARIF or JSON). This script
reads whichever of them are present and renders:

  * a summary table (stage -> finding count -> highest severity), and
  * a per-stage table of the individual findings.

Only the standard library is used, so it runs anywhere with no install step.
Missing inputs are skipped, not fatal -- a stage may not have produced its
artifact.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# Severity ordering, worst first.
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "N/A": -1}

_SARIF_LEVEL_TO_SEVERITY = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
_ZAP_RISKCODE_TO_SEVERITY = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}


@dataclass(frozen=True)
class Finding:
    stage: str
    tool: str
    ident: str
    severity: str
    where: str
    title: str


def _load_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _cvss_to_severity(score: str | float | None) -> str | None:
    try:
        value = float(score)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return "CRITICAL"
    if value >= 7.0:
        return "HIGH"
    if value >= 4.0:
        return "MEDIUM"
    return "LOW"


def parse_sarif(path: Path, stage: str, tool: str) -> list[Finding]:
    """Pull findings out of a SARIF 2.1.0 document (Bandit, Trivy)."""
    data = _load_json(path)
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []
    for run in data.get("runs", []):
        # Map ruleId -> the rule's CVSS score, if the tool recorded one.
        rule_cvss: dict[str, str | None] = {}
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            props = rule.get("properties", {})
            rule_cvss[rule.get("id", "")] = props.get("security-severity")

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "?")
            severity = _cvss_to_severity(rule_cvss.get(rule_id)) or _SARIF_LEVEL_TO_SEVERITY.get(
                result.get("level", "warning"), "MEDIUM"
            )
            locations = result.get("locations", [])
            where = ""
            if locations:
                phys = locations[0].get("physicalLocation", {})
                where = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine")
                if where and line:
                    where = f"{where}:{line}"
            message = result.get("message", {}).get("text", "").strip().splitlines()
            findings.append(
                Finding(
                    stage=stage,
                    tool=tool,
                    ident=rule_id,
                    severity=severity,
                    where=where or "-",
                    title=message[0] if message else rule_id,
                )
            )
    return findings


def parse_pip_audit(path: Path) -> list[Finding]:
    """pip-audit JSON: {"dependencies": [{name, version, vulns: [...]}]}."""
    data = _load_json(path)
    deps = data.get("dependencies", []) if isinstance(data, dict) else data
    if not isinstance(deps, list):
        return []

    findings: list[Finding] = []
    for dep in deps:
        name = dep.get("name", "?")
        version = dep.get("version", "?")
        for vuln in dep.get("vulns", []):
            fix = ", ".join(vuln.get("fix_versions", [])) or "none"
            findings.append(
                Finding(
                    stage="Dependencies",
                    tool="pip-audit",
                    ident=vuln.get("id", "?"),
                    severity="N/A",  # pip-audit JSON carries no severity
                    where=f"{name} {version}",
                    title=f"fixed in {fix}",
                )
            )
    return findings


def parse_zap(path: Path) -> list[Finding]:
    """ZAP baseline report_json.json: {"site": [{"alerts": [...]}]}."""
    data = _load_json(path)
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []
    for site in data.get("site", []):
        target = site.get("@name", "")
        for alert in site.get("alerts", []):
            findings.append(
                Finding(
                    stage="DAST",
                    tool="OWASP ZAP",
                    ident=str(alert.get("pluginid", "?")),
                    severity=_ZAP_RISKCODE_TO_SEVERITY.get(str(alert.get("riskcode", "0")), "INFO"),
                    where=f"{target} (x{alert.get('count', '?')})",
                    title=alert.get("alert", "").strip(),
                )
            )
    return findings


def _highest(findings: Iterable[Finding]) -> str:
    best = max((SEVERITY_RANK.get(f.severity, -1) for f in findings), default=-1)
    for name, rank in SEVERITY_RANK.items():
        if rank == best:
            return name
    return "-"


def _sort_key(f: Finding) -> tuple[int, str, str]:
    return (-SEVERITY_RANK.get(f.severity, -1), f.where, f.ident)


# Which tool owns each stage, for the rows that have zero findings.
STAGE_TOOLS = {
    "SAST": "Bandit",
    "Dependencies": "pip-audit",
    "Image (packages)": "Trivy",
    "Image (config)": "Trivy",
    "DAST": "OWASP ZAP",
}


def render_markdown(
    findings: list[Finding], stage_order: list[str], attempted: set[str] | None = None
) -> str:
    attempted = attempted if attempted is not None else set(stage_order)
    by_stage: dict[str, list[Finding]] = {}
    for f in findings:
        by_stage.setdefault(f.stage, []).append(f)

    lines = ["# Security scan report", "", "_Generated from CI artifacts._", "", "## Summary", ""]
    lines += ["| Stage | Tool | Findings | Highest severity |", "|---|---|---:|---|"]
    for stage in stage_order:
        group = by_stage.get(stage)
        if group:
            tools = ", ".join(sorted({f.tool for f in group}))
            lines.append(f"| {stage} | {tools} | {len(group)} | {_highest(group)} |")
        elif stage in attempted:
            lines.append(f"| {stage} | {STAGE_TOOLS.get(stage, '-')} | 0 | clean |")
        else:
            lines.append(f"| {stage} | - | _not run_ | - |")
    lines.append(f"| **Total** | | **{len(findings)}** | **{_highest(findings)}** |")

    for stage in stage_order:
        group = by_stage.get(stage)
        if not group:
            continue
        tools = ", ".join(sorted({f.tool for f in group}))
        lines += [
            "",
            f"## {stage} — {tools}",
            "",
            "| Severity | ID | Where | Detail |",
            "|---|---|---|---|",
        ]
        for f in sorted(group, key=_sort_key):
            lines.append(f"| {f.severity} | {f.ident} | {f.where} | {f.title} |")

    return "\n".join(lines) + "\n"


def collect(args: argparse.Namespace) -> tuple[list[Finding], set[str]]:
    """Return (findings, attempted-stages). A stage counts as attempted when its
    input path was given and the file exists -- so "ran, found nothing" reads
    differently from "did not run"."""
    findings: list[Finding] = []
    attempted: set[str] = set()
    plan = [
        (args.bandit, "SAST", lambda p: parse_sarif(p, "SAST", "Bandit")),
        (args.pip_audit, "Dependencies", parse_pip_audit),
        (
            args.trivy_image,
            "Image (packages)",
            lambda p: parse_sarif(p, "Image (packages)", "Trivy"),
        ),
        (args.trivy_config, "Image (config)", lambda p: parse_sarif(p, "Image (config)", "Trivy")),
        (args.zap, "DAST", parse_zap),
    ]
    for raw_path, stage, parse in plan:
        if not raw_path:
            continue
        path = Path(raw_path)
        if not path.is_file():
            continue
        attempted.add(stage)
        findings += parse(path)
    # Feeds sometimes list the same advisory twice (e.g. once per alias); a
    # Finding is a frozen dataclass, so dict.fromkeys drops exact duplicates
    # while keeping order.
    return list(dict.fromkeys(findings)), attempted


STAGE_ORDER = ["SAST", "Dependencies", "Image (packages)", "Image (config)", "DAST"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bandit", help="Bandit SARIF file")
    parser.add_argument("--pip-audit", dest="pip_audit", help="pip-audit JSON file")
    parser.add_argument("--trivy-image", dest="trivy_image", help="Trivy image SARIF file")
    parser.add_argument("--trivy-config", dest="trivy_config", help="Trivy config SARIF file")
    parser.add_argument("--zap", help="ZAP baseline report_json.json")
    parser.add_argument("--out", default="security-report.md", help="output Markdown path")
    args = parser.parse_args(argv)

    findings, attempted = collect(args)
    report = render_markdown(findings, STAGE_ORDER, attempted)
    Path(args.out).write_text(report, encoding="utf-8")
    print(f"Wrote {args.out}: {len(findings)} findings, highest {_highest(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
