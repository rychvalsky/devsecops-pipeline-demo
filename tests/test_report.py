"""Unit tests for scripts/build_report.py (the F8 aggregator)."""

import argparse
import json
from pathlib import Path

from scripts.build_report import (
    STAGE_ORDER,
    collect,
    main,
    parse_pip_audit,
    parse_sarif,
    parse_zap,
    render_markdown,
)


def _write(path: Path, obj: object) -> str:
    path.write_text(json.dumps(obj), encoding="utf-8")
    return str(path)


def test_parse_sarif_reads_level_and_cvss(tmp_path: Path) -> None:
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "B105", "properties": {}},
                            {"id": "CVE-1", "properties": {"security-severity": "9.8"}},
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "B105",
                        "level": "error",
                        "message": {"text": "Possible hardcoded password"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/auth.py"},
                                    "region": {"startLine": 16},
                                }
                            }
                        ],
                    },
                    {"ruleId": "CVE-1", "level": "warning", "message": {"text": "bad dep"}},
                ],
            }
        ]
    }
    findings = parse_sarif(Path(_write(tmp_path / "b.sarif", sarif)), "SAST", "Bandit")

    assert [f.severity for f in findings] == [
        "HIGH",
        "CRITICAL",
    ]  # error -> HIGH, cvss 9.8 -> CRITICAL
    assert findings[0].where == "app/auth.py:16"
    assert findings[0].ident == "B105"


def test_parse_sarif_missing_file_is_empty(tmp_path: Path) -> None:
    assert parse_sarif(tmp_path / "nope.sarif", "SAST", "Bandit") == []


def test_parse_pip_audit_flattens_vulns(tmp_path: Path) -> None:
    report = {
        "dependencies": [
            {
                "name": "starlette",
                "version": "0.41.3",
                "vulns": [
                    {"id": "PYSEC-1", "fix_versions": ["1.0.1"]},
                    {"id": "PYSEC-2", "fix_versions": []},
                ],
            },
            {"name": "fastapi", "version": "0.115.6", "vulns": []},
        ]
    }
    findings = parse_pip_audit(Path(_write(tmp_path / "pa.json", report)))

    assert {f.ident for f in findings} == {"PYSEC-1", "PYSEC-2"}
    assert all(f.stage == "Dependencies" and f.severity == "N/A" for f in findings)
    assert "starlette 0.41.3" in findings[0].where
    assert findings[1].title == "fixed in none"


def test_parse_zap_maps_riskcode(tmp_path: Path) -> None:
    report = {
        "site": [
            {
                "@name": "http://localhost:8010",
                "alerts": [
                    {
                        "pluginid": "10021",
                        "alert": "X-Content-Type-Options Header Missing",
                        "riskcode": "1",
                        "count": "2",
                    },
                    {"pluginid": "40012", "alert": "XSS", "riskcode": "3", "count": "1"},
                ],
            }
        ]
    }
    findings = parse_zap(Path(_write(tmp_path / "zap.json", report)))

    assert [f.severity for f in findings] == ["LOW", "HIGH"]
    assert findings[0].where == "http://localhost:8010 (x2)"


def test_render_markdown_summary_and_totals() -> None:
    from scripts.build_report import Finding

    findings = [
        Finding("SAST", "Bandit", "B105", "HIGH", "app/auth.py:16", "hardcoded"),
        Finding("DAST", "OWASP ZAP", "10021", "LOW", "http://x (x1)", "header missing"),
    ]
    md = render_markdown(findings, STAGE_ORDER)

    assert "# Security scan report" in md
    assert "| **Total** | | **2** | **HIGH** |" in md
    assert "| Dependencies | - | _no report_ | - |" in md  # stage with no findings
    assert "## SAST — Bandit" in md
    assert "| HIGH | B105 | app/auth.py:16 | hardcoded |" in md


def test_collect_drops_exact_duplicates(tmp_path: Path) -> None:
    # A feed that lists the same advisory twice.
    report = {
        "dependencies": [
            {
                "name": "starlette",
                "version": "0.41.3",
                "vulns": [
                    {"id": "PYSEC-1", "fix_versions": ["1.0.1"]},
                    {"id": "PYSEC-1", "fix_versions": ["1.0.1"]},
                ],
            }
        ]
    }
    args = argparse.Namespace(
        bandit=None,
        pip_audit=_write(tmp_path / "pa.json", report),
        trivy_image=None,
        trivy_config=None,
        zap=None,
    )
    assert len(collect(args)) == 1


def test_main_writes_file_with_no_inputs(tmp_path: Path, capsys) -> None:
    out = tmp_path / "security-report.md"
    rc = main(["--out", str(out)])

    assert rc == 0
    assert out.exists()
    assert "# Security scan report" in out.read_text(encoding="utf-8")
    assert "0 findings" in capsys.readouterr().out
