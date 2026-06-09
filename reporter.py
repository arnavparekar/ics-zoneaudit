"""
reporter.py — JSON + HTML Report Generation

Generates structured compliance audit reports from ICS-ZoneAudit analysis:
  - JSON report following the schema in the SRS (scan_metadata, zone_summary,
    violations, per-asset data)
  - Single-file HTML report with embedded CSS, zone topology SVG diagram,
    violations table, and per-asset scorecards

Uses Jinja2 for HTML templating with report.html.j2.
"""

import json
import os
from typing import List, Dict, Any


def _build_zone_summary(assets: list) -> dict:
    """Build a summary count of assets per zone."""
    summary = {
        "Enterprise": 0,
        "DMZ": 0,
        "Control": 0,
        "Field Device": 0,
        "Unknown": 0
    }
    for asset in assets:
        if asset.zone in summary:
            summary[asset.zone] += 1
        else:
            summary["Unknown"] += 1
    
    # Remove empty zones to keep report clean
    return {k: v for k, v in summary.items() if v > 0}


def _serialize_assets(assets: list) -> List[Dict[str, Any]]:
    """Convert Asset objects to dictionaries for JSON serialization."""
    serialized = []
    for asset in assets:
        serialized.append({
            "ip": asset.ip,
            "hostname": asset.hostname,
            "os_match": asset.os_match,
            "zone": asset.zone,
            "sl": asset.sl,
            "score": asset.score,
            "max_score": asset.max_score,
            "open_ports": [p.number for p in asset.open_ports],
            "checks": asset.checks
        })
    return serialized


def _serialize_violations(violations: list) -> List[Dict[str, Any]]:
    """Convert Violation objects to dictionaries for JSON serialization."""
    serialized = []
    for v in violations:
        serialized.append({
            "violation_id": v.violation_id,
            "severity": v.severity,
            "type": v.type,
            "description": v.description,
            "affected_assets": v.affected_assets,
            "iec_reference": v.iec_reference
        })
    return serialized


def generate_json_report(assets: list, violations: list, metadata: dict, output_prefix: str) -> str:
    """
    Generate a JSON report of the audit results.
    
    Args:
        assets: List of classified and scored Asset objects
        violations: List of detected Violation objects
        metadata: Scan metadata dict
        output_prefix: Base filename for the output file
        
    Returns:
        str: Path to the generated JSON file
    """
    report = {
        "scan_metadata": metadata,
        "zone_summary": _build_zone_summary(assets),
        "violations": _serialize_violations(violations),
        "assets": _serialize_assets(assets)
    }
    
    output_path = f"{output_prefix}.json"
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        
    return output_path

