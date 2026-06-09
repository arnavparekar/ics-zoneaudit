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


def generate_zone_svg(assets: list, violations: list) -> str:
    """
    Generate an inline SVG string representing the zone topology (Purdue model).
    Draws boxes for Enterprise, DMZ, Control, and Field zones.
    Conduit lines are drawn between them, colored red if boundary violations exist.
    """
    # Check for specific violations to color the conduits
    has_field_ent_conduit = any(v.type == "Direct field-to-enterprise conduit" for v in violations)
    has_ent_dmz_violation = any(v.type == "ICS protocol on enterprise asset" for v in violations)
    has_ot_exposure = any(v.type in ["Enterprise protocol on OT network", "Remote desktop on field device"] for v in violations)
    
    # Colors
    c_normal = "#3b82f6"  # Blue
    c_violation = "#ef4444"  # Red
    c_box_bg = "rgba(30, 34, 53, 0.8)"
    c_text = "#e2e8f0"
    
    # Base conduit colors
    ent_dmz_color = c_violation if has_ent_dmz_violation else c_normal
    dmz_ctrl_color = c_violation if has_ot_exposure else c_normal
    ctrl_field_color = c_violation if has_ot_exposure else c_normal
    
    svg = [
        '<svg viewBox="0 0 800 450" xmlns="http://www.w3.org/2000/svg">',
        '  <defs>',
        '    <linearGradient id="boxGrad" x1="0%" y1="0%" x2="100%" y2="100%">',
        '      <stop offset="0%" stop-color="rgba(59, 130, 246, 0.1)" />',
        '      <stop offset="100%" stop-color="rgba(30, 34, 53, 0.4)" />',
        '    </linearGradient>',
        '  </defs>'
    ]
    
    # Helper to draw a zone box
    def draw_zone(y, title, sl, count):
        return f'''
        <g transform="translate(150, {y})">
            <rect width="500" height="60" rx="8" fill="url(#boxGrad)" stroke="{c_normal}" stroke-width="2"/>
            <text x="20" y="36" fill="{c_text}" font-family="monospace" font-size="18" font-weight="bold">{title}</text>
            <text x="480" y="36" fill="#94a3b8" font-family="monospace" font-size="14" text-anchor="end">SL: {sl} | Assets: {count}</text>
        </g>
        '''
        
    counts = _build_zone_summary(assets)
    
    # Draw standard vertical conduits
    svg.append(f'  <line x1="400" y1="110" x2="400" y2="150" stroke="{ent_dmz_color}" stroke-width="4" stroke-dasharray="4"/>')
    svg.append(f'  <line x1="400" y1="210" x2="400" y2="250" stroke="{dmz_ctrl_color}" stroke-width="4" stroke-dasharray="4"/>')
    svg.append(f'  <line x1="400" y1="310" x2="400" y2="350" stroke="{ctrl_field_color}" stroke-width="4" stroke-dasharray="4"/>')
    
    # Draw illegal bypass conduit if detected
    if has_field_ent_conduit:
        svg.append(f'  <path d="M 150 80 C 50 80, 50 380, 150 380" fill="none" stroke="{c_violation}" stroke-width="4" stroke-dasharray="8"/>')
        svg.append(f'  <text x="30" y="230" fill="{c_violation}" font-family="monospace" font-size="12" transform="rotate(-90 40,230)">VIOLATION: DIRECT CONDUIT</text>')

    # Draw Zone Boxes
    svg.append(draw_zone(50, "Enterprise Zone", "SL1", counts.get("Enterprise", 0)))
    svg.append(draw_zone(150, "DMZ", "SL2", counts.get("DMZ", 0)))
    svg.append(draw_zone(250, "Control Zone", "SL2/3", counts.get("Control", 0)))
    svg.append(draw_zone(350, "Field Device Zone", "SL2/3", counts.get("Field Device", 0)))
    
    svg.append('</svg>')
    return "\n".join(svg)


def generate_html_report(assets: list, violations: list, metadata: dict, output_prefix: str) -> str:
    """
    Generate a single-file HTML report with Jinja2.
    """
    from jinja2 import Environment, FileSystemLoader
    
    env = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")))
    template = env.get_template("report.html.j2")
    
    zone_summary = _build_zone_summary(assets)
    svg_diagram = generate_zone_svg(assets, violations)
    
    html_content = template.render(
        scan_metadata=metadata,
        zone_summary=zone_summary,
        violations=violations,
        assets=assets,
        svg_diagram=svg_diagram
    )
    
    output_path = f"{output_prefix}.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    return output_path


