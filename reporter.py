"""
reporter.py — JSON + HTML Report Generation

Generates structured compliance audit reports from ICS-ZoneAudit analysis:
  - JSON report following the schema in the SRS (scan_metadata, zone_summary,
    violations, per-asset data)
  - Single-file HTML report with embedded CSS, zone topology SVG diagram,
    violations table, and per-asset scorecards

Uses Jinja2 for HTML templating with report.html.j2.
"""
