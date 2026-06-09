#!/usr/bin/env python3
"""
ICS-ZoneAudit — IEC 62443 Zone & Conduit Compliance Auditor

Reads an Nmap XML scan of an industrial network, classifies assets into
IEC 62443 security zones, checks for zone boundary and conduit violations,
scores each asset against a hardening checklist, and generates a structured
compliance audit report (JSON + HTML).

Usage:
    python ics_zoneaudit.py --input scan.xml [--config topology.yml] [--output report] [--format both] [--strict]

Author: Arnav Parekar | VIT Chennai
"""

import argparse
import sys
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Port:
    """Represents a single port discovered during an Nmap scan."""
    number: int
    protocol: str
    state: str            # 'open', 'closed', or 'filtered'
    service_name: str
    product: str = ""
    version: str = ""


@dataclass
class Asset:
    """Represents a discovered network asset (host) from an Nmap scan."""
    ip: str
    hostname: str = ""
    os_match: str = ""
    os_vendor: str = ""
    os_family: str = ""
    ports: List[Port] = field(default_factory=list)
    zone: str = "Unknown"
    sl: str = ""
    score: int = 0
    max_score: int = 15
    checks: dict = field(default_factory=dict)

    @property
    def open_ports(self) -> List[Port]:
        """Return only ports in the 'open' state."""
        return [p for p in self.ports if p.state == "open"]

    @property
    def filtered_ports(self) -> List[Port]:
        """Return only ports in the 'filtered' state."""
        return [p for p in self.ports if p.state == "filtered"]

    @property
    def open_port_numbers(self) -> set:
        """Return a set of open port numbers."""
        return {p.number for p in self.open_ports}

    def has_open_port(self, port_number: int) -> bool:
        """Check if a specific port is open on this asset."""
        return port_number in self.open_port_numbers

    @property
    def subnet_24(self) -> str:
        """Return the /24 subnet prefix for this asset's IP."""
        parts = self.ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ""


def parse_nmap_xml(filepath: str) -> tuple:
    """
    Parse an Nmap XML file and return a list of Asset objects and scan metadata.

    Tries libnmap first for a clean object model. Falls back to
    xml.etree.ElementTree (stdlib) if libnmap is unavailable.

    Returns:
        tuple: (list[Asset], dict) — assets and scan metadata
    """
    try:
        return _parse_with_libnmap(filepath)
    except ImportError:
        print("[!] libnmap not installed, falling back to xml.etree.ElementTree")
        return _parse_with_etree(filepath)
    except Exception as e:
        print(f"[!] libnmap parse error ({e}), falling back to xml.etree.ElementTree")
        return _parse_with_etree(filepath)


def _parse_with_libnmap(filepath: str) -> tuple:
    """Parse Nmap XML using the libnmap library."""
    from libnmap.parser import NmapParser

    nmap_report = NmapParser.parse_fromfile(filepath)

    metadata = {
        "target": nmap_report.commandline if nmap_report.commandline else "N/A",
        "scan_time": nmap_report.started if hasattr(nmap_report, 'started') else 0,
        "scan_end_time": nmap_report.endtime if hasattr(nmap_report, 'endtime') else 0,
        "total_hosts": len(nmap_report.hosts),
        "summary": nmap_report.summary if hasattr(nmap_report, 'summary') else "",
    }

    assets = []
    for host in nmap_report.hosts:
        if host.is_up():
            hostname = ""
            if host.hostnames:
                hostname = host.hostnames[0] if isinstance(host.hostnames[0], str) else host.hostnames[0].get("name", "")

            os_match = ""
            os_vendor = ""
            os_family = ""
            if host.os_fingerprinted and host.os_match_probabilities():
                best_match = host.os_match_probabilities()[0]
                os_match = best_match.name if hasattr(best_match, 'name') else ""
                if hasattr(best_match, 'osclasses') and best_match.osclasses:
                    os_class = best_match.osclasses[0]
                    os_vendor = os_class.vendor if hasattr(os_class, 'vendor') else ""
                    os_family = os_class.osfamily if hasattr(os_class, 'osfamily') else ""

            ports = []
            for service in host.services:
                port = Port(
                    number=service.port,
                    protocol=service.protocol,
                    state=service.state,
                    service_name=service.service if service.service else "",
                    product=service.service_dict.get("product", "") if service.service_dict else "",
                    version=service.service_dict.get("version", "") if service.service_dict else "",
                )
                ports.append(port)

            asset = Asset(
                ip=host.address,
                hostname=hostname,
                os_match=os_match,
                os_vendor=os_vendor,
                os_family=os_family,
                ports=ports,
            )
            assets.append(asset)

    return assets, metadata


def _parse_with_etree(filepath: str) -> tuple:
    """Parse Nmap XML using stdlib xml.etree.ElementTree (fallback)."""
    import xml.etree.ElementTree as ET

    tree = ET.parse(filepath)
    root = tree.getroot()

    # Extract scan metadata
    metadata = {
        "target": root.get("args", "N/A"),
        "scan_time": int(root.get("start", 0)),
        "scan_end_time": 0,
        "total_hosts": 0,
        "summary": "",
    }

    # Parse runstats if present
    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            metadata["scan_end_time"] = int(finished.get("time", 0))
            metadata["summary"] = finished.get("summary", "")
        hosts_elem = runstats.find("hosts")
        if hosts_elem is not None:
            metadata["total_hosts"] = int(hosts_elem.get("total", 0))

    assets = []
    for host_elem in root.findall("host"):
        # Check host status
        status_elem = host_elem.find("status")
        if status_elem is not None and status_elem.get("state") != "up":
            continue

        # Get IP address
        ip = ""
        for addr_elem in host_elem.findall("address"):
            if addr_elem.get("addrtype") == "ipv4":
                ip = addr_elem.get("addr", "")
                break

        if not ip:
            continue

        # Get hostname
        hostname = ""
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name", "")

        # Get OS match
        os_match = ""
        os_vendor = ""
        os_family = ""
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch_elem = os_elem.find("osmatch")
            if osmatch_elem is not None:
                os_match = osmatch_elem.get("name", "")
                osclass_elem = osmatch_elem.find("osclass")
                if osclass_elem is not None:
                    os_vendor = osclass_elem.get("vendor", "")
                    os_family = osclass_elem.get("osfamily", "")

        # Get ports
        ports = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                service_elem = port_elem.find("service")

                port = Port(
                    number=int(port_elem.get("portid", 0)),
                    protocol=port_elem.get("protocol", "tcp"),
                    state=state_elem.get("state", "unknown") if state_elem is not None else "unknown",
                    service_name=service_elem.get("name", "") if service_elem is not None else "",
                    product=service_elem.get("product", "") if service_elem is not None else "",
                    version=service_elem.get("version", "") if service_elem is not None else "",
                )
                ports.append(port)

        asset = Asset(
            ip=ip,
            hostname=hostname,
            os_match=os_match,
            os_vendor=os_vendor,
            os_family=os_family,
            ports=ports,
        )
        assets.append(asset)

    if metadata["total_hosts"] == 0:
        metadata["total_hosts"] = len(assets)

    return assets, metadata


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="ics_zoneaudit",
        description="ICS-ZoneAudit — IEC 62443 Zone & Conduit Compliance Auditor. "
                    "Parses Nmap XML scans, classifies assets into IEC 62443 security zones, "
                    "detects zone/conduit violations, and generates audit reports.",
        epilog="Example: python ics_zoneaudit.py --input scan.xml --config topology.yml --output report --format both"
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to Nmap XML scan file (required)"
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Optional YAML topology config file specifying known assets, "
             "expected zone assignments, and custom conduit rules"
    )
    parser.add_argument(
        "--output", "-o",
        default="zoneaudit_report",
        help="Output filename prefix (default: zoneaudit_report)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "html", "both"],
        default="both",
        help="Output format: json, html, or both (default: both)"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if any HIGH severity violation is found"
    )

    return parser.parse_args()


def print_assets_table(assets: list):
    """Print a formatted table of discovered assets."""
    print(f"\n{'IP Address':<18} {'Hostname':<25} {'OS Match':<30} {'Open Ports'}")
    print("-" * 100)
    for asset in assets:
        open_ports = ", ".join(
            f"{p.number}/{p.service_name}" for p in asset.open_ports
        )
        os_display = asset.os_match[:28] if asset.os_match else "N/A"
        hostname_display = asset.hostname[:23] if asset.hostname else "N/A"
        print(f"{asset.ip:<18} {hostname_display:<25} {os_display:<30} {open_ports}")


def main():
    """Main entry point for ICS-ZoneAudit."""
    args = parse_args()

    print(f"ICS-ZoneAudit v1.0")
    print(f"{'=' * 60}")
    print(f"  Input file:  {args.input}")
    print(f"  Config file: {args.config or 'None'}")
    print(f"  Output:      {args.output}")
    print(f"  Format:      {args.format}")
    print(f"  Strict mode: {args.strict}")
    print(f"{'=' * 60}")

    # Step 1: Parse Nmap XML
    print("\n[*] Parsing Nmap XML...")
    try:
        assets, metadata = parse_nmap_xml(args.input)
    except FileNotFoundError:
        print(f"[!] Error: File not found: {args.input}")
        return 1
    except Exception as e:
        print(f"[!] Error parsing Nmap XML: {e}")
        return 1

    print(f"    Found {len(assets)} hosts up")
    print_assets_table(assets)

    # Future steps (not yet implemented)
    print("\n[*] Classifying zones...         (not yet implemented)")
    print("[*] Running hardening checks...  (not yet implemented)")
    print("[*] Detecting violations...      (not yet implemented)")
    print("[*] Generating report...         (not yet implemented)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
