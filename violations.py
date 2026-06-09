"""
violations.py — Cross-Zone Conduit Violation Detection

Detects zone boundary violations and unexpected cross-zone communication
paths as defined by IEC 62443-3-2. A conduit is a communication path
between two zones; IEC 62443 requires each conduit to be explicitly
defined, controlled, and secured.

Violation types detected:
  - Dual-homed assets (appearing in multiple zones)
  - Direct field-device-to-enterprise conduits (no DMZ in between)
  - ICS protocol exposure on enterprise assets
  - SMB/RDP on control or field device networks
  - Missing firewall evidence
  - Unexpected cross-zone service exposure
"""

from dataclasses import dataclass, field
from typing import List, Optional


# ICS protocol ports
ICS_PROTOCOL_PORTS = {502, 20000, 102}  # Modbus, DNP3, S7comm

# Port-to-service name mapping
PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    102: "S7comm",
    111: "RPC",
    161: "SNMP",
    443: "HTTPS",
    445: "SMB",
    502: "Modbus",
    3389: "RDP",
    4840: "OPC UA",
    20000: "DNP3",
    44818: "EtherNet/IP",
}


@dataclass
class Violation:
    """Represents a single zone boundary or conduit violation."""
    violation_id: str
    severity: str         # 'HIGH', 'MEDIUM', or 'LOW'
    type: str
    description: str
    affected_assets: List[str]
    iec_reference: str


def _get_service_name(port_num: int) -> str:
    """Get human-readable service name for a port number."""
    return PORT_SERVICE_MAP.get(port_num, f"port {port_num}")


def _next_violation_id(violations: list) -> str:
    """Generate the next sequential violation ID."""
    return f"V-{len(violations) + 1:03d}"


def detect_dual_homed_assets(assets: list, violations: list) -> list:
    """
    Detect assets that show characteristics of being dual-homed
    (present in multiple zones simultaneously).

    An asset is flagged if it has both strong enterprise indicators
    (RDP, SMB) AND ICS/control indicators (ICS protocols or control
    hostname patterns).

    Severity: HIGH — dual-homed assets bypass zone isolation.
    """
    control_keywords = ["hmi", "scada", "dcs", "engineering", "eng-workstation"]

    for asset in assets:
        open_ports = asset.open_port_numbers
        hostname_lower = asset.hostname.lower() if asset.hostname else ""

        has_enterprise = bool(open_ports & {3389, 445})
        has_control = bool(
            open_ports & {44818, 4840, 502, 20000, 102} or
            any(kw in hostname_lower for kw in control_keywords)
        )

        if has_enterprise and has_control:
            enterprise_services = [_get_service_name(p) for p in open_ports & {3389, 445}]
            ics_services = [_get_service_name(p) for p in open_ports & {44818, 4840, 502, 20000, 102}]

            violations.append(Violation(
                violation_id=_next_violation_id(violations),
                severity="HIGH",
                type="Dual-homed asset",
                description=(
                    f"Host {asset.ip} ({asset.hostname or 'unknown'}) in {asset.zone} zone "
                    f"has both enterprise services ({', '.join(enterprise_services)}) and "
                    f"ICS protocols ({', '.join(ics_services)}) — violates zone isolation"
                ),
                affected_assets=[asset.ip],
                iec_reference="IEC 62443-3-2 Section 4.3 — Zone isolation requirements"
            ))

    return violations


def detect_field_enterprise_conduit(assets: list, violations: list) -> list:
    """
    Detect direct conduits between Field Device and Enterprise zones.

    A Field Device asset and an Enterprise asset sharing the same /24
    subnet implies a direct conduit without DMZ in between.

    Severity: HIGH — field devices must not communicate directly with enterprise.
    """
    field_assets = [a for a in assets if a.zone == "Field Device"]
    enterprise_assets = [a for a in assets if a.zone == "Enterprise"]

    for fa in field_assets:
        fa_subnet = fa.subnet_24
        for ea in enterprise_assets:
            if ea.subnet_24 == fa_subnet:
                violations.append(Violation(
                    violation_id=_next_violation_id(violations),
                    severity="HIGH",
                    type="Direct field-to-enterprise conduit",
                    description=(
                        f"Field device {fa.ip} ({fa.hostname or 'unknown'}) and enterprise "
                        f"asset {ea.ip} ({ea.hostname or 'unknown'}) share subnet {fa_subnet} — "
                        f"direct communication path without DMZ intermediary"
                    ),
                    affected_assets=[fa.ip, ea.ip],
                    iec_reference="IEC 62443-3-2 Section 5.4.2 — Conduit requirements"
                ))

    return violations


def detect_ics_on_enterprise(assets: list, violations: list) -> list:
    """
    Detect ICS protocol ports on Enterprise zone assets.

    ICS protocols (Modbus, DNP3, S7comm) should never be present on
    enterprise network assets.

    Severity: HIGH — indicates serious zone boundary breach.
    """
    for asset in assets:
        if asset.zone == "Enterprise":
            ics_open = asset.open_port_numbers & ICS_PROTOCOL_PORTS
            if ics_open:
                services = [_get_service_name(p) for p in ics_open]
                violations.append(Violation(
                    violation_id=_next_violation_id(violations),
                    severity="HIGH",
                    type="ICS protocol on enterprise asset",
                    description=(
                        f"Enterprise asset {asset.ip} ({asset.hostname or 'unknown'}) "
                        f"has ICS protocol(s) open: {', '.join(services)} — "
                        f"industrial protocols must not be on enterprise network"
                    ),
                    affected_assets=[asset.ip],
                    iec_reference="IEC 62443-3-2 Section 4.2 — Zone boundary requirements"
                ))

    return violations


def detect_smb_rdp_on_ot(assets: list, violations: list) -> list:
    """
    Detect SMB or RDP on Control or Field Device zone assets.

    These enterprise protocols should not be present on OT networks
    as they increase the attack surface and can be used for lateral movement.

    Severity: MEDIUM — improper service exposure.
    """
    for asset in assets:
        if asset.zone in ("Control", "Field Device"):
            # Check SMB
            if asset.has_open_port(445):
                violations.append(Violation(
                    violation_id=_next_violation_id(violations),
                    severity="MEDIUM",
                    type="Enterprise protocol on OT network",
                    description=(
                        f"SMB (port 445) is open on {asset.ip} ({asset.hostname or 'unknown'}) "
                        f"in {asset.zone} zone — file sharing protocols should not be on OT networks"
                    ),
                    affected_assets=[asset.ip],
                    iec_reference="IEC 62443-3-3 SR 5.2 — Zone boundary protection"
                ))

            # Check RDP on field devices only (RDP on control zone is less severe)
            if asset.has_open_port(3389) and asset.zone == "Field Device":
                violations.append(Violation(
                    violation_id=_next_violation_id(violations),
                    severity="MEDIUM",
                    type="Remote desktop on field device",
                    description=(
                        f"RDP (port 3389) is open on field device {asset.ip} "
                        f"({asset.hostname or 'unknown'}) — remote desktop should "
                        f"not be enabled on PLCs, RTUs, or sensors"
                    ),
                    affected_assets=[asset.ip],
                    iec_reference="NIST 800-82 Section 6.2.7 — Remote access restrictions"
                ))

    return violations


def detect_insecure_protocols(assets: list, violations: list) -> list:
    """
    Detect insecure protocols (Telnet, FTP) on OT network assets.

    These cleartext protocols are particularly dangerous on OT networks
    where credential theft can lead to process manipulation.

    Severity: MEDIUM on OT assets, LOW on enterprise.
    """
    for asset in assets:
        if asset.zone in ("Control", "Field Device"):
            if asset.has_open_port(23):
                violations.append(Violation(
                    violation_id=_next_violation_id(violations),
                    severity="MEDIUM",
                    type="Insecure protocol on OT asset",
                    description=(
                        f"Telnet (port 23) is open on {asset.ip} ({asset.hostname or 'unknown'}) "
                        f"in {asset.zone} zone — cleartext protocols expose credentials"
                    ),
                    affected_assets=[asset.ip],
                    iec_reference="IEC 62443-3-3 SR 1.3 — Human user identification"
                ))

            if asset.has_open_port(21):
                violations.append(Violation(
                    violation_id=_next_violation_id(violations),
                    severity="MEDIUM",
                    type="Insecure protocol on OT asset",
                    description=(
                        f"FTP (port 21) is open on {asset.ip} ({asset.hostname or 'unknown'}) "
                        f"in {asset.zone} zone — cleartext file transfer exposes credentials"
                    ),
                    affected_assets=[asset.ip],
                    iec_reference="NIST 800-82 Section 6.2.1 — Identification and authentication"
                ))

    return violations


def detect_missing_firewall(assets: list, violations: list) -> list:
    """
    Detect OT assets without firewall evidence.

    Field Device and Control zone assets should show filtered ports
    as evidence of perimeter protection. Absence of any filtered ports
    suggests the asset is directly accessible.

    Severity: MEDIUM for Control, HIGH for Field Device.
    """
    for asset in assets:
        if asset.zone in ("Control", "Field Device"):
            if len(asset.filtered_ports) == 0:
                severity = "HIGH" if asset.zone == "Field Device" else "MEDIUM"
                violations.append(Violation(
                    violation_id=_next_violation_id(violations),
                    severity=severity,
                    type="No firewall evidence",
                    description=(
                        f"No filtered ports detected on {asset.ip} "
                        f"({asset.hostname or 'unknown'}) in {asset.zone} zone — "
                        f"asset appears unprotected by firewall or packet filter"
                    ),
                    affected_assets=[asset.ip],
                    iec_reference="IEC 62443-3-2 Section 5.3 — Security zone boundaries"
                ))

    return violations


def detect_violations(assets: list, config: dict = None) -> list:
    """
    Run all violation detection rules against the list of classified assets.

    Args:
        assets: List of Asset objects with zone assignments
        config: Optional topology config dict (for future use)

    Returns:
        list[Violation]: All detected violations, sorted by severity
    """
    violations = []

    # Run all detection rules
    detect_dual_homed_assets(assets, violations)
    detect_field_enterprise_conduit(assets, violations)
    detect_ics_on_enterprise(assets, violations)
    detect_smb_rdp_on_ot(assets, violations)
    detect_insecure_protocols(assets, violations)
    detect_missing_firewall(assets, violations)

    # Sort by severity: HIGH > MEDIUM > LOW
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    violations.sort(key=lambda v: severity_order.get(v.severity, 3))

    # Re-assign violation IDs after sorting
    for i, v in enumerate(violations):
        v.violation_id = f"V-{i + 1:03d}"

    return violations
