"""
checker.py — IEC 62443 Hardening Checklist Engine

Scores each asset against a 15-point hardening checklist derived from
IEC 62443-3-3 system requirements and NIST SP 800-82 guidance.

Each check is binary: pass (1) or fail (0). Total score /15 is shown
on the asset scorecard.

Checks H-01 through H-15 cover:
  - Insecure protocol exposure (Telnet, FTP, RPC)
  - ICS protocol boundary violations (Modbus, OPC UA, S7comm)
  - Remote access on field devices (RDP, web interfaces)
  - Network segmentation (SNMP, SMB, dual-homing)
  - General hardening (open port count, firewall evidence)
"""

from dataclasses import dataclass, field
from typing import Callable, List, Optional


# ICS protocol ports used across multiple checks
ICS_PROTOCOL_PORTS = {502, 20000, 102}  # Modbus, DNP3, S7comm


@dataclass
class CheckResult:
    """Result of a single hardening check."""
    check_id: str
    name: str
    passed: bool
    fail_condition: str
    source: str
    details: str = ""


def check_h01_telnet_disabled(asset, all_assets=None) -> CheckResult:
    """H-01: Telnet disabled — Port 23 open is a fail."""
    passed = not asset.has_open_port(23)
    return CheckResult(
        check_id="H-01",
        name="Telnet disabled",
        passed=passed,
        fail_condition="Port 23 open",
        source="IEC 62443-3-3 SR 1.3",
        details="" if passed else f"Telnet (port 23) is open on {asset.ip}"
    )


def check_h02_ftp_disabled(asset, all_assets=None) -> CheckResult:
    """H-02: FTP disabled — Port 21 open is a fail."""
    passed = not asset.has_open_port(21)
    return CheckResult(
        check_id="H-02",
        name="FTP disabled",
        passed=passed,
        fail_condition="Port 21 open",
        source="NIST 800-82",
        details="" if passed else f"FTP (port 21) is open on {asset.ip}"
    )


def check_h03_modbus_not_exposed(asset, all_assets=None) -> CheckResult:
    """
    H-03: Default Modbus port not exposed to enterprise zone.

    Fail condition: Asset is in Field Device zone AND port 502 is open
    AND at least one Enterprise zone asset exists in the scan
    (implies no enforced segmentation between field and enterprise).
    """
    if all_assets is None:
        all_assets = []

    has_enterprise = any(a.zone == "Enterprise" for a in all_assets)
    failed = (
        asset.zone == "Field Device" and
        asset.has_open_port(502) and
        has_enterprise
    )
    return CheckResult(
        check_id="H-03",
        name="Modbus not exposed to enterprise",
        passed=not failed,
        fail_condition="Port 502 on Field Device with Enterprise assets in scan",
        source="IEC 62443-3-3 SR 5.2",
        details="" if not failed else (
            f"Modbus (port 502) on {asset.ip} (Field Device) is potentially "
            f"reachable from Enterprise zone — no enforced segmentation detected"
        )
    )


def check_h04_no_rpc(asset, all_assets=None) -> CheckResult:
    """H-04: No anonymous RPC services — Port 111 open is a fail."""
    passed = not asset.has_open_port(111)
    return CheckResult(
        check_id="H-04",
        name="No anonymous RPC services",
        passed=passed,
        fail_condition="Port 111 open",
        source="NIST 800-82",
        details="" if passed else f"RPC portmapper (port 111) is open on {asset.ip}"
    )


def check_h05_ssh_over_telnet(asset, all_assets=None) -> CheckResult:
    """H-05: SSH preferred over Telnet — Telnet open + SSH absent is a fail."""
    has_telnet = asset.has_open_port(23)
    has_ssh = asset.has_open_port(22)
    failed = has_telnet and not has_ssh
    return CheckResult(
        check_id="H-05",
        name="SSH preferred over Telnet",
        passed=not failed,
        fail_condition="Telnet open + SSH absent",
        source="IEC 62443-3-3 SR 1.3",
        details="" if not failed else (
            f"Telnet is available but SSH is not on {asset.ip} — "
            f"no encrypted remote access alternative"
        )
    )


def check_h06_opcua_not_enterprise(asset, all_assets=None) -> CheckResult:
    """
    H-06: OPC UA not directly exposed at enterprise boundary.

    Fail condition: Port 4840 open on an asset classified in the Enterprise zone.
    Note: Assets with OPC UA are typically classified as DMZ or Control by the
    classifier, so this catches edge cases where zone was overridden or
    the asset is in Enterprise despite having OPC UA.
    """
    failed = asset.has_open_port(4840) and asset.zone == "Enterprise"
    return CheckResult(
        check_id="H-06",
        name="OPC UA not on enterprise boundary",
        passed=not failed,
        fail_condition="Port 4840 on Enterprise zone asset",
        source="IEC 62443-3-2",
        details="" if not failed else (
            f"OPC UA (port 4840) is exposed on {asset.ip} in Enterprise zone — "
            f"ICS protocol should not be directly accessible from enterprise network"
        )
    )


def check_h07_no_rdp_field(asset, all_assets=None) -> CheckResult:
    """H-07: No RDP on field device — Port 3389 on Field Device zone asset is a fail."""
    failed = asset.has_open_port(3389) and asset.zone == "Field Device"
    return CheckResult(
        check_id="H-07",
        name="No RDP on field device",
        passed=not failed,
        fail_condition="Port 3389 on Field Device zone asset",
        source="NIST 800-82",
        details="" if not failed else (
            f"RDP (port 3389) is open on field device {asset.ip} — "
            f"remote desktop should not be enabled on PLCs/RTUs"
        )
    )


def check_h08_no_web_on_plc(asset, all_assets=None) -> CheckResult:
    """H-08: Web management interface disabled on PLC — Port 80 on Field Device zone is a fail."""
    failed = asset.has_open_port(80) and asset.zone == "Field Device"
    return CheckResult(
        check_id="H-08",
        name="Web interface disabled on PLC",
        passed=not failed,
        fail_condition="Port 80 on Field Device zone asset",
        source="IEC 62443-3-3 SR 2.4",
        details="" if not failed else (
            f"HTTP web interface (port 80) is active on field device {asset.ip} — "
            f"web management should be disabled on PLCs and RTUs"
        )
    )

def check_h09_snmp_not_exposed(asset, all_assets=None) -> CheckResult:
    """
    H-09: SNMP not exposed externally.

    Fail condition: Port 161 is open AND asset is in Enterprise zone OR DMZ
    (SNMP externally reachable from enterprise-facing networks).
    """
    failed = asset.has_open_port(161) and asset.zone in ("Enterprise", "DMZ")
    return CheckResult(
        check_id="H-09",
        name="SNMP not exposed externally",
        passed=not failed,
        fail_condition="Port 161 on Enterprise or DMZ zone asset",
        source="NIST 800-82",
        details="" if not failed else (
            f"SNMP (port 161) is externally reachable on {asset.ip} "
            f"({asset.zone} zone) — SNMP should not be exposed on "
            f"enterprise-facing networks"
        )
    )


def check_h10_not_dual_homed(asset, all_assets=None) -> CheckResult:
    """
    H-10: Engineering workstation not dual-homed.

    Fail condition: Asset appears in both Enterprise + Control zone.
    Since our classifier assigns a single zone, we detect this by checking
    if the asset has both strong enterprise characteristics (RDP or SMB)
    AND control characteristics (ICS protocols or control hostname).
    Web ports alone are not sufficient enterprise indicators since they
    are common across all zones.
    """
    open_port_nums = asset.open_port_numbers
    hostname_lower = asset.hostname.lower() if asset.hostname else ""

    # Enterprise indicators — strong signals only (RDP, SMB)
    has_enterprise_traits = bool(open_port_nums & {3389, 445})

    # Control indicators — ICS protocols or control hostname
    control_keywords = ["hmi", "scada", "dcs", "engineering", "eng-workstation"]
    has_control_traits = bool(
        open_port_nums & {44818, 4840, 502, 20000, 102} or
        any(kw in hostname_lower for kw in control_keywords)
    )

    failed = has_enterprise_traits and has_control_traits
    return CheckResult(
        check_id="H-10",
        name="Not dual-homed (Enterprise+Control)",
        passed=not failed,
        fail_condition="Asset shows both Enterprise and Control zone characteristics",
        source="IEC 62443-3-2 Zone isolation",
        details="" if not failed else (
            f"Asset {asset.ip} ({asset.hostname}) appears to be dual-homed — "
            f"has both enterprise services and ICS/control indicators"
        )
    )


def check_h11_no_smb_control(asset, all_assets=None) -> CheckResult:
    """H-11: SMB not on control network — Port 445 on Control or Field Device zone is a fail."""
    failed = asset.has_open_port(445) and asset.zone in ("Control", "Field Device")
    return CheckResult(
        check_id="H-11",
        name="SMB not on control network",
        passed=not failed,
        fail_condition="Port 445 on Control or Field Device zone asset",
        source="IEC 62443-3-3 SR 5.2",
        details="" if not failed else (
            f"SMB (port 445) is open on {asset.ip} in {asset.zone} zone — "
            f"file sharing protocols should not be on control/field networks"
        )
    )


def check_h12_port_count(asset, all_assets=None) -> CheckResult:
    """H-12: No unnecessary open ports — Asset has >10 open ports is a fail."""
    count = len(asset.open_ports)
    failed = count > 10
    return CheckResult(
        check_id="H-12",
        name="No unnecessary open ports",
        passed=not failed,
        fail_condition="Asset has >10 open ports",
        source="General hardening",
        details="" if not failed else (
            f"Asset {asset.ip} has {count} open ports — "
            f"excessive open ports increase attack surface"
        )
    )


def check_h13_ics_not_on_enterprise(asset, all_assets=None) -> CheckResult:
    """
    H-13: ICS protocol port not on enterprise asset.

    Fail condition: Modbus/DNP3/S7comm port open on an Enterprise zone asset.
    """
    has_ics = bool(asset.open_port_numbers & ICS_PROTOCOL_PORTS)
    failed = has_ics and asset.zone == "Enterprise"
    return CheckResult(
        check_id="H-13",
        name="ICS protocol not on enterprise asset",
        passed=not failed,
        fail_condition="Modbus/DNP3/S7 port on Enterprise zone asset",
        source="IEC 62443-3-2",
        details="" if not failed else (
            f"ICS protocol port detected on enterprise asset {asset.ip} — "
            f"industrial protocols should not be present on enterprise network"
        )
    )


def check_h14_no_field_enterprise_conduit(asset, all_assets=None) -> CheckResult:
    """
    H-14: No direct field device to enterprise conduit.

    Fail condition: A Field Device zone asset and an Enterprise zone asset
    share the same /24 subnet (inferred direct conduit, no DMZ in between).
    """
    if all_assets is None:
        all_assets = []

    failed = False
    enterprise_peer = ""

    if asset.zone == "Field Device":
        asset_subnet = asset.subnet_24
        for other in all_assets:
            if other.zone == "Enterprise" and other.subnet_24 == asset_subnet:
                failed = True
                enterprise_peer = other.ip
                break

    return CheckResult(
        check_id="H-14",
        name="No field-to-enterprise conduit",
        passed=not failed,
        fail_condition="Field Device and Enterprise asset on same /24 subnet",
        source="IEC 62443-3-2 conduit rules",
        details="" if not failed else (
            f"Field device {asset.ip} shares /24 subnet with enterprise "
            f"asset {enterprise_peer} — direct conduit without DMZ detected"
        )
    )


def check_h15_firewall_evidence(asset, all_assets=None) -> CheckResult:
    """
    H-15: Firewall evidence present.

    Fail condition: All scanned ports return open or closed, none filtered.
    At least one 'filtered' port is evidence that a firewall is in the path.
    """
    has_filtered = len(asset.filtered_ports) > 0
    failed = not has_filtered
    return CheckResult(
        check_id="H-15",
        name="Firewall evidence present",
        passed=not failed,
        fail_condition="No filtered ports detected (no firewall evidence)",
        source="IEC 62443-3-2",
        details="" if not failed else (
            f"No filtered ports on {asset.ip} — all ports are open or closed, "
            f"suggesting no firewall or packet filter is protecting this asset"
        )
    )


# Complete registry of all 15 hardening checks
HARDENING_CHECKS = [
    check_h01_telnet_disabled,
    check_h02_ftp_disabled,
    check_h03_modbus_not_exposed,
    check_h04_no_rpc,
    check_h05_ssh_over_telnet,
    check_h06_opcua_not_enterprise,
    check_h07_no_rdp_field,
    check_h08_no_web_on_plc,
    check_h09_snmp_not_exposed,
    check_h10_not_dual_homed,
    check_h11_no_smb_control,
    check_h12_port_count,
    check_h13_ics_not_on_enterprise,
    check_h14_no_field_enterprise_conduit,
    check_h15_firewall_evidence,
]


def run_checks(asset, all_assets: list = None) -> dict:
    """
    Run all hardening checks against an asset and return results.

    Args:
        asset: The Asset object to check
        all_assets: List of all assets (needed for cross-asset checks)

    Returns:
        dict with keys:
          - 'results': list of CheckResult objects
          - 'score': number of passed checks
          - 'max_score': total number of checks
          - 'checks_detail': dict mapping check_id → {passed, name, details, source}
    """
    if all_assets is None:
        all_assets = [asset]

    results = []
    for check_fn in HARDENING_CHECKS:
        result = check_fn(asset, all_assets)
        results.append(result)

    score = sum(1 for r in results if r.passed)
    max_score = len(results)

    checks_detail = {}
    for r in results:
        checks_detail[r.check_id] = {
            "name": r.name,
            "passed": r.passed,
            "fail_condition": r.fail_condition,
            "source": r.source,
            "details": r.details,
        }

    return {
        "results": results,
        "score": score,
        "max_score": max_score,
        "checks_detail": checks_detail,
    }


def run_all_checks(assets: list) -> list:
    """
    Run hardening checks on all assets. Updates each asset's score,
    max_score, and checks fields in-place.

    Args:
        assets: List of Asset objects

    Returns:
        list: The same list with hardening scores applied
    """
    for asset in assets:
        result = run_checks(asset, assets)
        asset.score = result["score"]
        asset.max_score = result["max_score"]
        asset.checks = result["checks_detail"]
    return assets
