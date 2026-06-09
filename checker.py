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


# Registry of all checks implemented so far (H-01 through H-08)
HARDENING_CHECKS = [
    check_h01_telnet_disabled,
    check_h02_ftp_disabled,
    check_h03_modbus_not_exposed,
    check_h04_no_rpc,
    check_h05_ssh_over_telnet,
    check_h06_opcua_not_enterprise,
    check_h07_no_rdp_field,
    check_h08_no_web_on_plc,
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
