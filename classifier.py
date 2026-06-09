"""
classifier.py — IEC 62443 Zone & Security Level Classification

Classifies each discovered asset into one of four IEC 62443-3-2 security zones
(Enterprise, DMZ, Control, Field Device) using port-based heuristics and
hostname patterns. Assigns a Security Level (SL1–SL3) based on zone and
detected services.

Zones implemented:
  - Enterprise Zone:    Corporate IT network, business systems (SL1)
  - DMZ Zone:           Buffer between enterprise and control (SL2)
  - Control Zone:       SCADA/DCS/HMI systems (SL2–SL3)
  - Field Device Zone:  PLCs, RTUs, sensors, actuators (SL2–SL3)
"""

# ICS protocol port numbers
ICS_PORTS = {
    502: "Modbus",
    20000: "DNP3",
    102: "S7comm",
    4840: "OPC UA",
    44818: "EtherNet/IP",
}

# Field device protocol ports (direct field-level protocols)
FIELD_DEVICE_PORTS = {502, 20000, 102}

# Control zone protocol ports
CONTROL_ZONE_PORTS = {44818}

# DMZ / Control bridge protocols
BRIDGE_PORTS = {4840}

# Hostname patterns that indicate Control zone
CONTROL_HOSTNAME_PATTERNS = [
    "hmi", "scada", "dcs", "plc", "rtu",
    "engineering", "eng-workstation", "control",
]

# Enterprise-facing service ports
ENTERPRISE_SERVICE_PORTS = {80, 443, 8080, 8443}

# Remote access ports
REMOTE_ACCESS_PORTS = {3389, 22}


def classify_zone(asset) -> str:
    """
    Classify an asset into an IEC 62443 security zone using port-based
    heuristics and hostname patterns.

    Priority order:
      1. Field device protocols (Modbus, DNP3, S7comm) → Field Device Zone
      2. Hostname contains HMI/SCADA/DCS keywords → Control Zone
      3. EtherNet/IP (port 44818) → Control Zone
      4. OPC UA (port 4840) + other ICS indicators → Control Zone
      5. OPC UA (port 4840) alone → DMZ (bridge/historian role)
      6. RDP/SSH + Windows/Linux OS, no ICS protocols → Enterprise or DMZ
      7. Web-only (80/443) + no ICS protocols → Enterprise Zone
      8. Unknown if no rule matches

    Args:
        asset: An Asset object with ip, hostname, os_match, open_ports, etc.

    Returns:
        str: Zone name — 'Enterprise', 'DMZ', 'Control', 'Field Device', or 'Unknown'
    """
    open_port_nums = asset.open_port_numbers
    hostname_lower = asset.hostname.lower() if asset.hostname else ""

    # --- Rule 1: Field device protocols (Modbus, DNP3, S7comm) ---
    # These are definitively field-level protocols used by PLCs, RTUs, sensors
    if open_port_nums & FIELD_DEVICE_PORTS:
        return "Field Device"

    # --- Rule 2: Hostname contains HMI/SCADA/DCS keywords ---
    # Hostname naming convention is a strong control zone indicator
    for pattern in CONTROL_HOSTNAME_PATTERNS:
        if pattern in hostname_lower:
            return "Control"

    # --- Rule 3: EtherNet/IP (port 44818) ---
    # Allen-Bradley PLC/IO or SCADA communication
    if 44818 in open_port_nums:
        return "Control"

    # --- Rule 4 & 5: OPC UA (port 4840) ---
    # OPC UA bridges field data to SCADA. If other ICS indicators exist,
    # it's a control system; if standalone with SSH/web, it's likely a DMZ historian
    if 4840 in open_port_nums:
        # Check if it also has control zone indicators
        has_control_indicators = (
            open_port_nums & CONTROL_ZONE_PORTS or
            any(p in hostname_lower for p in CONTROL_HOSTNAME_PATTERNS)
        )
        if has_control_indicators:
            return "Control"
        # OPC UA alone = likely historian/data bridge in DMZ
        return "DMZ"

    # --- Rule 6: Remote access (RDP/SSH) + standard OS, no ICS protocols ---
    has_remote_access = bool(open_port_nums & REMOTE_ACCESS_PORTS)
    has_ics = bool(open_port_nums & (FIELD_DEVICE_PORTS | CONTROL_ZONE_PORTS | BRIDGE_PORTS))

    if has_remote_access and not has_ics:
        # Determine if it's DMZ or Enterprise based on service profile
        has_web = bool(open_port_nums & ENTERPRISE_SERVICE_PORTS)
        has_rpc_or_vpn = 111 in open_port_nums

        # DMZ indicators: gateway/vpn hostname, RPC services, mixed access profile
        dmz_hostname_hints = ["vpn", "gateway", "dmz", "proxy", "bastion", "jump"]
        is_dmz_hostname = any(hint in hostname_lower for hint in dmz_hostname_hints)

        if is_dmz_hostname or has_rpc_or_vpn:
            return "DMZ"
        return "Enterprise"

    # --- Rule 7: Web-only (80/443) + no ICS protocols ---
    if open_port_nums & ENTERPRISE_SERVICE_PORTS and not has_ics:
        return "Enterprise"

    # --- Rule 8: No matching rule ---
    return "Unknown"


def classify_assets(assets: list) -> list:
    """
    Classify all assets in the list and return the modified list.

    Args:
        assets: List of Asset objects

    Returns:
        list: The same list with zone assignments applied
    """
    for asset in assets:
        asset.zone = classify_zone(asset)
    return assets
