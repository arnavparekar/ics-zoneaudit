import pytest
from ics_zoneaudit import Asset, Port
from checker import (
    check_h01_telnet_disabled,
    check_h03_modbus_not_exposed,
    check_h10_not_dual_homed,
    check_h14_no_field_enterprise_conduit
)


def create_asset(ip="192.168.1.10", zone="Unknown", ports=None, hostname=""):
    """Helper to create an Asset object for testing."""
    if ports is None:
        ports = []
    
    port_objs = []
    for p in ports:
        port_objs.append(Port(number=p, protocol="tcp", state="open", service_name=""))
        
    asset = Asset(ip=ip, hostname=hostname, ports=port_objs)
    asset.zone = zone
    return asset


class TestChecker:

    def test_h01_telnet(self):
        # Telnet open -> fail
        asset_fail = create_asset(ports=[23])
        assert not check_h01_telnet_disabled(asset_fail).passed
        
        # Telnet closed -> pass
        asset_pass = create_asset(ports=[22, 80])
        assert check_h01_telnet_disabled(asset_pass).passed

    def test_h03_modbus_not_exposed(self):
        field_asset = create_asset(zone="Field Device", ports=[502])
        ent_asset = create_asset(zone="Enterprise", ports=[80])
        
        # Fail if Modbus is in Field and Enterprise is in scan
        assert not check_h03_modbus_not_exposed(field_asset, [field_asset, ent_asset]).passed
        
        # Pass if no Enterprise asset in scan
        assert check_h03_modbus_not_exposed(field_asset, [field_asset]).passed

    def test_h10_not_dual_homed(self):
        # Fail if strong enterprise (RDP 3389) + ICS (Modbus 502)
        asset_fail = create_asset(ports=[3389, 502])
        assert not check_h10_not_dual_homed(asset_fail).passed
        
        # Pass if web (80) + ICS (502) - web is not a strong enterprise indicator
        asset_pass1 = create_asset(ports=[80, 502])
        assert check_h10_not_dual_homed(asset_pass1).passed
        
        # Pass if only enterprise (3389, 445)
        asset_pass2 = create_asset(ports=[3389, 445])
        assert check_h10_not_dual_homed(asset_pass2).passed

    def test_h14_no_field_enterprise_conduit(self):
        field_asset = create_asset(ip="192.168.10.50", zone="Field Device")
        ent_asset_same = create_asset(ip="192.168.10.100", zone="Enterprise")
        ent_asset_diff = create_asset(ip="192.168.20.100", zone="Enterprise")
        
        # Fail if same /24 subnet
        assert not check_h14_no_field_enterprise_conduit(field_asset, [field_asset, ent_asset_same]).passed
        
        # Pass if different subnet
        assert check_h14_no_field_enterprise_conduit(field_asset, [field_asset, ent_asset_diff]).passed
