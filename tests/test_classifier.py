import pytest
from ics_zoneaudit import Asset, Port
from classifier import classify_zone, assign_security_level, _check_config_override


def create_asset(ip="192.168.1.10", hostname="", ports=None):
    """Helper to create an Asset object for testing."""
    if ports is None:
        ports = []
    
    port_objs = []
    for p in ports:
        port_objs.append(Port(number=p, protocol="tcp", state="open", service_name=""))
        
    return Asset(ip=ip, hostname=hostname, ports=port_objs)


class TestClassifier:
    
    def test_classify_zone_field_device(self):
        # Modbus port 502 -> Field Device
        asset = create_asset(ports=[80, 502])
        assert classify_zone(asset) == "Field Device"
        
        # S7comm port 102 -> Field Device
        asset = create_asset(ports=[102])
        assert classify_zone(asset) == "Field Device"

    def test_classify_zone_control(self):
        # EtherNet/IP 44818 -> Control
        asset = create_asset(ports=[44818])
        assert classify_zone(asset) == "Control"
        
        # Hostname indicates control
        asset = create_asset(hostname="scada-server", ports=[80])
        assert classify_zone(asset) == "Control"

    def test_classify_zone_dmz(self):
        # OPC UA alone -> DMZ (historian profile)
        asset = create_asset(ports=[4840])
        assert classify_zone(asset) == "DMZ"
        
        # Web + SSH + RPC -> DMZ (mixed access profile)
        asset = create_asset(ports=[80, 443, 22, 111])
        assert classify_zone(asset) == "DMZ"
        
        # Historian -> DMZ
        asset = create_asset(hostname="historian", ports=[4840])
        assert classify_zone(asset) == "DMZ"

    def test_classify_zone_enterprise(self):
        # SMB/RDP without web/ssh -> Enterprise
        asset = create_asset(ports=[445, 3389])
        assert classify_zone(asset) == "Enterprise"
        
        # Standard corporate IT name -> Enterprise
        asset = create_asset(hostname="corp-mail", ports=[25, 80])
        assert classify_zone(asset) == "Enterprise"

    def test_assign_security_level(self):
        # Enterprise -> SL1
        asset = create_asset()
        asset.zone = "Enterprise"
        assert assign_security_level(asset) == "SL1"
        
        # Control base -> SL2
        asset = create_asset()
        asset.zone = "Control"
        assert assign_security_level(asset) == "SL2"
        
        # Control with critical port (Modbus) -> SL3
        asset = create_asset(ports=[502])
        asset.zone = "Control"
        assert assign_security_level(asset) == "SL3"
        
        # Field Device base -> SL2
        asset = create_asset(ports=[80])
        asset.zone = "Field Device"
        assert assign_security_level(asset) == "SL2"
        
        # Field Device with Modbus -> SL3
        asset = create_asset(ports=[502])
        asset.zone = "Field Device"
        assert assign_security_level(asset) == "SL3"

    def test_config_override(self):
        config = {
            "zones": {
                "Control": ["192.168.10.15"],
                "DMZ": ["10.0.0.0/24"]
            }
        }
        
        # Exact IP match
        assert _check_config_override("192.168.10.15", config) == "Control"
        
        # Subnet match
        assert _check_config_override("10.0.0.55", config) == "DMZ"
        
        # No match
        assert _check_config_override("192.168.1.1", config) is None
