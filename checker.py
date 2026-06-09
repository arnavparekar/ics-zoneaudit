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
