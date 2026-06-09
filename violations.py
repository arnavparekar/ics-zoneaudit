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
