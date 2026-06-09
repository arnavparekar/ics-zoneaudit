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
