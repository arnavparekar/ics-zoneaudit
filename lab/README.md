# ICS-ZoneAudit Optional OT Lab

This directory contains a `docker-compose.yml` file that spins up a miniature simulated OT network using lightweight Alpine Linux containers.

This lab is useful for testing the ICS-ZoneAudit tool if you don't have access to a real industrial network. It simulates the exact hosts and misconfigurations found in the `samples/demo_scan.xml` file.

## Prerequisites
- Docker
- Docker Compose
- Nmap

## Usage

1. **Start the simulated OT network:**
   ```bash
   docker compose up -d
   ```

2. **Verify the containers are running:**
   ```bash
   docker compose ps
   ```

3. **Run an Nmap scan against the simulated network:**
   *Note: You may need to run this with `sudo` depending on your Docker networking setup, or run it from another container attached to the Docker bridge networks.*
   ```bash
   nmap -sV -p- -oX my_scan.xml 192.168.1.10 192.168.1.30 192.168.1.20 192.168.2.10 192.168.3.10 192.168.4.10 192.168.4.40
   ```
   *(Or just scan the subnets: `192.168.1.0/24 192.168.2.0/24 192.168.3.0/24 192.168.4.0/24`)*

4. **Run ICS-ZoneAudit on the generated XML:**
   ```bash
   python ../ics_zoneaudit.py --input my_scan.xml
   ```

5. **Stop the lab when finished:**
   ```bash
   docker compose down
   ```

## Simulated Misconfigurations

The lab is intentionally built with violations to trigger the ICS-ZoneAudit checks:
- **Dual-homed assets**: `eng-ws-01` and `scada-server-01` are connected to multiple zones.
- **Direct field-to-enterprise conduit**: `plc-modbus-01` bridges the Field network directly to the Enterprise network.
- **Insecure protocols**: Telnet and FTP are running on field devices (`plc-siemens-01`).
- **Web/RDP on field devices**: `plc-modbus-01` exposes RDP and HTTP.
