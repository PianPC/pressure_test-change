# Pressure Test Console

Flask-based pressure testing console with Memcached, DNS, NTP, multi-protocol testing, and a TCP Censor Scan workflow.

## TCP Censor Scan

The TCP scan feature is integrated as a Flask Blueprint under `/api/tcp-scan/*`.

- Backend module: `modules/tcp_censor_scan/`
- Routes: `modules/tcp_censor_routes.py`
- Input resources: `tcp_scan_data/ip_lists/`
- GeoIP database: `tcp_scan_data/geoip/`
- Run outputs: `runs/tcp_censor_scan/<run_id>/`
- Default config: `config/tcp_censor_scan/scan.example.toml`

The default web form runs with `dry_run` enabled so the UI and pipeline can be tested without root privileges or zmap. For real scans, disable dry-run and run on Linux with root/cap networking permissions, a valid interface name, zmap binaries, traceroute, Scapy, and the GeoIP database.

## Development Check

```bash
python app.py
```

Open `http://localhost:5000`, then use the `TCP Scan` navigation item.
