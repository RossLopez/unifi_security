# UniFi Security for Splunk (unifi_security)

Splunk search-head app with security content for Ubiquiti UniFi: a Dashboard Studio overview, tuning macros and scheduled detections for IPS/IDS threats, firewall activity, admin access, rogue APs and WiFi authentication.

Requires the **UniFi Security Add-on** ([`TA-unifi_security`](https://github.com/RossLopez/TA-unifi_security)) for parsing and CIM mapping.

## Repository layout

| Path | Purpose |
|---|---|
| `unifi_security/` | The app itself (packaged as-is). See its [README](unifi_security/README.md) for the dashboard, detections and macros. |
| `scripts/package.sh` | Builds `dist/unifi_security-<version>.spl` |
| `docs/ROADMAP.md` | Backlog, Splunkbase checklist and release history |

## Build

```bash
scripts/package.sh
```

AppInspect (needs Python 3.9–3.12 and `brew install libmagic`):

```bash
python3.12 -m venv .venv && .venv/bin/pip install splunk-appinspect
.venv/bin/splunk-appinspect inspect dist/unifi_security-<version>.spl --mode precert --included-tags cloud
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).

*Not affiliated with or endorsed by Ubiquiti Inc. UniFi is a trademark of Ubiquiti Inc.*
