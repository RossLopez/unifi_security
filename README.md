# UniFi Security for Splunk (unifi_security)

Splunk search-head app with security content for Ubiquiti UniFi: a Dashboard Studio overview, tuning macros and scheduled detections for IPS/IDS threats, firewall activity, admin access, rogue APs and WiFi authentication.

Requires the **UniFi Security Add-on** ([`TA-unifi_security`](https://github.com/RossLopez/TA-unifi_security)) for parsing and CIM mapping.

## Repository layout

| Path | Purpose |
|---|---|
| `unifi_security/` | The app itself (packaged as-is). See its [README](unifi_security/README.md) for the dashboard, detections and macros. |
| `scripts/compat_test.py` | Installs both packages in throwaway `splunk/splunk` Docker containers, loads demo data and checks routing, eventtypes, every dashboard search and saved search, plus a dashboard screenshot |
| `scripts/demo_data.py` | Generates sanitized demo UniFi syslog (last 24h) for screenshots and trying the app: `python3 scripts/demo_data.py > demo.log`, then `splunk add oneshot demo.log -index unifi -sourcetype ubiquiti:unifi` |
| `assets/screenshots/` | Splunkbase listing screenshots, taken on demo data |
| `scripts/build_icons.py` | Renders `assets/` (SVG sources, 512px Splunkbase listing icon) and the app's `static/` icons and logos (`pip install resvg-py`) |
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

Compatibility test (Docker; screenshots need `pip install playwright` and Google Chrome). Runs one container at a time and accepts Splunk's license and General Terms:

```bash
python3 scripts/compat_test.py --ta ../TA-unifi_security/dist/TA-unifi_security-<version>.spl --app dist/unifi_security-<version>.spl 9.4.16 10.0.11 10.2.8 10.4.2 10.6.1
```

## Support

Developer supported, best effort. Report dashboard or detection problems at https://github.com/RossLopez/unifi_security/issues; for parsing or missing fields use https://github.com/RossLopez/TA-unifi_security/issues. Replace real IP addresses, MAC addresses, hostnames, usernames and SSIDs in any log samples you post.

Not supported by Splunk or Ubiquiti.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

*Not affiliated with or endorsed by Ubiquiti Inc. UniFi is a trademark of Ubiquiti Inc.*
