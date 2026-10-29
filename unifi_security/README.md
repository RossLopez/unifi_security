# UniFi Security (unifi_security) v0.2.4

Search-head app with security content for UniFi data. Requires the **UniFi Security Add-on** (`TA-unifi_security`) 0.2.0 or later.

## Compatibility

- Splunk Enterprise 9.4, 10.0, 10.2, 10.4 and 10.6 (tested on 9.4.16, 10.0.11, 10.2.8, 10.4.2 and 10.6.1).
- Splunk Cloud Platform: passes AppInspect's Splunk Cloud checks; not yet tested on a Cloud stack.

## Where to install

| Splunk instance | Install the app? |
|---|---|
| Search heads (search head clusters: push from the deployer) | Yes |
| Indexers, heavy forwarders, universal forwarders | No |
| Splunk Cloud Platform | Yes, on the search head |

The add-on (`TA-unifi_security`) must be installed on the same search heads and on the instance that receives UniFi syslog; see its README.

## Get started

1. Install and configure the add-on first, and confirm data arrives: `index=unifi earliest=-15m | stats count by sourcetype`.
2. Install the app on the search heads.
3. If your UniFi data is not in `index=unifi`, change the `unifi_index` macro (see Tuning).
4. Open **UniFi Security Overview**. Panels fill as matching events arrive; see Troubleshooting for panels that stay empty.
5. Enable the detections you want (below).

## Dashboard

**UniFi Security Overview** (Dashboard Studio): KPI tiles; security events over time; top IPS signatures; IPS sources by country; recent IPS events; firewall blocks by client; top blocked destinations; UniFi OS firewall/NAT rule hits; admin access; WiFi auth failures; rogue APs; sudo/SSH activity.

## Detections

All detections ship **disabled** and, once enabled, write to Triggered Alerts only.

| Alert | Schedule | Throttle | Logic |
|---|---|---|---|
| IPS Threat Detected | every 15 min (:01) | 4h per src/dest | Any IPS detection, grouped by src/dest, with GeoIP |
| Outbound IPS Detection From Internal Host | every 15 min (:02) | 4h per src/dest | IPS hit where src is internal and dest is external (possible C2 / compromised IoT) |
| Unexpected sudo On UniFi OS | every 15 min (:03) | none | sudo by an account not in `unifi_sudo_expected_users` |
| SSH Activity On UniFi Device | every 15 min (:04) | none | Any successful SSH login, or 5+ failures from one source |
| Admin Access From New Source | hourly (:05) | none | Admin user + source IP not seen in the previous 30 days |
| Rogue AP Impersonating SSID | hourly (:10) | 24h per BSSID | CEF 529 WiFi Impersonation |
| WiFi Authentication Failure Threshold | hourly (:15) | 12h per client MAC | ≥ `unifi_wifi_fail_threshold` WPA failures per client MAC |
| Excessive Firewall Blocks From Client | hourly (:20) | 6h per client | ≥ `unifi_fw_block_threshold` blocks per internal client |
| New Device On Network | hourly (:25) | none | Client MAC first seen (connect or DHCP) in 30 days |

## Tuning the detections

1. **Enable:** Settings > Searches, reports, and alerts, set App to UniFi Security, then Edit > Enable for each alert you want.
2. **Notify:** Edit > Edit Alert > Add Actions (email, webhook, or any alert action you have installed). Throttling is under the same dialog.
3. **Adjust thresholds and lists** with the macros below: Settings > Advanced search > Search macros, App: UniFi Security. Your changes are saved in `local/` and survive app upgrades.

   | Macro | Default | Controls |
   |---|---|---|
   | `unifi_index` | `index=unifi` | Where the dashboard and detections search, e.g. `(index=unifi OR index=network)` |
   | `unifi_fw_block_threshold` | `50` | Excessive Firewall Blocks From Client: blocks per internal client per hour |
   | `unifi_wifi_fail_threshold` | `20` | WiFi Authentication Failure Threshold: failures per client MAC per hour |
   | `unifi_sudo_expected_users` | `("ucs-update", "unifi-access")` | Unexpected sudo On UniFi OS: accounts that normally run sudo on UniFi OS (quoted, comma-separated) |
   | `unifi_is_private(field)` | RFC1918, 100.64.0.0/10, loopback | What counts as internal for Outbound IPS and the dashboard; add your own ranges if needed |

4. **Suppress known noise** (a signature you accept, a trusted admin source) by adding a filter to the alert's search, e.g. `NOT signature="ET INFO …"`, in Edit > Edit Search.
5. **Baselines:** Admin Access From New Source and New Device On Network compare against the previous 30 days. Until 30 days of data are indexed, every admin source and device looks new, so enable them after that. Both search 30 days of data every hour.
6. `action=allowed` on IPS events means the gateway is in detect-only (IDS) mode or the signature only alerts: the traffic was not dropped.

## Troubleshooting

| Symptom | Check |
|---|---|
| Dashboard is empty | `index=unifi earliest=-24h \| stats count by sourcetype` returns `ubiquiti:unifi*` sourcetypes; the `unifi_index` macro points at the right index; the add-on 0.2.0 or later is on this search head. |
| Some panels stay empty | Not every setup produces every event: rogue AP panels need a WiFi impersonation detection, the firewall/NAT rule panel needs Syslog Logging on firewall policies, and sudo/SSH need gateway syslog. See the add-on README, "Send logs from UniFi". |
| "IPS sources by country" shows Private/Unknown | Splunk's `iplocation` has no country for private or reserved addresses. |
| Alerts never trigger | They ship disabled (see Tuning); check Activity > Triggered Alerts and each alert's throttle. |

## Support

Developer supported, best effort. Report dashboard or detection problems at https://github.com/RossLopez/unifi_security/issues; for parsing or missing fields use https://github.com/RossLopez/TA-unifi_security/issues. Replace real IP addresses, MAC addresses, hostnames, usernames and SSIDs in any log samples you post.

Not supported by Splunk or Ubiquiti.

## Release notes

- **0.2.4** — README: where to install, getting started, detection schedules and throttling, tuning the detections, and troubleshooting.
- **0.2.3** — Documented supported Splunk versions: Enterprise 9.4–10.6, tested on each in Docker.
- **0.2.2** — Dashboard tables: set column widths, readable timestamps, admin table drops the redundant `msg` column; wider firewall rule-log panel.
- **0.2.1** — Splunk Web icons and logos fill the whole square; Splunk 10 showed its blue icon background through the transparent rounded corners.
- **0.2.0** — Searches use the add-on's renamed sourcetypes (`ubiquiti:unifi*`); requires TA-unifi_security 0.2.0 or later.
- **0.1.5** — Author set to Ross Lopez; added support details.
- **0.1.4** — Added app icons and logos (`static/`).
- **0.1.3** — Detections ship disabled, with `schedule_window = auto` and staggered schedules. Added `[id]` stanza and `app.manifest`; update checks enabled.
- **0.1.2** — Apache 2.0 LICENSE included in the package.
- **0.1.1** — Released alongside TA-unifi_security 0.1.1.
- **0.1.0** — Initial build.
