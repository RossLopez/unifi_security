# UniFi Security (unifi_security) v0.1.3

Search-head app with security content for UniFi data. Requires the **UniFi Security Add-on** (`TA-unifi_security`).

## Dashboard

**UniFi Security Overview** (Dashboard Studio): KPI tiles; security events over time; top IPS signatures; IPS sources by country; recent IPS events; firewall blocks by client; top blocked destinations; UniFi OS firewall/NAT rule hits; admin access; WiFi auth failures; rogue APs; sudo/SSH activity.

## Detections

All detections ship **disabled**. Enable the ones you want in Settings > Searches, reports, and alerts. They write to Triggered Alerts only; add email/webhook actions as needed.

| Alert | Schedule | Logic |
|---|---|---|
| IPS Threat Detected | 15 min (:01) | Any IPS detection, grouped by src/dest, with GeoIP; suppressed 4h per pair |
| Outbound IPS Detection From Internal Host | 15 min (:02) | IPS hit where src is internal and dest is external (possible C2 / compromised IoT) |
| Admin Access From New Source | hourly | Admin user + source IP not seen in the previous 30 days |
| Rogue AP Impersonating SSID | hourly | CEF 529 WiFi Impersonation, suppressed 24h per BSSID |
| WiFi Authentication Failure Threshold | hourly | ≥ `unifi_wifi_fail_threshold` (20) WPA failures per client MAC |
| Excessive Firewall Blocks From Client | hourly | ≥ `unifi_fw_block_threshold` (50) blocks per internal client |
| Unexpected sudo On UniFi OS | 15 min (:03) | sudo by an account not in `unifi_sudo_expected_users` |
| SSH Activity On UniFi Device | 15 min (:04) | Any successful SSH login, or 5+ failures from one source |
| New Device On Network | hourly | Client MAC first seen (connect or DHCP) in 30 days |

## Macros to tune

`unifi_index`, `unifi_sudo_expected_users`, `unifi_fw_block_threshold`, `unifi_wifi_fail_threshold`, plus helpers `unifi_is_private(field)` and `unifi_geo(field)`.

## Release notes

- **0.1.3** — Detections ship disabled, with `schedule_window = auto` and staggered schedules. Added `[id]` stanza and `app.manifest`; update checks enabled.
- **0.1.2** — Apache 2.0 LICENSE included in the package.
- **0.1.1** — Released alongside TA-unifi_security 0.1.1.
- **0.1.0** — Initial build.
