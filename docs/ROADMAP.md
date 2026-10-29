# Roadmap — unifi_security

Add-on backlog (parsing, ingestion, CIM): [TA-unifi_security/docs/ROADMAP.md](https://github.com/RossLopez/TA-unifi_security/blob/main/docs/ROADMAP.md).

## Splunkbase readiness

### Must-fix (AppInspect / Splunk Cloud)
- [x] `app.conf`: `[id]` stanza, `check_for_updates = true`, `is_configured` removed. `[triggers]` not needed (only Splunk-native conf files).
- [x] Author: Ross Lopez (`app.conf`, `app.manifest`).
- [x] `app.manifest` (`slim generate-manifest`) with target workloads: search heads.
- [ ] Declare the `TA-unifi_security` dependency in `app.manifest` (requires bundling it via `slim package`; documented in README for now).
- [x] Icons and logos in `static/` (`appIcon` 36/72, `appIconAlt` 36/72, `appLogo` 160x40/320x80); built by `scripts/build_icons.py`, 512px listing icon in `assets/`.
- [x] Support contact: GitHub Issues (README Support section, issue template). Repos must be public before the listing goes live.
- [x] LICENSE (Apache 2.0) and release notes.
- [x] Ship saved searches `disabled = 1`; add `schedule_window = auto`; stagger cron minutes.
- [x] Clean packaging (no `local/`, `local.meta`, hidden files; 644/755 perms; top dir == app id).
- [x] `splunk-appinspect inspect --mode precert --included-tags cloud` clean (AppInspect 4.3.1, 0.1.3). Re-run before every release.

### App content
- [ ] Replace hourly `earliest=-30d` searches (new admin source, new device) with KV store/lookup baselines or `tstats` on accelerated CIM data models.
- [ ] Portable index macro default + setup page (index, thresholds, expected sudo accounts); move sudo allowlist to a lookup.
- [ ] Declare minimum Splunk version (Dashboard Studio: 9.x+).
- [ ] Optional: MITRE ATT&CK annotations, ES RBA / correlation-search compatibility.

### Listing / docs
- [ ] README: install-location table, required add-on version, detection tuning.
- [x] Screenshots (`assets/screenshots/`, taken on `unifi_security/scripts/demo_data.py` data); trademark disclaimer; no Ubiquiti logos.

## Release history
- 0.2.2 — Dashboard tables: set column widths, readable timestamps, admin table drops the redundant `msg` column; wider firewall rule-log panel. Added `scripts/demo_data.py` and listing screenshots.
- 0.2.1 — Splunk Web icons and logos fill the whole square; Splunk 10 showed its blue icon background through the transparent rounded corners.
- 0.2.0 — Macros use the renamed `ubiquiti:unifi*` sourcetypes; requires TA-unifi_security 0.2.0+.
- 0.1.5 — Author set to Ross Lopez; added support details and a GitHub bug report template.
- 0.1.4 — Added app icons and logos (`static/`) and `scripts/build_icons.py`.
- 0.1.3 — AppInspect fixes: detections ship disabled with `schedule_window = auto` and staggered schedules; added `[id]` and `app.manifest`; removed `is_configured`; enabled update checks.
- 0.1.2 — Moved to its own repository; Apache 2.0 LICENSE included in the package.
- 0.1.1 — Released alongside TA-unifi_security 0.1.1 (CEF fields now native `UNIFI*` names).
- 0.1.0 — Initial build.
