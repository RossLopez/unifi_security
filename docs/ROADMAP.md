# Roadmap — unifi_security

Add-on backlog (parsing, ingestion, CIM): [TA-unifi_security/docs/ROADMAP.md](https://github.com/RossLopez/TA-unifi_security/blob/main/docs/ROADMAP.md).

## Splunkbase readiness

### Must-fix (AppInspect / Splunk Cloud)
- [x] `app.conf`: `[id]` stanza, `check_for_updates = true`, `is_configured` removed. `[triggers]` not needed (only Splunk-native conf files).
- [ ] Publisher / author name for the listing (`author = Ross` today).
- [x] `app.manifest` (`slim generate-manifest`) with target workloads: search heads.
- [ ] Declare the `TA-unifi_security` dependency in `app.manifest` (requires bundling it via `slim package`; documented in README for now).
- [ ] Icons (`appIcon.png` 36x36, `appIcon_2x.png` 72x72, Alt variants, `appLogo.png`), support contact.
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
- [ ] Screenshots; trademark disclaimer; no Ubiquiti logos.

## Release history
- 0.1.3 — AppInspect fixes: detections ship disabled with `schedule_window = auto` and staggered schedules; added `[id]` and `app.manifest`; removed `is_configured`; enabled update checks.
- 0.1.2 — Moved to its own repository; Apache 2.0 LICENSE included in the package.
- 0.1.1 — Released alongside TA-unifi_security 0.1.1 (CEF fields now native `UNIFI*` names).
- 0.1.0 — Initial build.
