# Roadmap — unifi_security

Add-on backlog (parsing, ingestion, CIM): [TA-unifi_security/docs/ROADMAP.md](https://github.com/RossLopez/TA-unifi_security/blob/main/docs/ROADMAP.md).

## Splunkbase readiness

### Must-fix (AppInspect / Splunk Cloud)
- [ ] `app.conf`: add `[id]` stanza (name, version), `check_for_updates = true`, `[triggers] reload.* = simple`, publisher name.
- [ ] `app.manifest` (`slim generate-manifest`) with target workloads: search heads; declare dependency on `TA-unifi_security`.
- [ ] Icons (`appIcon.png` 36x36, `appIcon_2x.png` 72x72, Alt variants, `appLogo.png`), support contact.
- [x] LICENSE (Apache 2.0) and release notes.
- [ ] Ship saved searches `disabled = 1`; add `schedule_window = auto`; stagger cron minutes.
- [ ] Clean packaging (no `local/`, `local.meta`, hidden files; correct perms; top dir == app id).
- [ ] `splunk-appinspect inspect --mode precert --included-tags cloud` clean.

### App content
- [ ] Replace hourly `earliest=-30d` searches (new admin source, new device) with KV store/lookup baselines or `tstats` on accelerated CIM data models.
- [ ] Portable index macro default + setup page (index, thresholds, expected sudo accounts); move sudo allowlist to a lookup.
- [ ] Declare minimum Splunk version (Dashboard Studio: 9.x+).
- [ ] Optional: MITRE ATT&CK annotations, ES RBA / correlation-search compatibility.

### Listing / docs
- [ ] README: install-location table, required add-on version, detection tuning.
- [ ] Screenshots; trademark disclaimer; no Ubiquiti logos.

## Release history
- 0.1.2 — Moved to its own repository; Apache 2.0 LICENSE included in the package.
- 0.1.1 — Released alongside TA-unifi_security 0.1.1 (CEF fields now native `UNIFI*` names).
- 0.1.0 — Initial build.
