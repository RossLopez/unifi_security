#!/usr/bin/env python3
"""Test the app and add-on against Splunk versions in throwaway Docker containers.

For each version: start splunk/splunk:<version> (linux/amd64, ports bound to
localhost only), install both packages, load demo data from demo_data.py, then
check that
  - both apps installed at the expected version,
  - every demo event was indexed and routed to the four ubiquiti:unifi* sourcetypes,
  - every eventtype the dashboard and detections use matches events,
  - every dashboard data source and every saved search runs without errors,
and save a screenshot of the dashboard (needs `pip install playwright` and
Google Chrome; skipped otherwise) for a visual check. Usage reporting to Splunk
is switched off in each container. Containers are removed afterwards unless
--keep is given.

Running Splunk's image accepts the Splunk General Terms and license.

Usage:  python3 scripts/compat_test.py --ta <TA.spl> --app <app.spl> 9.4.16 10.0.11 ...
"""
import argparse, base64, json, os, pathlib, re, secrets, shutil, ssl, subprocess, sys, tarfile, tempfile, time
import urllib.error, urllib.parse, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
MGMT, WEB = 18089, 18000
SOURCETYPES = {"ubiquiti:unifi", "ubiquiti:unifi:cef", "ubiquiti:unifi:ap", "ubiquiti:unifi:switch"}
EVENTTYPES = {"unifi_ips_threat", "unifi_firewall_block", "unifi_admin_access", "unifi_rogue_ap",
              "unifi_wifi_auth_failure", "unifi_sudo", "unifi_ssh_auth", "unifi_fw_rule_log",
              "unifi_dhcp_lease", "unifi_protect_detection"}
CTX = ssl._create_unverified_context()


def app_info(spl):
    """(app id, version) from the package's default/app.conf."""
    with tarfile.open(spl) as t:
        out = t.extractfile(next(m for m in t.getmembers() if m.name.endswith("/default/app.conf"))).read().decode()
    name = re.search(r"^\[package\][^\[]*?^id = (\S+)", out, re.M | re.S).group(1)
    return name, re.search(r"^\[launcher\][^\[]*?^version = (\S+)", out, re.M | re.S).group(1)


class Splunk:
    def __init__(self, password):
        self.auth = "Basic " + base64.b64encode(f"admin:{password}".encode()).decode()

    def rest(self, path, data=None, ns="servicesNS/admin/unifi_security"):
        url = f"https://127.0.0.1:{MGMT}/{ns}/{path}"
        body = urllib.parse.urlencode({**(data or {}), "output_mode": "json"}).encode() if data is not None else None
        if body is None:
            url += ("&" if "?" in url else "?") + "output_mode=json"
        req = urllib.request.Request(url, data=body, headers={"Authorization": self.auth})
        try:
            with urllib.request.urlopen(req, context=CTX, timeout=300) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return json.loads(e.read() or b"{}") | {"http_status": e.code}

    def search(self, q, earliest="-24h"):
        """Oneshot search in the app's namespace -> (rows, error messages)."""
        r = self.rest("search/jobs", {"search": q if q.lstrip().startswith("|") else "search " + q, "exec_mode": "oneshot",
                                      "earliest_time": earliest, "latest_time": "now", "count": 0})
        errors = [m["text"] for m in r.get("messages", []) if m.get("type") in ("ERROR", "FATAL")]
        return r.get("results", []), errors


def docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check).stdout.strip()


def wait_healthy(name, timeout=1200):
    end = time.time() + timeout
    while time.time() < end:
        state = docker("inspect", "-f", "{{.State.Status}} {{.State.Health.Status}}", name, check=False)
        if state.endswith("healthy") and "unhealthy" not in state:
            return
        if state.startswith(("exited", "dead")):
            raise RuntimeError(f"container {state}: " + docker("logs", "--tail", "20", name, check=False))
        time.sleep(10)
    raise RuntimeError("timed out waiting for Splunk to start")


def screenshot(password, path):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return "skipped (playwright not installed)"
    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome", headless=True)
        pg = b.new_page(viewport={"width": 1600, "height": 2200})
        console = []
        pg.on("console", lambda m: console.append(m.text) if m.type == "error" else None)
        pg.on("response", lambda r: console.append(f"HTTP {r.status} {r.url}") if r.status >= 400 else None)
        pg.goto(f"http://localhost:{WEB}/en-US/account/login")
        pg.fill("#username", "admin")
        pg.fill("#password", password)
        pg.keyboard.press("Enter")
        pg.wait_for_url("**/app/**")
        pg.goto(f"http://localhost:{WEB}/en-US/app/unifi_security/unifi_security_overview"
                "?form.global_time.earliest=-24h&form.global_time.latest=now")
        time.sleep(20)
        pg.screenshot(path=str(path))
        b.close()
    return f"{path.name}, {len(console)} console error(s)" + "".join(f"\n    - {c[:200]}" for c in console)


def run(version, ta, app, demo, out, keep):
    name = f"unifi-compat-{version}"
    password = "Compat-" + secrets.token_urlsafe(12)
    s = Splunk(password)
    work = pathlib.Path(tempfile.mkdtemp(prefix="unifi-compat-"))
    for f in (ta, app, demo):
        shutil.copy(f, work)
        os.chmod(work / pathlib.Path(f).name, 0o644)
    os.chmod(work, 0o755)
    results, ok = [], True

    def check(label, passed, detail=""):
        nonlocal ok
        ok &= bool(passed)
        results.append(f"  [{'PASS' if passed else 'FAIL'}] {label}" + (f": {detail}" if detail else ""))

    docker("rm", "-f", name, check=False)
    docker("run", "-d", "--name", name, "--platform", "linux/amd64",
           "-p", f"127.0.0.1:{WEB}:8000", "-p", f"127.0.0.1:{MGMT}:8089",
           "-e", "SPLUNK_START_ARGS=--accept-license", "-e", "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com",
           "-e", f"SPLUNK_PASSWORD={password}", "-e", "TZ=UTC",
           "-e", f"SPLUNK_APPS_URL=/test/{pathlib.Path(ta).name},/test/{pathlib.Path(app).name}",
           "-v", f"{work}:/test:ro", f"splunk/splunk:{version}")
    try:
        wait_healthy(name)
        tel = "servicesNS/nobody/splunk_instrumentation"
        opt_in = s.rest("admin/telemetry/general", ns=tel).get("entry", [{}])[0].get("content", {}).get("optInVersion", 1)
        s.rest("admin/telemetry/general", {"sendAnonymizedUsage": "false", "sendLicenseUsage": "false",
                                           "sendSupportUsage": "false", "sendAnonymizedWebAnalytics": "false",
                                           "optInVersionAcknowledged": opt_in, "showOptInModal": "0"}, ns=tel)
        for spl in (ta, app):
            appid, ver = app_info(spl)
            got = s.rest(f"apps/local/{appid}", ns="services").get("entry", [{}])[0].get("content", {}).get("version")
            check(f"{appid} installed", got == ver, f"version {got}")

        s.rest("data/indexes", {"name": "unifi"}, ns="services")
        docker("exec", "-u", "splunk", name, "/opt/splunk/bin/splunk", "add", "oneshot", f"/test/{demo.name}",
               "-index", "unifi", "-sourcetype", "ubiquiti:unifi", "-auth", f"admin:{password}")
        expected, count = len(demo.read_text().splitlines()), 0
        for _ in range(30):
            count = int(s.search("index=unifi | stats count")[0][0]["count"])
            if count >= expected:
                break
            time.sleep(5)
        check("demo events indexed", count == expected, f"{count}/{expected}")

        rows, _ = s.search("index=unifi | stats count by sourcetype")
        check("sourcetype routing", {r["sourcetype"] for r in rows} == SOURCETYPES,
              ", ".join(f"{r['sourcetype']}={r['count']}" for r in rows))
        rows, _ = s.search("index=unifi | stats count by eventtype")
        missing = EVENTTYPES - {r["eventtype"] for r in rows}
        check("eventtypes", not missing, "missing " + ", ".join(sorted(missing)) if missing else f"{len(EVENTTYPES)} matched")
        rows, _ = s.search("index=unifi eventtype=unifi_ips_threat | where isnull(src) OR isnull(dest) OR isnull(signature) "
                           "OR isnull(action) OR isnull(severity) | stats count")
        check("IPS CIM fields (src dest signature action severity)", rows and rows[0]["count"] == "0")

        view = s.rest("data/ui/views/unifi_security_overview").get("entry", [{}])[0].get("content", {}).get("eai:data", "")
        definition = json.loads(re.search(r"<definition><!\[CDATA\[(.*?)\]\]></definition>", view, re.S).group(1))
        bad = []
        for key, ds in definition["dataSources"].items():
            rows, errors = s.search(ds["options"]["query"])
            if errors or not rows:
                bad.append(f"{key}: {errors or 'no results'}")
        check(f"dashboard searches ({len(definition['dataSources'])})", not bad, "; ".join(bad))

        saved = s.rest("saved/searches?count=0&search=eai:acl.app%3Dunifi_security")["entry"]
        bad = []
        for e in saved:
            _, errors = s.search(e["content"]["search"], e["content"].get("dispatch.earliest_time") or "-24h")
            if errors:
                bad.append(f"{e['name']}: {errors}")
        check(f"saved searches ({len(saved)})", saved and not bad, "; ".join(bad))

        results.append("  screenshot: " + screenshot(password, out / f"dashboard_{version}.png"))
    except Exception as e:  # report and carry on with the next version
        check("run", False, repr(e))
    finally:
        if not keep:
            docker("rm", "-f", name, check=False)
        shutil.rmtree(work, ignore_errors=True)
    return ok, results


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("versions", nargs="+", help="splunk/splunk image tags, e.g. 9.4.16 10.6.1")
    ap.add_argument("--ta", required=True, help="TA-unifi_security .spl")
    ap.add_argument("--app", required=True, help="unifi_security .spl")
    ap.add_argument("--out", default=str(ROOT / "dist" / "compat"), help="directory for screenshots (default dist/compat)")
    ap.add_argument("--keep", action="store_true", help="leave the last container running")
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    demo = out / "demo.log"
    demo.write_text(subprocess.run([sys.executable, str(ROOT / "scripts" / "demo_data.py")],
                                   capture_output=True, text=True, check=True).stdout)
    summary = []
    for i, v in enumerate(args.versions):
        print(f"== Splunk {v}", flush=True)
        ok, lines = run(v, args.ta, args.app, demo, out, args.keep and i == len(args.versions) - 1)
        print("\n".join(lines), flush=True)
        summary.append(f"{v}: {'PASS' if ok else 'FAIL'}")
    print("\n" + "\n".join(summary))
    sys.exit(0 if all(l.endswith("PASS") for l in summary) else 1)


if __name__ == "__main__":
    main()
