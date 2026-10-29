#!/usr/bin/env python3
"""Generate sanitized demo UniFi syslog for screenshots and trying the app.

Writes events in the relay format the add-on expects (relay header + device
header), spread over the last N hours. Every address, MAC, name and domain is
a placeholder: RFC1918/RFC5737 IPs, 02:11:22:33:44:xx / aa:bb:cc:dd:ee:xx MACs
and example.* domains. RFC5737 sources have no GeoIP country, so the "IPS
sources by country" panel shows Private/Unknown.

Usage:  python3 scripts/demo_data.py [--hours 24] [--seed 7] > demo.log
Load:   splunk add oneshot demo.log -index unifi -sourcetype ubiquiti:unifi
"""
import argparse, datetime as dt, json, random

RELAY = "192.168.1.5"
UDM = "unifi DreamMachinePro"
APS = [("192.168.1.7", "aabbccddee01", "U6-Pro"), ("192.168.1.8", "aabbccddee02", "U6-Extender")]
NET_VER, OS_VER = "10.6.109", "5.1.33"

ATTACKERS = [f"198.51.100.{n}" for n in (14, 23, 58, 77, 131, 202)] + [f"203.0.113.{n}" for n in (45, 88, 150, 199)]
SIGS = [  # (signature, sid, policy, risk, cef severity, dest port)
    ("ET DROP Dshield Block Listed Source group 1", 2402000, "DShield Block List", "medium", 7, 443),
    ("ET SCAN Suspicious inbound to MSSQL port 1433", 2010935, "Scan", "medium", 6, 1433),
    ("ET SCAN Suspicious inbound to PostgreSQL port 5432", 2010939, "Scan", "medium", 6, 5432),
    ("ET SCAN NMAP -sS window 1024", 2009582, "Scan", "low", 4, 22),
    ("ET CINS Active Threat Intelligence Poor Reputation IP group 42", 2403341, "CINS Army List", "high", 8, 8443),
    ("ET COMPROMISED Known Compromised or Hostile Host Traffic group 7", 2500012, "Compromised Hosts", "high", 8, 3389),
]
OUT_SIGS = [("ET POLICY Observed DNS Query to .onion proxy Domain", 2014939, "Policy", "medium", 6, 53),
            ("ET INFO Possible Crypto Miner Pool Connection", 2027866, "Malware", "high", 8, 3333)]
CLIENTS = [  # (alias, hostname, ip, mac, model, network)
    ("Living Room TV", "SmartTV", "192.168.30.75", "02:11:22:33:44:02", "Android Smart TV", "IoT"),
    ("Thermostat", "thermostat", "192.168.30.21", "02:11:22:33:44:07", "Smart Thermostat", "IoT"),
    ("Doorbell Camera", "doorbell", "192.168.30.33", "02:11:22:33:44:08", "Video Doorbell", "IoT"),
    ("Kids Tablet", "tablet-01", "192.168.20.41", "02:11:22:33:44:09", "Android Tablet", "Family"),
    ("Game Console 2", "console", "192.168.30.12", "02:11:22:33:44:01", "Game Console", "IoT"),
    ("Workstation", "Workstation", "192.168.1.240", "02:11:22:33:44:03", "Desktop", "Default"),
]
BLOCKED = [("ads.example.net", "198.51.100.6", "HTTPS"), ("telemetry.example.com", "198.51.100.9", "HTTPS"),
           ("tracker.example.org", "203.0.113.31", "HTTPS"), ("metrics.example.net", "203.0.113.64", "HTTP"),
           ("ntp.example.org", "192.0.2.123", "NTP")]
ADMINS = [("Jane Admin", "web", "192.168.1.240"), ("Sam Ops", "web", "192.168.1.52")]


def hdr(t, device):
    s = t.strftime("%b %d %H:%M:%S")
    return f"{s} {RELAY} {s} {device}"


def cef(t, product, ver, sid, name, sev, ext):
    return f"{hdr(t, 'unifi')} CEF:0|Ubiquiti|{product}|{ver}|{sid}|{name}|{sev}|{ext}"


def utc(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def ips(t, rnd, outbound=False):
    if outbound:
        sig, sid, policy, risk, sev, dpt = rnd.choice(OUT_SIGS)
        c = rnd.choice(CLIENTS[:4])
        src, dst, spt, direction, zone = c[2], rnd.choice(ATTACKERS), rnd.randint(40000, 65000), "outgoing", "External"
    else:
        sig, sid, policy, risk, sev, dpt = rnd.choice(SIGS)
        src, dst, spt, direction, zone = rnd.choice(ATTACKERS), "192.168.1.1", rnd.randint(1024, 65000), "incoming", "Internal"
    return cef(t, "UniFi Network", NET_VER, 200, "Threat Detected", sev,
               f"UNIFIcategory=Security UNIFIhost=Dream Machine Pro proto=TCP spt={spt} dpt={dpt} act=allowed app=Other "
               f"UNIFIrisk={risk} UNIFIpolicyName={policy} UNIFIpolicyType=IDS/IPS UNIFIdirection={direction} "
               f"UNIFIdeviceMac=aa:bb:cc:dd:ee:00 UNIFIdeviceName=Dream Machine Pro UNIFIdeviceModel=UDM-Pro "
               f"UNIFIdeviceIp=192.168.1.1 UNIFIdeviceVersion={OS_VER} src={src} dst={dst} UNIFIdstZone={zone} "
               f"UNIFItotalBytes={rnd.randint(60, 1500)} UNIFItotalPackets={rnd.randint(1, 4)} "
               f"UNIFIipsSessionId={rnd.randint(10**13, 10**14)} UNIFIipsSignature={sig} UNIFIipsSignatureId={sid} "
               f"UNIFIutcTime={utc(t)} msg=A network intrusion attempt from {src} to {dst} has been detected.")


def fw_block(t, rnd):
    alias, hostname, ip, mac, model, net = rnd.choice(CLIENTS[:5])
    domain, dst, app = rnd.choice(BLOCKED)
    proto = "UDP" if app == "NTP" else rnd.choice(["TCP", "UDP"])
    dpt = {"HTTPS": 443, "HTTP": 80, "NTP": 123}[app]
    return cef(t, "UniFi Network", NET_VER, 203, "Blocked by Firewall", 4,
               f"UNIFIcategory=Security UNIFIhost=Dream Machine Pro proto={proto} spt={rnd.randint(30000, 65000)} dpt={dpt} "
               f"act=blocked app={app} UNIFIrisk=low UNIFIpolicyName=Block IoT Telemetry UNIFIpolicyType=Firewall "
               f"UNIFIdirection=outgoing UNIFIdeviceInboundInterface={net} UNIFIdeviceOutboundInterface=Internet 1 dst={dst} "
               f"UNIFIsrcClientAlias={alias} UNIFIsrcClientHostname={hostname} UNIFIsrcClientIp={ip} UNIFIsrcClientMac={mac} "
               f"UNIFIsrcClientModel={model} UNIFIsrcZone=Internal UNIFIdstZone=External UNIFIdstDomain={domain} "
               f"UNIFItotalBytes={rnd.randint(60, 1500)} UNIFItotalPackets=1 UNIFIutcTime={utc(t)} "
               f"msg={alias} was blocked from accessing {dst} by Block IoT Telemetry.")


def admin(t, rnd):
    if rnd.random() < 0.3:
        return cef(t, "UniFi OS", OS_VER, 1000, "Admin Accessed UniFi OS", 1,
                   f"UNIFIhost=Host UNIFIdeviceName=Dream Machine Pro UNIFIdeviceModel=UDMPRO UNIFIdeviceIp=203.0.113.10 "
                   f"UNIFIdeviceMac=AA:BB:CC:DD:EE:00 UNIFIdeviceVersion={OS_VER} UNIFIadmin=Jane Admin "
                   f"UNIFIaccessMethod=unifi.ui.com msg=Jane Admin accessed the UniFi OS using unifi.ui.com. Source IP: 203.0.113.10")
    name, method, ip = rnd.choice(ADMINS)
    return cef(t, "UniFi Network", NET_VER, 544, "Network Accessed", 4,
               f"UNIFIcategory=Audit UNIFIhost=Dream Machine Pro UNIFIaccessMethod={method} UNIFIadmin={name} src={ip} "
               f"UNIFIutcTime={utc(t)} msg={name} accessed UniFi Network using the {method}. Source IP: {ip}")


def rogue(t, rnd):
    ch, sig = rnd.choice([(64, 19), (64, 22), (149, 14)])
    return cef(t, "UniFi Network", NET_VER, 529, "WiFi Impersonation Detected", 6,
               f"UNIFIcategory=UniFi Devices UNIFIhost=Dream Machine Pro UNIFIdetectedByApAndSignalStrength=Access Point "
               f"WiFi 6 Extender, aa:bb:cc:dd:ee:02, {sig} UNIFIdetectedByQty=1 UNIFIwifiChannel={ch} UNIFIwifiName=HomeWiFi "
               f"UNIFIwifiBand=na UNIFIbssid=02:aa:bb:cc:dd:ee UNIFIutcTime={utc(t)} msg=Access Point WiFi 6 Extender "
               f"detected a third-party AP broadcasting HomeWiFi on channel {ch} with a signal strength of {sig}.")


def wifi_fail(t, rnd):
    ip, mac, model = rnd.choice(APS)
    sta = rnd.choice(["02:11:22:33:44:05", "02:11:22:33:44:05", "02:11:22:33:44:0a", "02:11:22:33:44:0b"])
    body = json.dumps({"message_type": "STA_ASSOC_TRACKER", "mac": sta, "vap": "wifi0ap1", "event_type": "failure",
                       "assoc_status": "0", "auth_failures": str(rnd.randint(1, 4)), "event_id": "2",
                       "sta_dc_reason": "sta left"}, separators=(",", ":"))
    return f"{hdr(t, ip)} {mac},{model}-6.8.2+15592: stahtd: stahtd[3805]: [STA-TRACKER].stahtd_dump_event(): {body}"


def sudo(t, rnd):
    cmd = rnd.choice(["/sbin/ubnt-tools id", "/usr/bin/ubios-udapi-client GET /system", "/sbin/ubnt-tools hwaddr"])
    return f"{hdr(t, UDM)} sudo[{rnd.randint(1000, 30000)}]: ucs-update : PWD=/data/unifi-identity-update ; USER=root ; COMMAND={cmd}"


def ssh(t, rnd):
    if rnd.random() < 0.6:
        return f"{hdr(t, UDM)} sshd[{rnd.randint(1000, 30000)}]: Accepted publickey for root from 192.168.1.240 port {rnd.randint(40000, 65000)} ssh2"
    return (f"{hdr(t, UDM)} sshd[{rnd.randint(1000, 30000)}]: Failed password for invalid user admin from 192.168.1.66 "
            f"port {rnd.randint(40000, 65000)} ssh2")


def fw_rule(t, rnd):
    src = rnd.choice(["192.168.1.46", "192.168.1.240", "192.168.20.41"])
    return (f"{hdr(t, UDM)} [PREROUTING-DNAT-3] DESCR=\"PortForward DNAT [media]\" IN=br0 OUT= "
            f"MAC=aa:bb:cc:dd:ee:00:02:11:22:33:44:04:08:00 SRC={src} DST=203.0.113.10 LEN=60 TOS=00 PREC=0x00 TTL=64 "
            f"ID={rnd.randint(1000, 65000)} DF PROTO=TCP SPT={rnd.randint(30000, 65000)} DPT=32400 SYN URGP=0 MARK=1a0000")


def noise(t, rnd):
    c = rnd.choice(CLIENTS)
    ip, mac, model = rnd.choice(APS)
    return rnd.choice([
        f"{hdr(t, UDM)} dnsmasq-dhcp[3211200]: DHCPACK(br0) {c[2]} {c[3]} {c[1]}",
        f"{hdr(t, UDM)} mcad[4667]: udapi-cfg._udapi_lu_set_inform_interval(): Changing LU inform interval 20 -> 1 (cur-state=ON)",
        f"{hdr(t, ip)} {mac},{model}-6.8.2+15592: hostapd[3808]: wifi0ap1: STA {c[3]} IEEE 802.11: associated",
        f"{hdr(t, '192.168.1.3')} aabbccddee03,US-8-60W-7.5.15+17146: switch: LLDP: LLDP event 2 is not processed, intIfNum 1",
        cef(t, "UniFi Protect", "7.3.70", 2159, "motion", 3,
            f"category=detection eventId=00000000-0000-4000-8000-{rnd.randint(0, 10**12):012d} eventType=motion "
            f"category=detection severity=3 timestamp={int(t.timestamp() * 1000)} msg=\"G4 Instant has recorded motion.\""),
    ])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rnd = random.Random(args.seed)
    end = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    span = args.hours * 3600

    def times(n, burst=None):
        out = [end - dt.timedelta(seconds=rnd.uniform(0, span)) for _ in range(n)]
        if burst:  # a scan: many events inside one 20-minute window
            start = end - dt.timedelta(seconds=burst[0] * span)
            out += [start + dt.timedelta(seconds=rnd.uniform(0, 1200)) for _ in range(burst[1])]
        return out

    events = []
    for gen, n, burst in ((lambda t: ips(t, rnd), 45, (0.35, 30)), (lambda t: ips(t, rnd, True), 6, None),
                          (lambda t: fw_block(t, rnd), 140, None), (lambda t: admin(t, rnd), 9, None),
                          (lambda t: rogue(t, rnd), 5, None), (lambda t: wifi_fail(t, rnd), 28, (0.7, 10)),
                          (lambda t: sudo(t, rnd), 12, None), (lambda t: ssh(t, rnd), 7, None),
                          (lambda t: fw_rule(t, rnd), 24, None), (lambda t: noise(t, rnd), 300, None)):
        events += [(t, gen(t)) for t in times(n, burst)]
    for _, line in sorted(events):
        print(line)


if __name__ == "__main__":
    main()
