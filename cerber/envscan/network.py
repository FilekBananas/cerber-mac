"""Network state: /etc/hosts, DNS resolvers, proxy/PAC settings, listening sockets and connections.

Sockets come from `netstat -anv` (shows the owning pid for every socket without
root on current macOS); `lsof -i` is the fallback.
"""
from __future__ import annotations

import ipaddress
import os
import re
from collections import defaultdict

from ..core import Confidence
from .model import Signal
from .patterns import classify_path, path_signals, redact
from .processes import snapshot
from .util import EnvContext, lstat_info, read_text, run, safe_listdir

N = "Heur:Env.Network"

SENSITIVE_DOMAIN = re.compile(
    r"(?:^|\.)(?:apple\.com|icloud\.com|me\.com|mzstatic\.com|apple-cloudkit\.com|cdn-apple\.com|"
    r"google\.com|googleapis\.com|gstatic\.com|youtube\.com|gmail\.com|microsoft\.com|live\.com|office\.com|"
    r"microsoftonline\.com|windowsupdate\.com|github\.com|githubusercontent\.com|gitlab\.com|mozilla\.org|"
    r"mozilla\.net|firefox\.com|paypal\.com|facebook\.com|instagram\.com|whatsapp\.com|amazon\.com|"
    r"twitter\.com|x\.com|linkedin\.com|dropbox\.com|slack\.com|zoom\.us|anthropic\.com|claude\.ai|openai\.com|"
    r"chatgpt\.com|homebrew\.sh|brew\.sh|pypi\.org|npmjs\.org|npmjs\.com|docker\.com|docker\.io)$", re.I)
BANK_DOMAIN = re.compile(
    r"(?i)(?:bank|pkobp|ipko|mbank|santander|ing\.pl|ingbank|millennium|pekao|aliorbank|credit-agricole|revolut|"
    r"wise\.com|chase\.com|wellsfargo|citi(?:bank)?\.com|hsbc|barclays|coinbase|binance|kraken\.com|bitstamp|"
    r"blockchain\.com|metamask|ledger\.com|trezor\.io|exodus\.com)")
AV_DOMAIN = re.compile(
    r"(?i)(?:virustotal|malwarebytes|sophos|kaspersky|avast|avg\.com|eset\.|norton|symantec|mcafee|bitdefender|"
    r"trendmicro|f-secure|withsecure|crowdstrike|sentinelone|objective-see|clamav|intego|webroot|avira|drweb|"
    r"emsisoft|hybrid-analysis|any\.run|joesandbox|triage\.|abuse\.ch)")
APPLE_SECURITY_HOSTS = {"ocsp.apple.com", "ocsp2.apple.com", "xp.apple.com", "api.apple-cloudkit.com",
                        "swscan.apple.com", "mesu.apple.com", "gdmf.apple.com", "swdist.apple.com", "swcdn.apple.com",
                        "updates.cdn-apple.com", "valid.apple.com", "crl.apple.com", "gs.apple.com",
                        "configuration.apple.com", "xp.itunes-apple.com.akadns.net", "osrecovery.apple.com"}
LICENSING_DOMAIN = re.compile(r"(?i)(?:adobe\.com|adobe\.io|adobelogin\.com|macromedia\.com|autodesk\.com|"
                              r"jetbrains\.com|sketchapp\.com)$")
# DNSChanger (RSPlug / Jahlav) rogue resolver ranges
ROGUE_DNS = [ipaddress.ip_network(n) for n in (
    "85.255.112.0/20", "67.210.0.0/20", "93.188.160.0/21", "77.67.83.0/24", "213.109.64.0/20", "64.28.176.0/20")]
MINER_PORTS = {3333, 4444, 5555, 7777, 14444, 14433, 45700, 45560, 3357, 9999}
BACKDOOR_PORTS = {4444, 1337, 31337, 5555, 6666, 6667, 12345, 54321, 4899, 1234}
COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 1935, 3478, 3479, 3480, 3481,
                5222, 5223, 5228, 5229, 5230, 8080, 8443, 8883, 9001, 9443, 19302, 19303, 19304, 19305, 19306,
                19307, 19308, 19309, 4070, 1119, 3724, 27015, 27016, 27017, 27018, 27019, 27020, 27036, 27037,
                1883, 5349, 8801, 8802, 8803, 8804, 8805, 8806, 8807, 8808, 8809, 8810, 2083, 2087, 2096,
                7000, 7001, 49152, 3000, 5000, 9000, 6443, 11434, 4242, 51820, 1194, 500, 4500}
SHARING_PORTS = {22: "Remote Login (SSH)", 5900: "Screen Sharing / VNC", 3283: "Apple Remote Desktop",
                 445: "File Sharing (SMB)", 548: "File Sharing (AFP)", 3031: "Remote Apple Events",
                 21: "FTP", 23: "Telnet", 88: "Kerberos (local KDC)", 631: "Printer Sharing (CUPS)"}
SCRIPTY = {"osascript", "nc", "ncat", "socat", "bash", "sh", "zsh", "dash", "perl", "ruby", "telnet"}
BROWSERS = re.compile(r"(?i)(chrome|chromium|brave|edge|arc|opera|vivaldi|firefox|safari|webkit)")


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified
                or a.is_reserved)


def _is_loopback_or_null(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return a.is_loopback or a.is_unspecified


# --------------------------------------------------------------------------- hosts

def collect_hosts(ctx: EnvContext) -> None:
    ctx.progress("/etc/hosts")
    body = read_text("/etc/hosts", 8 << 20)
    if body is None:
        ctx.limit("/etc/hosts jest nieczytelny")
        return
    entries = []
    for line in body.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        ip, names = parts[0], [n.lower().rstrip(".") for n in parts[1:]]
        names = [n for n in names if n not in ("localhost", "broadcasthost", "localhost.localdomain", "ip6-localhost",
                                                "ip6-loopback")]
        if names:
            entries.append((ip, names))
    ctx.inventory["hosts"] = {"entries": len(entries), "file": lstat_info("/etc/hosts"),
                              "sample": [f"{ip} {' '.join(n[:3])}" for ip, n in entries[:30]]}
    sigs: list[Signal] = []
    redirects, blocked_sec, blocked_av, blocked_lic = [], [], [], []
    for ip, names in entries:
        for n in names:
            sensitive = SENSITIVE_DOMAIN.search(n) or BANK_DOMAIN.search(n) or AV_DOMAIN.search(n)
            if _is_loopback_or_null(ip) or ip in ("0.0.0.0", "::"):
                if n in APPLE_SECURITY_HOSTS:
                    blocked_sec.append(n)
                elif AV_DOMAIN.search(n):
                    blocked_av.append(n)
                elif LICENSING_DOMAIN.search(n):
                    blocked_lic.append(n)
            elif sensitive:
                redirects.append(f"{n} -> {ip}")
    if redirects:
        public = [r for r in redirects if _is_public(r.rsplit(" -> ", 1)[1])]
        sigs.append(Signal(f"{N}.HostsRedirect", 50 if public else 25, Confidence.HIGH if public else Confidence.MEDIUM,
                           "plik hosts przekierowuje znane/bankowe/bezpieczeństwa domeny"
                           + (" na publiczne adresy IP" if public else " na adresy prywatne"), redirects[:10]))
    if blocked_sec:
        sigs.append(Signal(f"{N}.HostsBlockAppleSecurity", 30, Confidence.MEDIUM,
                           "plik hosts blokuje usługi bezpieczeństwa/aktualizacji Apple (XProtect, OCSP, aktualizacje)", blocked_sec[:10]))
    if blocked_av:
        sigs.append(Signal(f"{N}.HostsBlockSecurityVendor", 35, Confidence.MEDIUM,
                           "plik hosts blokuje strony producentów zabezpieczeń", blocked_av[:10]))
    if blocked_lic:
        sigs.append(Signal(f"{N}.HostsBlockLicensing", 10, Confidence.LOW,
                           "plik hosts blokuje serwery licencji oprogramowania (typowe dla pirackiego oprogramowania)",
                           blocked_lic[:10], pua=True))
    ctx.add_finding("hosts", "Modyfikacja /etc/hosts", "/etc/hosts", sigs,
                    {"redirects": redirects[:50], "blocked_security": blocked_sec, "blocked_vendors": blocked_av,
                     "blocked_licensing": blocked_lic[:50], "entries": len(entries)})


# --------------------------------------------------------------------------- DNS / proxy

def collect_dns_proxy(ctx: EnvContext) -> None:
    ctx.progress("ustawienia DNS i proxy")
    r = run(["/usr/sbin/scutil", "--dns"], timeout=10)
    servers: list[str] = []
    if r.ok:
        main = r.out.split("DNS configuration (for scoped queries)")[0]
        for m in re.finditer(r"nameserver\[\d+\]\s*:\s*(\S+)", main):
            if m.group(1) not in servers:
                servers.append(m.group(1))
    else:
        ctx.limit("scutil --dns nie powiodło się; resolwery DNS nie zostały sprawdzone")
    resolver_files = {}
    for n in safe_listdir("/etc/resolver")[0]:
        body = read_text(os.path.join("/etc/resolver", n), 64 << 10) or ""
        resolver_files[n] = re.findall(r"^\s*nameserver\s+(\S+)", body, re.M)
    ctx.inventory["dns"] = {"nameservers": servers, "resolver_files": resolver_files}
    ctx.posture["dns_servers"] = servers
    sigs: list[Signal] = []
    for s in servers:
        try:
            a = ipaddress.ip_address(s.split("%")[0])
        except ValueError:
            continue
        if any(a in net for net in ROGUE_DNS if a.version == net.version):
            sigs.append(Signal(f"{N}.RogueDNS", 60, Confidence.HIGH,
                               "resolwer DNS w znanym złośliwym zakresie DNSChanger", [s]))
    for dom, ns in resolver_files.items():
        if SENSITIVE_DOMAIN.search(dom) or BANK_DOMAIN.search(dom):
            sigs.append(Signal(f"{N}.ResolverOverride", 30, Confidence.MEDIUM,
                               f"/etc/resolver nadpisuje DNS dla wrażliwej domeny {dom}", ns[:3]))
    ctx.add_finding("dns", "Konfiguracja DNS", "scutil --dns", sigs, {"nameservers": servers,
                                                                      "resolver_files": resolver_files})

    r = run(["/usr/sbin/scutil", "--proxy"], timeout=10)
    if not r.ok:
        ctx.limit("scutil --proxy nie powiodło się; ustawienia proxy nie zostały sprawdzone")
        return
    kv = dict(re.findall(r"^\s*(\w+)\s*:\s*(.+?)\s*$", r.out, re.M))
    proxies = {}
    for kind in ("HTTP", "HTTPS", "SOCKS", "FTP", "RTSP", "Gopher"):
        if kv.get(f"{kind}Enable") == "1":
            proxies[kind] = f"{kv.get(f'{kind}Proxy', '?')}:{kv.get(f'{kind}Port', '?')}"
    pac = kv.get("ProxyAutoConfigURLString") if kv.get("ProxyAutoConfigEnable") == "1" else None
    wpad = kv.get("ProxyAutoDiscoveryEnable") == "1"
    ctx.inventory["proxy"] = {"proxies": proxies, "pac_url": redact(pac) if pac else None, "auto_discovery": wpad}
    ctx.posture["proxy"] = ctx.inventory["proxy"]
    sigs = []
    for kind, hp in proxies.items():
        host = hp.rsplit(":", 1)[0]
        if host in ("127.0.0.1", "localhost", "::1"):
            sigs.append(Signal(f"{N}.LocalProxy", 5, Confidence.LOW,
                               f"ruch {kind} przechodzi przez lokalne proxy (narzędzie debugujące, VPN lub przechwytywanie)", [hp]))
        elif _is_public(host) or not re.match(r"^[\d.:]+$", host):
            sigs.append(Signal(f"{N}.RemoteProxy", 20, Confidence.MEDIUM,
                               f"ruch {kind} jest kierowany przez zdalne proxy", [hp]))
        else:
            sigs.append(Signal(f"{N}.LanProxy", 5, Confidence.LOW, f"proxy {kind} w sieci lokalnej", [hp]))
    if pac:
        m = re.match(r"^(\w+)://([^/:]+)", pac)
        scheme, host = (m.group(1).lower(), m.group(2)) if m else ("", "")
        if scheme == "file":
            sigs += path_signals(pac[7:], f"{N}.PAC", "plik automatycznej konfiguracji proxy")
            sigs.append(Signal(f"{N}.PACFile", 15, Confidence.MEDIUM, "automatyczna konfiguracja proxy wczytana z pliku lokalnego",
                               [redact(pac)]))
        elif host in ("127.0.0.1", "localhost") or not _is_public(host) and re.match(r"^[\d.]+$", host or "x"):
            sigs.append(Signal(f"{N}.PACLocal", 5, Confidence.LOW, "automatyczna konfiguracja proxy serwowana lokalnie", [redact(pac)]))
        else:
            sigs.append(Signal(f"{N}.PACRemote", 25, Confidence.MEDIUM,
                               "automatyczna konfiguracja proxy pobierana ze zdalnego URL (technika adware/przejmowania "
                               "ruchu lub konfiguracja firmowa)", [redact(pac)]))
    if wpad:
        sigs.append(Signal(f"{N}.WPAD", 5, Confidence.LOW, "włączone automatyczne wykrywanie proxy (WPAD)", []))
    ctx.add_finding("network", "Systemowa konfiguracja proxy", "scutil --proxy", sigs, ctx.inventory["proxy"],
                    allow_zero=False)


# --------------------------------------------------------------------------- sockets

_NETSTAT_RX = re.compile(
    r"^(?P<proto>(?:tcp|udp)(?:4|6|46))\s+\d+\s+\d+\s+(?P<local>\S+)\s+(?P<remote>\S+)\s+"
    r"(?:(?P<state>[A-Z_0-9]+)\s+)?\d+\s+\d+\s+\d+\s+\d+\s+(?P<proc>.*?):(?P<pid>\d+)\s+[0-9a-f]{5}\s")


def _split_addr(a: str) -> tuple[str, int | None]:
    if a in ("*.*",):
        return "*", None
    host, _, port = a.rpartition(".")
    try:
        return host, int(port)
    except ValueError:
        return a, None


def _sockets(ctx: EnvContext) -> list[dict]:
    socks: list[dict] = []
    ok = False
    for proto in ("tcp", "udp"):
        r = run(["/usr/sbin/netstat", "-anv", "-p", proto], timeout=20)
        if not r.ok:
            continue
        for line in r.out.splitlines():
            m = _NETSTAT_RX.match(line)
            if not m:
                continue
            ok = True
            lh, lp = _split_addr(m.group("local"))
            rh, rp = _split_addr(m.group("remote"))
            socks.append({"proto": m.group("proto"), "local": lh, "lport": lp, "remote": rh, "rport": rp,
                          "state": m.group("state") or "", "pid": int(m.group("pid")),
                          "pname": m.group("proc").strip()})
    if ok:
        ctx.inventory["network_source"] = "netstat -anv"
        return socks
    # fallback: lsof (only the current user's processes without root)
    r = run(["/usr/sbin/lsof", "-nP", "-i", "-FpcnPtT"], timeout=30)
    if not r.ok and not r.out:
        ctx.limit("nie udało się wyliczyć gniazd sieciowych (netstat i lsof zawiodły)")
        return socks
    if not ctx.is_root:
        ctx.limit("gniazda sieciowe wyliczone przez lsof: bez roota widoczne są tylko procesy bieżącego użytkownika")
    pid, cmd, proto, state = None, "", "", ""
    for line in r.out.splitlines():
        if not line:
            continue
        k, v = line[0], line[1:]
        if k == "p":
            pid = int(v)
        elif k == "c":
            cmd = v
        elif k == "P":
            proto = v.lower()
        elif k == "T" and v.startswith("ST="):
            state = v[3:]
            if socks and socks[-1]["pid"] == pid:
                socks[-1]["state"] = state
        elif k == "n":
            local, _, remote = v.partition("->")
            lh, _, lp = local.rpartition(":")
            rh, _, rp = remote.rpartition(":")
            socks.append({"proto": proto, "local": lh.strip("[]") or "*", "lport": int(lp) if lp.isdigit() else None,
                          "remote": rh.strip("[]") or "*", "rport": int(rp) if rp.isdigit() else None,
                          "state": "", "pid": pid, "pname": cmd})
    ctx.inventory["network_source"] = "lsof"
    return socks


def collect_network(ctx: EnvContext) -> None:
    ctx.progress("gniazda sieciowe")
    socks = _sockets(ctx)
    procs = snapshot(ctx)
    home = ctx.homes[0].home if ctx.homes else None
    listeners: dict[int, list[str]] = defaultdict(list)
    conns: dict[int, list[dict]] = defaultdict(list)
    sharing: set[str] = set()
    inv_listen = ctx.inv("listeners")
    system_pids = {1} | {p for p, i in procs.items() if (i.get("exe") or "").startswith(("/usr/", "/System/"))
                         and not (i.get("exe") or "").startswith("/usr/local/")}
    for s in socks:
        if s["state"] == "LISTEN" or (s["proto"].startswith("udp") and s["remote"] == "*" and s["lport"]):
            wildcard = s["local"] in ("*", "0.0.0.0", "::", "")
            if s["state"] == "LISTEN":
                inv_listen.append({"proto": s["proto"], "address": f"{s['local']}:{s['lport']}", "pid": s["pid"],
                                   "process": s["pname"]})
                if wildcard and s["lport"] in SHARING_PORTS and s["pid"] in system_pids:
                    sharing.add(SHARING_PORTS[s["lport"]])
            if wildcard and s["state"] == "LISTEN":
                listeners[s["pid"]].append(f"{s['proto']} *:{s['lport']}")
        elif s["remote"] not in ("*", "") and s["rport"]:
            conns[s["pid"]].append(s)
    ctx.posture["sharing_services"] = sorted(sharing)
    ctx.posture["remote_login"] = "Remote Login (SSH)" in sharing
    ctx.posture["screen_sharing"] = "Screen Sharing / VNC" in sharing

    def proc_desc(pid: int) -> tuple[dict, str, bool]:
        info = procs.get(pid, {})
        exe = info.get("exe") or ""
        apple = bool(exe) and classify_path(exe).has("apple")
        return info, exe, apple

    fw_block_all = ctx.posture.get("firewall_state") == 2
    for pid, ports in sorted(listeners.items()):
        info, exe, apple = proc_desc(pid)
        if apple or pid in (0, 1):
            continue
        name = info.get("name") or next((s["pname"] for s in socks if s["pid"] == pid), str(pid))
        sigs = [Signal(f"{N}.PublicListener", 0, Confidence.INFO,
                       "proces spoza Apple nasłuchuje na wszystkich interfejsach sieciowych"
                       + (" (połączenia przychodzące blokuje zapora)" if fw_block_all else ""), ports[:10])]
        if exe:
            si = ctx.sign(exe) if os.path.exists(exe) else None
            loc = [s for s in path_signals(exe, f"{N}.Listener", "program nasłuchujący", home)
                   if not s.name.endswith("UserDocsPath")]
            sigs += EnvContext.dampen_trusted(loc, si)
            if si and si.status == "unsigned":
                sigs.append(Signal(f"{N}.UnsignedListener", 20, Confidence.MEDIUM,
                                   "niepodpisany program przyjmuje połączenia sieciowe", [exe]))
        bports = sorted({int(p.rsplit(":", 1)[1]) for p in ports if p.rsplit(":", 1)[1].isdigit()} & BACKDOOR_PORTS)
        if bports:
            sigs.append(Signal(f"{N}.BackdoorPort", 20, Confidence.MEDIUM,
                               "nasłuchuje na porcie typowym dla backdoorów/bind shell", [str(p) for p in bports]))
        if os.path.basename(exe) in SCRIPTY:
            sigs.append(Signal(f"{N}.ScriptListener", 30, Confidence.MEDIUM,
                               f"'{os.path.basename(exe)}' nasłuchuje w sieci (bind shell?)", ports[:5]))
        ctx.add_finding("network", f"{name} (pid {pid}) nasłuchuje na wszystkich interfejsach", f"pid {pid}", sigs,
                        {"pid": pid, "exe": exe, "ports": ports}, allow_zero=True)

    conn_inv = ctx.inv("connections")
    for pid, cs in sorted(conns.items()):
        info, exe, apple = proc_desc(pid)
        public = [c for c in cs if _is_public(c["remote"])]
        name = info.get("name") or (cs[0]["pname"] if cs else str(pid))
        conn_inv.append({"pid": pid, "process": name, "connections": len(cs), "public": len(public),
                         "remote_ports": sorted({c["rport"] for c in public})[:20]})
        if apple or not public:
            continue
        base = os.path.basename(exe) if exe else name
        is_browser = bool(BROWSERS.search(exe or name))
        si = ctx.sign(exe) if exe and os.path.exists(exe) else None
        weak = bool(si and si.weak and not classify_path(exe).has("pkgmgr"))
        sigs = []
        miner = sorted({f"{c['remote']}:{c['rport']}" for c in public if c["rport"] in MINER_PORTS})
        if miner:
            sigs.append(Signal(f"{N}.MinerPort", 10 if is_browser else 30,
                               Confidence.LOW if is_browser else Confidence.MEDIUM,
                               "połączenie z portem typowym dla pul kopania kryptowalut / RAT", miner[:5],
                               pua=not is_browser))
        odd = sorted({f"{c['remote']}:{c['rport']}" for c in public if c["rport"] not in COMMON_PORTS
                      and c["rport"] not in MINER_PORTS and c["rport"] < 49152})
        if odd and (weak or base in SCRIPTY):
            sigs.append(Signal(f"{N}.UnusualPort", 15, Confidence.LOW,
                               "proces niepodpisany/ad-hoc lub skryptowy łączy się z publicznymi IP na nietypowych portach", odd[:5]))
        if base in SCRIPTY:
            sigs.append(Signal(f"{N}.ScriptConnection", 20, Confidence.MEDIUM,
                               f"'{base}' utrzymuje połączenie z publicznym adresem IP",
                               sorted({f"{c['remote']}:{c['rport']}" for c in public})[:5]))
        if exe and si and si.status == "unsigned":
            sigs.append(Signal(f"{N}.UnsignedClient", 10, Confidence.LOW,
                               "niepodpisany program łączy się z publicznymi adresami IP", [exe]))
        ctx.add_finding("network", f"Połączenia wychodzące {name} (pid {pid})", f"pid {pid}", sigs,
                        {"pid": pid, "exe": exe, "remote": sorted({f"{c['remote']}:{c['rport']}" for c in public})[:30]})
    ctx.inventory["network_summary"] = {"sockets": len(socks), "listening_processes": len(listeners),
                                        "processes_with_connections": len(conns)}
