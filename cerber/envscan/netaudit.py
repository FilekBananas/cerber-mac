"""Network & remote-access audit (the "Mega" laptop level).

Two collectors fill one dict, ``ctx.inventory["network_audit"]``, with the NETWORK structure of
app/PROTOCOL.md (boot_time, summary, listening, connections, traffic, traffic_history,
remote_access, sessions, logins):

* ``netaudit_traffic``: listening sockets (who accepts connections and from where), outgoing
  connections (checked against the local ThreatFox/URLhaus IOC database, reverse DNS of public
  peers), bytes sent/received per process since boot (``nettop``) and the long-term per-process
  history kept by macOS in netusage.sqlite (needs Full Disk Access / root). Findings: live
  connections to known C2/malware addresses, script/unsigned programs talking to public IPs on
  unusual ports, possible data exfiltration (large uploads by unsigned or oddly located programs).
* ``netaudit_remote``: macOS sharing services (Remote Login, Screen Sharing, Remote Management,
  Remote Apple Events, File Sharing), third-party remote-control tools (installed / running /
  connected), tunnels and reverse proxies (ngrok, cloudflared, ssh -R ...), VPN/mesh networks,
  current sessions (``who``), login history (``last``), SSH authorized_keys and MDM enrollment.

summary: listening_all_interfaces = distinct (pid, TCP port) listening on every interface;
public_connections = distinct (process, public endpoint) pairs; processes_online = processes with a
public connection; remote_tools = third-party remote-control tools (installed or running) + running
tunnels (VPN/mesh networks are listed but not counted); ioc_hits = connections to IOC addresses;
uploaded_bytes_since_boot = sum of nettop bytes_out of the running processes.

Read-only by design: query commands with timeouts and without a shell, never sudo, nothing is
changed. The only network activity is reverse DNS of at most 60 public peers (~8 s budget).
Texts shown to the user are Polish; keys are English.
"""
from __future__ import annotations

import ipaddress
import os
import queue
import re
import socket
import sqlite3
import threading
import time
import urllib.parse

from ..core import Confidence
from .model import Signal, combine, severity_of
from .network import BACKDOOR_PORTS, COMMON_PORTS, MINER_PORTS, _is_public, _sockets, _split_addr
from .patterns import classify_path, is_apple_path, redact
from .processes import APPLE_DAEMON_NAMES, snapshot
from .util import EnvContext, load_plist, read_text, run, safe_listdir

NA = "Heur:Env.NetAudit"
RA = "Heur:Env.Remote"
MB = 1 << 20
GB = 1 << 30

NETUSAGE_DB = "/private/var/networkd/db/netusage.sqlite"
CORE_DATA_EPOCH = 978307200          # 2001-01-01 00:00:00 UTC (Core Data / NSDate reference)
MAX_CONNECTIONS = 600
MAX_TRAFFIC = 60
MAX_HISTORY = 100
MAX_DNS = 60
DNS_BUDGET = 8.0
FDA_REASON = "wymaga Pełnego dostępu do dysku lub uprawnień administratora"

# Where third-party remote-control tools get installed (tests patch these).
APP_DIRS = ["/Applications"]
SYSTEM_LAUNCH_DIRS = ["/Library/LaunchAgents", "/Library/LaunchDaemons"]
EXTRA_DIRS = ["/Library/PrivilegedHelperTools", "/usr/local", "/opt"]
ARD_LAUNCHD_FLAG = "/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd"

# --------------------------------------------------------------------------- small helpers


def _pl(n: int, one: str, few: str, many: str) -> str:
    if n == 1:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def fmt_bytes(n: int | float | None) -> str:
    n = int(n or 0)
    for unit, size in (("GB", GB), ("MB", MB), ("kB", 1 << 10)):
        if n >= size:
            return f"{n / size:.1f} {unit}".replace(".", ",")
    return f"{n} B"


def fmt_ts(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(epoch)))
    except (OverflowError, OSError, ValueError):
        return None


def _ip(addr: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        a = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return None
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        return a.ipv4_mapped
    return a


def normalize_ip(addr: str) -> str:
    """'::ffff:1.2.3.4' -> '1.2.3.4'; anything else unchanged."""
    a = _ip(addr)
    if a is not None and isinstance(a, ipaddress.IPv4Address) and ":" in addr:
        return str(a)
    return addr


_CGNAT = ipaddress.ip_network("100.64.0.0/10")   # carrier-grade NAT / Tailscale addresses: not the Internet


def is_public_ip(addr: str) -> bool:
    a = _ip(addr)
    if a is None:
        return False
    if a.version == 4 and a in _CGNAT:
        return False
    return _is_public(str(a))


def is_loopback(addr: str) -> bool:
    if "%lo0" in addr or addr == "localhost":
        return True
    a = _ip(addr)
    return bool(a and a.is_loopback)


def exposure_of(addr: str) -> str:
    """all = every interface (reachable from the network), localhost = this Mac only, specific = one address."""
    if addr in ("*", "", "0.0.0.0", "::", "*.*"):
        return "all"
    if is_loopback(addr):
        return "localhost"
    a = _ip(addr)
    if a is not None and a.is_unspecified:
        return "all"
    return "specific"


def _base(name: str | None) -> str:
    b = os.path.basename(name or "").lower()
    return re.sub(r"[\d.]+$", "", b) or b


# Large anycast/CDN ranges shared by thousands of unrelated sites: an IOC hit there is weak evidence.
SHARED_NETS = [ipaddress.ip_network(n) for n in (
    # Cloudflare
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16", "2a04:4e40::/32",
    # Google front ends
    "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19", "172.253.0.0/16", "74.125.0.0/16",
    "209.85.128.0/17", "2a00:1450::/32", "2607:f8b0::/32",
    # Amazon CloudFront edges
    "13.32.0.0/15", "13.224.0.0/14", "18.64.0.0/14", "52.84.0.0/15", "54.230.0.0/16", "54.239.128.0/18",
    "99.84.0.0/16", "143.204.0.0/16", "205.251.192.0/19", "216.137.32.0/19",
    # Microsoft front door
    "13.107.0.0/16",
)]


def is_shared_ip(addr: str) -> bool:
    a = _ip(addr)
    return bool(a) and any(a.version == n.version and a in n for n in SHARED_NETS)


# --------------------------------------------------------------------------- signer labels

def signer_label(info) -> str:
    st = info.status
    if st == "apple":
        return "Apple"
    if st == "appstore":
        return f"Mac App Store ({info.team_id or '?'})"
    if st == "devid":
        return "Developer ID: " + info.authority.split(":", 1)[-1].strip()
    if st == "development":
        return f"certyfikat deweloperski ({info.authority})"
    return {"adhoc": "ad-hoc (bez tożsamości twórcy)", "unsigned": "brak podpisu",
            "notcode": "skrypt (nie jest podpisywany)", "missing": "plik nie istnieje",
            "other": f"nieznany wystawca ({info.authority or '?'})",
            "error": "nie sprawdzono"}.get(st, st)


def _sign(ctx: EnvContext, exe: str | None):
    """(label, SignInfo|None) for an executable; Apple system paths are not codesigned again."""
    if not exe:
        return None, None
    if is_apple_path(exe):
        return "Apple", None
    if not os.path.exists(exe):
        return "plik nie istnieje", None
    si = ctx.sign(exe)
    return signer_label(si), si


def _proc_name_exe(procs: dict, pid: int | None, fallback: str = "") -> tuple[str, str | None]:
    info = procs.get(pid) or {}
    name = info.get("name") or fallback or (f"pid {pid} (proces zakończony)" if pid is not None else "?")
    return name, info.get("exe") or None


# --------------------------------------------------------------------------- shared state

def _audit(ctx: EnvContext) -> dict:
    with ctx._lock:
        a = ctx.inventory.get("network_audit")
        if not isinstance(a, dict):
            a = {"boot_time": None,
                 "summary": {"listening_all_interfaces": 0, "public_connections": 0, "processes_online": 0,
                             "remote_tools": 0, "ioc_hits": 0, "uploaded_bytes_since_boot": 0},
                 "listening": [], "connections": [], "traffic": [],
                 "traffic_history": {"available": False, "reason": "nie sprawdzono", "items": []},
                 "remote_access": [], "sessions": [], "logins": []}
            ctx.inventory["network_audit"] = a
        return a


# `netstat -anvl`: like network._sockets, but -l prints full IPv6 addresses (without it they are cut to
# ~16 characters, which breaks public/IOC checks of IPv6 peers) and rxbytes/txbytes are kept per socket.
_NETSTAT_RX = re.compile(
    r"^(?P<proto>(?:tcp|udp)(?:4|6|46))\s+\d+\s+\d+\s+(?P<local>\S+)\s+(?P<remote>\S+)\s+"
    r"(?:(?P<state>[A-Z_0-9]+)\s+)?(?P<rx>\d+)\s+(?P<tx>\d+)\s+\d+\s+\d+\s+(?P<proc>.*?):(?P<pid>\d+)\s+[0-9a-f]{5}\s")


def parse_netstat(text: str) -> list[dict]:
    socks = []
    for line in (text or "").splitlines():
        m = _NETSTAT_RX.match(line)
        if not m:
            continue
        lh, lp = _split_addr(m.group("local"))
        rh, rp = _split_addr(m.group("remote"))
        socks.append({"proto": m.group("proto"), "local": lh, "lport": lp, "remote": rh, "rport": rp,
                      "state": m.group("state") or "", "pid": int(m.group("pid")), "pname": m.group("proc").strip(),
                      "rx": int(m.group("rx")), "tx": int(m.group("tx"))})
    return socks


def _socks(ctx: EnvContext) -> list[dict]:
    cached = getattr(ctx, "_netaudit_socks", None)
    if cached is None:
        cached = []
        for proto in ("tcp", "udp"):
            r = run(["/usr/sbin/netstat", "-anvl", "-p", proto], timeout=20)
            if r.ok:
                cached += parse_netstat(r.out)
        if not cached:
            cached = _sockets(ctx)   # netstat without -l, or lsof
        ctx._netaudit_socks = cached  # type: ignore[attr-defined]
    return cached


def _risk(signals: list[Signal]) -> str:
    det = combine(signals) if signals else None
    if det is None or det.score <= 0:
        return "info"
    sev = severity_of(det)
    return {"pua": "suspicious"}.get(sev, sev)


# --------------------------------------------------------------------------- listening sockets

PORT_SERVICES: dict[int, str] = {
    21: "Serwer FTP", 22: "Zdalne logowanie (SSH)", 23: "Telnet (nieszyfrowane zdalne logowanie)",
    53: "Serwer DNS", 67: "Serwer DHCP", 80: "Serwer WWW (HTTP)", 88: "Kerberos (lokalny KDC)",
    137: "NetBIOS (nazwy w sieci Windows)", 138: "NetBIOS (datagramy)", 139: "NetBIOS / SMB",
    443: "Serwer WWW (HTTPS)", 445: "Udostępnianie plików (SMB)", 548: "Udostępnianie plików (AFP)",
    631: "Udostępnianie drukarek (CUPS)", 873: "Serwer rsync", 1900: "UPnP / SSDP (wykrywanie urządzeń)",
    2049: "Udostępnianie plików (NFS)", 3031: "Zdalne zdarzenia Apple (Remote Apple Events)",
    3283: "Apple Remote Desktop", 3306: "Baza danych MySQL", 3389: "Pulpit zdalny (RDP)",
    3478: "STUN/TURN (rozmowy audio-wideo)", 4000: "NoMachine (NX)", 4444: "Port typowy dla backdoorów (4444)",
    5000: "AirPlay (odbiornik) / serwer deweloperski", 5353: "Bonjour (mDNS)", 5432: "Baza danych PostgreSQL",
    5900: "Udostępnianie ekranu (VNC)", 5938: "TeamViewer", 6379: "Baza danych Redis", 6568: "AnyDesk",
    7000: "AirPlay (odbiornik)", 7070: "AnyDesk", 8080: "Serwer WWW (HTTP, port alternatywny)",
    8443: "Serwer WWW (HTTPS, port alternatywny)", 9993: "ZeroTier", 11434: "Ollama (lokalne modele AI)",
    27017: "Baza danych MongoDB", 31337: "Port typowy dla backdoorów (31337)", 41641: "Tailscale",
    51820: "WireGuard VPN", 62078: "Synchronizacja z iPhone/iPad",
}
PORT_SERVICES.update({p: "Serwer VNC (dodatkowy ekran)" for p in range(5901, 5910)})
PORT_SERVICES.update({p: "RustDesk" for p in range(21115, 21120)})


def service_for(port: int | None, process: str | None = None, exe: str | None = None) -> str | None:
    if process or exe:
        tool = match_remote_tool(f"{process or ''} {exe or ''}") if not (exe and is_apple_path(exe)) else None
        if tool:
            return tool[1]
    return PORT_SERVICES.get(port or -1)


def build_listening(socks: list[dict], procs: dict) -> list[dict]:
    """LISTEN TCP sockets + bound UDP sockets, one entry per (proto, address, port, pid)."""
    out: list[dict] = []
    seen: set[tuple] = set()
    for s in socks:
        tcp_listen = s.get("state") == "LISTEN"
        udp_bound = str(s.get("proto", "")).startswith("udp") and s.get("remote") in ("*", "") and s.get("lport")
        if not (tcp_listen or udp_bound):
            continue
        local = s.get("local") or "*"
        key = (s["proto"], local, s.get("lport"), s.get("pid"))
        if key in seen:
            continue
        seen.add(key)
        name, exe = _proc_name_exe(procs, s.get("pid"), s.get("pname", ""))
        out.append({"proto": s["proto"], "address": normalize_ip(local) if local != "*" else "*",
                    "port": s.get("lport"), "exposure": exposure_of(local), "process": name, "pid": s.get("pid"),
                    "exe": exe, "signer": None, "service": service_for(s.get("lport"), name, exe)})
    rank = {"all": 0, "specific": 1, "localhost": 2}
    out.sort(key=lambda d: (rank[d["exposure"]], 0 if d["proto"].startswith("tcp") else 1, d["port"] or 0,
                            d["pid"] or 0, d["proto"]))
    return out


# --------------------------------------------------------------------------- outgoing connections

def build_connections(socks: list[dict], procs: dict) -> list[dict]:
    """Every non-listening socket with a remote endpoint that leaves this Mac (loopback skipped)."""
    out: list[dict] = []
    seen: dict[tuple, dict] = {}
    for s in socks:
        if s.get("state") == "LISTEN":
            continue
        remote = s.get("remote") or ""
        if remote in ("*", "") or not s.get("rport") or is_loopback(remote):
            continue
        remote = normalize_ip(remote)
        udp = str(s.get("proto", "")).startswith("udp")
        state = s.get("state") or ("UDP" if udp else "")
        key = (s.get("pid"), remote, s["rport"])     # one entry per process & endpoint (live state preferred)
        prev = seen.get(key)
        if prev is not None:
            if prev["state"] != "ESTABLISHED" and state == "ESTABLISHED":
                prev["state"] = state
            continue
        name, exe = _proc_name_exe(procs, s.get("pid"), s.get("pname", ""))
        c = {"process": name, "pid": s.get("pid"), "exe": exe, "remote": remote, "port": s["rport"],
             "host": None, "state": state, "public": is_public_ip(remote), "ioc": None}
        seen[key] = c
        out.append(c)
    out.sort(key=lambda c: (not c["public"], c["process"].lower(), c["pid"] or 0, c["remote"], c["port"]))
    return out


def format_ioc(threat: str) -> str:
    src, _, fam = (threat or "").partition(".")
    if src == "ThreatFox":
        what = "serwer C2 / infrastruktura złośliwego oprogramowania"
    elif src == "URLhaus":
        what = "serwer rozsyłający złośliwe oprogramowanie"
    else:
        what = "adres z listy zagrożeń"
    return f"{src or 'IOC'}: {fam or 'unknown'} – {what}"


def _ioc_lookup(ctx: EnvContext):
    """ip -> threat label | None, backed by the local IOC database (cerber.config.IOCDB)."""
    try:
        from .. import config
        path = config.IOCDB
    except Exception:  # noqa: BLE001
        path = ""
    if not path or not os.path.isfile(path):
        ctx.limit("Baza wskaźników zagrożeń (IOC) jest niedostępna – połączeń nie porównano z listą "
                  "znanych serwerów C2 (zaktualizuj bazy)")
        return None
    try:
        from ..engines.ioc_fuzzy import IocService
        svc = IocService(path)

        def look(ip: str) -> str | None:
            return svc.lookup("ip", ip)
    except Exception:  # noqa: BLE001 - engine import problems must not hide the network audit
        con = sqlite3.connect(f"file:{urllib.parse.quote(path)}?mode=ro&immutable=1", uri=True)

        def look(ip: str) -> str | None:
            row = con.execute("SELECT threat FROM ioc WHERE kind='ip' AND value=?", (ip.lower(),)).fetchone()
            return row[0] if row else None

    def safe(ip: str) -> str | None:
        try:
            return look(ip)
        except sqlite3.Error:
            return None
    return safe


def reverse_dns(ips: list[str], budget: float = DNS_BUDGET, workers: int = 16) -> dict[str, str | None]:
    """PTR names via the system resolver in daemon threads; whatever is not done after `budget` s is dropped."""
    results: dict[str, str | None] = {}
    if not ips:
        return results
    q: queue.Queue = queue.Queue()
    for ip in ips:
        q.put(ip)
    lock = threading.Lock()

    def worker() -> None:
        while True:
            try:
                ip = q.get_nowait()
            except queue.Empty:
                return
            try:
                host = socket.gethostbyaddr(ip)[0]
            except Exception:  # noqa: BLE001 - herror/gaierror/timeout
                host = None
            with lock:
                results[ip] = host.rstrip(".") if host else None

    threads = [threading.Thread(target=worker, daemon=True, name="cerber-rdns") for _ in range(min(workers, len(ips)))]
    for t in threads:
        t.start()
    deadline = time.monotonic() + budget
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    with lock:
        return dict(results)


# --------------------------------------------------------------------------- traffic (nettop)

def parse_nettop(text: str) -> list[dict]:
    """`nettop -P -L 1 -x -J bytes_in,bytes_out` CSV: 'name.pid,bytes_in,bytes_out,'."""
    rows: dict[int, dict] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith(","):
            continue
        parts = line.rstrip(",").rsplit(",", 2)
        if len(parts) != 3:
            continue
        ident, b_in, b_out = (p.strip() for p in parts)
        name, dot, pid = ident.rpartition(".")
        if not dot or not pid.isdigit() or not b_in.isdigit() or not b_out.isdigit():
            continue
        r = {"name": name, "pid": int(pid), "bytes_in": int(b_in), "bytes_out": int(b_out)}
        cur = rows.get(r["pid"])
        if cur is None or r["bytes_in"] + r["bytes_out"] > cur["bytes_in"] + cur["bytes_out"]:
            rows[r["pid"]] = r
    return sorted(rows.values(), key=lambda r: (-r["bytes_out"], -r["bytes_in"], r["pid"]))


def parse_boottime(text: str) -> float | None:
    m = re.search(r"\bsec\s*=\s*(\d+)", text or "")
    return float(m.group(1)) if m else None


# --------------------------------------------------------------------------- traffic history (netusage.sqlite)

def read_netusage(path: str = NETUSAGE_DB, limit: int = MAX_HISTORY) -> tuple[list[dict], str | None]:
    """Per-process totals with first/last activity from macOS' network-usage database (read-only)."""
    parent = os.path.dirname(path)
    _, err = safe_listdir(parent)
    if err == "missing":
        return [], "baza historii ruchu (netusage.sqlite) nie istnieje na tym Macu"
    con = None
    last_err = ""
    base = "file:" + urllib.parse.quote(path)
    for q in ("?mode=ro", "?mode=ro&immutable=1"):
        try:
            con = sqlite3.connect(base + q, uri=True, timeout=2)
            con.execute("SELECT count(*) FROM sqlite_master").fetchone()
            break
        except sqlite3.Error as e:
            last_err = str(e)
            if con is not None:
                con.close()
            con = None
    if con is None:
        if err == "denied" or "unable to open" in last_err or "authoriz" in last_err:
            return [], FDA_REASON
        return [], f"nie udało się odczytać bazy historii ruchu ({last_err or 'błąd'})"
    try:
        tables = {r[0].upper(): r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "ZPROCESS" not in tables or "ZLIVEUSAGE" not in tables:
            return [], "nieznany format bazy historii ruchu (netusage.sqlite)"

        def cols(t: str) -> set[str]:
            return {str(r[1]).upper() for r in con.execute(f'PRAGMA table_info("{tables[t]}")')}
        pc, lc = cols("ZPROCESS"), cols("ZLIVEUSAGE")
        fk = "ZHASPROCESS" if "ZHASPROCESS" in lc else next((c for c in sorted(lc) if c.endswith("PROCESS")), None)
        name_col = "ZPROCNAME" if "ZPROCNAME" in pc else ("ZBUNDLENAME" if "ZBUNDLENAME" in pc else None)
        if not fk or not name_col or "Z_PK" not in pc:
            return [], "nieznany format bazy historii ruchu (netusage.sqlite)"
        ins = [c for c in ("ZWIFIIN", "ZWIREDIN", "ZWWANIN") if c in lc]
        outs = [c for c in ("ZWIFIOUT", "ZWIREDOUT", "ZWWANOUT") if c in lc]
        s_in = " + ".join(f"COALESCE(l.{c}, 0)" for c in ins) or "0"
        s_out = " + ".join(f"COALESCE(l.{c}, 0)" for c in outs) or "0"
        bundle = "p.ZBUNDLENAME" if "ZBUNDLENAME" in pc and name_col != "ZBUNDLENAME" else "NULL"
        l_ts = "l.ZTIMESTAMP" if "ZTIMESTAMP" in lc else "NULL"
        p_first = "p.ZFIRSTTIMESTAMP" if "ZFIRSTTIMESTAMP" in pc else "NULL"
        p_last = "p.ZTIMESTAMP" if "ZTIMESTAMP" in pc else "NULL"
        sql = (f"SELECT p.{name_col}, {bundle}, SUM({s_in}), SUM({s_out}), MIN({l_ts}), MAX({l_ts}), "
               f"MIN({p_first}), MAX({p_last}) FROM ZLIVEUSAGE l JOIN ZPROCESS p ON l.{fk} = p.Z_PK GROUP BY p.Z_PK")
        agg: dict[str, dict] = {}

        def ts(v) -> float | None:
            try:
                f = float(v)
            except (TypeError, ValueError):
                return None
            return f if 0 < f < 4e9 else None
        for name, bname, b_in, b_out, l_min, l_max, p_first_v, p_last_v in con.execute(sql):
            label = str(name or bname or "?")
            proc, _, bid = label.partition("/")
            if not bid and bname and bname != proc:
                bid = str(bname)
            label = f"{proc} ({bid})" if bid else proc
            firsts = [t for t in (ts(l_min), ts(p_first_v)) if t is not None]
            lasts = [t for t in (ts(l_max), ts(p_last_v)) if t is not None]
            cur = agg.setdefault(label, {"process": label, "bytes_out": 0, "bytes_in": 0, "_first": None, "_last": None})
            cur["bytes_out"] += int(b_out or 0)
            cur["bytes_in"] += int(b_in or 0)
            if firsts:
                f = min(firsts)
                cur["_first"] = f if cur["_first"] is None else min(cur["_first"], f)
            if lasts:
                la = max(lasts)
                cur["_last"] = la if cur["_last"] is None else max(cur["_last"], la)
        items = sorted(agg.values(), key=lambda r: (-r["bytes_out"], -r["bytes_in"], r["process"]))[:limit]
        for r in items:
            first, last = r.pop("_first"), r.pop("_last")
            r["first_seen"] = fmt_ts(CORE_DATA_EPOCH + first) if first is not None else None
            r["last_seen"] = fmt_ts(CORE_DATA_EPOCH + last) if last is not None else None
        return items, None
    except sqlite3.Error as e:
        if "authoriz" in str(e) or "unable to open" in str(e):
            return [], FDA_REASON
        return [], f"nie udało się odczytać bazy historii ruchu ({e})"
    finally:
        con.close()


# --------------------------------------------------------------------------- heuristics (pure)

SCRIPT_NAMES = {"bash", "sh", "zsh", "dash", "fish", "ksh", "tcsh", "csh", "python", "perl", "ruby", "php", "node",
                "osascript", "nc", "ncat", "netcat", "socat", "curl", "wget", "telnet", "openssl", "pwsh", "tclsh",
                "expect", "lua", "deno", "bun"}
# Ports used by ordinary developer / database / messaging traffic, in addition to network.COMMON_PORTS.
DEV_PORTS = {22, 873, 1433, 1521, 2376, 3306, 4000, 4222, 5001, 5432, 5671, 5672, 6379, 7687, 8000, 8008, 8081,
             8088, 8888, 9090, 9091, 9092, 9200, 9300, 9418, 10000, 11211, 15672, 25565, 26257, 6380, 5439, 7474}
BENIGN_UPLOADERS = re.compile(
    r"(?i)(google chrome|chromium|brave browser|microsoft edge|firefox|safari|/arc\.app/|opera|vivaldi|orion|"
    r"dropbox|google drive|googledrive|onedrive|icloud|/box\.app/|boxsync|pcloud|megasync|nextcloud|owncloud|"
    r"synology|resilio|syncthing|backblaze|bzserv|bztransmit|/arq|carbon copy cloner|superduper|crashplan|code42|"
    r"idrive|acronis|slack|zoom\.us|microsoft teams|webex|skype|discord|whatsapp|telegram|signal\.app|messenger|"
    r"/obs\.app/|streamlabs|steam|battle\.net|epic games|creative cloud|adobe|figma|canva|notion|spotify|docker|"
    r"orbstack|claude|chatgpt|codex|cursor|visual studio code|code helper|xcode|jetbrains|github desktop|"
    r"transmit|cyberduck|filezilla|forklift|lightroom|lm studio|ollama)")


def odd_location(exe: str, home: str | None = None) -> list[str]:
    """Polish descriptions of the unusual places an executable runs from ([] = ordinary place)."""
    pi = classify_path(exe, home)
    if pi.has("apple"):
        return []
    out = []
    if pi.has("tmp"):
        out.append("katalog tymczasowy (/tmp)")
    elif pi.has("varfolders") and not pi.has("translocated"):
        out.append("folder tymczasowy (/var/folders)")
    if pi.has("shared"):
        out.append("/Users/Shared")
    if pi.has("trash"):
        out.append("Kosz")
    if pi.has("hidden"):
        out.append("ukryty katalog")
    if pi.has("random_appsupport", "random_library"):
        out.append("katalog o losowej nazwie")
    if pi.has("volume"):
        out.append("zamontowany dysk lub obraz")
    if not out and not pi.has("pkgmgr", "app_bundle") and re.match(r"^/Users/[^/]+/Library/", pi.path):
        out.append("~/Library (poza pakietem aplikacji)")
    return out


def exfil_signals(exe: str, bytes_out: int, bytes_in: int, sign_status: str, signer: str = "",
                  home: str | None = None) -> list[Signal]:
    """Possible data exfiltration: who uploaded a lot, from where, and how well is it signed."""
    if not exe or bytes_out <= 0:
        return []
    vol = f"wysłano {fmt_bytes(bytes_out)}, pobrano {fmt_bytes(bytes_in)}"
    if is_apple_path(exe) or sign_status == "apple":
        # Apple's own daemons are not judged; Apple's curl/python/osascript/nc are the stealers' upload channel
        base = _base(exe)
        if base in SCRIPT_NAMES and bytes_out >= 20 * MB and bytes_out > bytes_in:
            return [Signal(f"{NA}.SystemToolUpload", 25, Confidence.MEDIUM,
                           f"systemowe narzędzie '{base}' wysłało {fmt_bytes(bytes_out)} (więcej niż pobrało) – "
                           "programy wykradające dane często wysyłają pliki właśnie przez curl/python/osascript; "
                           "sprawdź, czy to Twoja praca", [exe, vol])]
        return []
    pi = classify_path(exe, home)
    trusted = sign_status in ("apple", "appstore", "devid")
    weak = sign_status in ("adhoc", "unsigned", "other", "development")
    pkg = pi.has("pkgmgr")
    odd = [] if pkg else odd_location(exe, home)
    big = bytes_out >= 50 * MB and bytes_out > bytes_in
    sigs: list[Signal] = []
    if odd and bytes_out >= 5 * MB:
        s = Signal(f"{NA}.UploadOddLocation", 30, Confidence.MEDIUM,
                   f"program uruchomiony z nietypowego miejsca ({', '.join(odd)}) wysłał {fmt_bytes(bytes_out)} danych",
                   [exe, vol])
        if trusted:
            s = s.scaled(0.4, f"plik podpisany: {signer}")
        sigs.append(s)
    if weak and not pkg:
        what = "bez podpisu cyfrowego" if sign_status == "unsigned" else "bez zaufanego podpisu twórcy"
        if big:
            sigs.append(Signal(f"{NA}.LargeUploadUnsigned", 40 if sign_status == "unsigned" else 35, Confidence.MEDIUM,
                               f"program {what} wysłał {fmt_bytes(bytes_out)} – więcej niż pobrał (możliwy wyciek danych)",
                               [exe, vol]))
        elif odd and bytes_out >= 5 * MB:
            sigs.append(Signal(f"{NA}.WeakSignedUpload", 15, Confidence.LOW,
                               f"program {what} z nietypowego miejsca wysyła dane", [exe, vol]))
    if pkg and big and bytes_out >= 500 * MB:
        sigs.append(Signal(f"{NA}.LargeUploadTool", 5, Confidence.LOW,
                           "narzędzie z menedżera pakietów (np. Homebrew) wysłało dużo danych – sprawdź, czy to Twoja "
                           "praca (git push, wysyłka plików, kopia)", [exe, vol]))
    if trusted and not odd and bytes_out >= GB and bytes_out > bytes_in and not BENIGN_UPLOADERS.search(exe):
        sigs.append(Signal(f"{NA}.LargeUpload", 5, Confidence.LOW,
                           f"podpisana aplikacja ({signer}) wysłała ponad 1 GB – zwykle synchronizacja lub kopia "
                           "zapasowa", [exe, vol]))
    return sigs


def unusual_port(port: int | None) -> bool:
    return bool(port) and port not in COMMON_PORTS and port not in DEV_PORTS and port < 49152


def script_connection_signals(exe: str | None, name: str, sign_status: str | None, pkgmgr: bool,
                              public_conns: list[dict]) -> list[Signal]:
    """Script interpreters / unsigned programs talking to public IPs on unusual ports."""
    base = _base(exe or name)
    script = base in SCRIPT_NAMES
    weak = sign_status in ("adhoc", "unsigned", "other") and not pkgmgr
    if not (script or weak):
        return []
    odd = [c for c in public_conns if unusual_port(c.get("port"))]
    if not odd:
        return []
    eps = sorted({f"{c['remote']}:{c['port']}" for c in odd})
    bad = sorted({f"{c['remote']}:{c['port']}" for c in odd if c["port"] in BACKDOOR_PORTS | MINER_PORTS})
    who = f"interpreter/skrypt '{base}'" if script else "program bez zaufanego podpisu"
    if pkgmgr:                     # Homebrew tool, local build, or a script from a project / package folder
        return [Signal(f"{NA}.DevToolBackdoorPort", 15, Confidence.LOW,
                       f"{who} (kod deweloperski) łączy się na porcie typowym dla backdoorów lub koparek", bad[:5])] \
            if bad else []
    if bad:
        return [Signal(f"{NA}.ScriptBackdoorPort", 35, Confidence.MEDIUM,
                       f"{who} łączy się z publicznym adresem na porcie typowym dla backdoorów lub koparek kryptowalut",
                       bad[:5])]
    return [Signal(f"{NA}.ScriptUnusualPort", 20, Confidence.MEDIUM,
                   f"{who} łączy się z publicznym adresem na nietypowym porcie", eps[:5])]


# --------------------------------------------------------------------------- collector: traffic

def _already_flagged(ctx: EnvContext, pid: int | None) -> bool:
    loc = f"pid {pid}"
    return any(f.category == "network" and f.location == loc and f.score >= 10 for f in ctx.findings)


def collect_traffic(ctx: EnvContext) -> None:
    ctx.progress("audyt sieci: porty, połączenia i ruch")
    audit = _audit(ctx)
    summary = audit["summary"]
    home = ctx.homes[0].home if ctx.homes else None

    # nettop needs ~5 s for one sample: run it while sockets / IOC / DNS are processed
    nettop_box: dict = {}

    def _nettop() -> None:
        nettop_box["r"] = run(["/usr/bin/nettop", "-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out"], timeout=25)
    t_nettop = threading.Thread(target=_nettop, daemon=True, name="cerber-nettop")
    t_nettop.start()

    r = run(["/usr/sbin/sysctl", "-n", "kern.boottime"], timeout=5)
    boot = parse_boottime(r.out) if r.ok else None
    if boot is None:
        try:
            import psutil
            boot = psutil.boot_time()
        except Exception:  # noqa: BLE001
            boot = None
    audit["boot_time"] = fmt_ts(boot)

    socks = _socks(ctx)
    procs = snapshot(ctx)
    listening = build_listening(socks, procs)
    conns = build_connections(socks, procs)
    exes = {d["exe"] for d in listening + conns if d.get("exe") and not is_apple_path(d["exe"])}
    ctx.codesign.prefetch(e for e in exes if os.path.exists(e))
    sign_cache: dict[str, tuple] = {}

    def sign(exe: str | None):
        if not exe:
            return None, None
        if exe not in sign_cache:
            sign_cache[exe] = _sign(ctx, exe)
        return sign_cache[exe]

    for d in listening:
        d["signer"] = sign(d["exe"])[0]

    # ---- IOC check of every public peer
    look = _ioc_lookup(ctx)
    public_ips = sorted({c["remote"] for c in conns if c["public"]})
    hits: dict[str, str] = {}
    if look:
        for ip in public_ips:
            t = look(ip)
            if t:
                hits[ip] = t
    for c in conns:
        if c["remote"] in hits:
            c["ioc"] = format_ioc(hits[c["remote"]])

    # ---- reverse DNS (bounded): IOC hits first, then the most-used addresses
    if ctx.options.get("reverse_dns", True) and public_ips:
        usage: dict[str, int] = {}
        for c in conns:
            if c["public"]:
                usage[c["remote"]] = usage.get(c["remote"], 0) + 1
        order = sorted(public_ips, key=lambda ip: (ip not in hits, -usage.get(ip, 0), ip))[:MAX_DNS]
        names = reverse_dns(order, budget=float(ctx.options.get("dns_budget", DNS_BUDGET)))
        for c in conns:
            c["host"] = names.get(c["remote"])
        if len(public_ips) > MAX_DNS:
            ctx.inventory["network_audit_dns_skipped"] = len(public_ips) - MAX_DNS

    # ---- findings: connections to known C2 / malware infrastructure
    for c in conns:
        if not c["ioc"]:
            continue
        threat = hits.get(c["remote"], "")
        shared = is_shared_ip(c["remote"])
        label, _ = sign(c["exe"])
        if shared:
            sig = Signal(f"{NA}.IocConnectionShared", 20, Confidence.LOW,
                         f"połączenie z adresem z listy zagrożeń ({c['ioc']}), ale jest to adres współdzielony przez "
                         "sieć CDN – ten sam adres obsługuje tysiące niezwiązanych stron, więc samo trafienie nie "
                         "dowodzi infekcji", [f"{c['remote']}:{c['port']}", c["host"] or "", c["exe"] or c["process"]])
        else:
            sig = Signal(f"{NA}.IocConnection", 85 if threat.startswith("ThreatFox") else 80, Confidence.HIGH,
                         f"aktywne połączenie z adresem znanym z listy zagrożeń: {c['ioc']}",
                         [f"{c['remote']}:{c['port']} ({c['state']})", c["host"] or "", c["exe"] or c["process"]])
        ctx.add_finding("network", f"Połączenie z adresem z listy zagrożeń: {c['process']} → {c['remote']}",
                        f"pid {c['pid']} → {c['remote']}", [sig],
                        {"pid": c["pid"], "process": c["process"], "exe": c["exe"], "signer": label,
                         "remote": c["remote"], "port": c["port"], "host": c["host"], "state": c["state"],
                         "ioc": c["ioc"], "shared_cdn": shared})
        if c["exe"] and not shared:
            ctx.add_target(c["exe"], "proces połączony z adresem z listy zagrożeń (IOC)", 2)

    # ---- findings: scripts / unsigned programs on unusual ports
    by_pid: dict[int, list[dict]] = {}
    for c in conns:
        if c["public"]:
            by_pid.setdefault(c["pid"], []).append(c)
    for pid, cs in sorted(by_pid.items(), key=lambda kv: kv[0] or 0):
        exe, name = cs[0]["exe"], cs[0]["process"]
        if (exe and is_apple_path(exe) and _base(exe) not in SCRIPT_NAMES) or _already_flagged(ctx, pid):
            continue   # Apple daemons are skipped, Apple's interpreters (curl, bash, osascript, nc …) are not
        _, si = sign(exe)
        from .provenance import dev_context
        dev = dev_context(exe, (procs.get(pid) or {}).get("cmdline"), si, home)
        sigs = script_connection_signals(exe, name, si.status if si else None, dev, cs)
        if sigs:
            ctx.add_finding("network", f"Nietypowe połączenia wychodzące: {name} (pid {pid})", f"pid {pid}", sigs,
                            {"pid": pid, "exe": exe, "remote": sorted({f"{c['remote']}:{c['port']}" for c in cs})[:30]})

    # ---- traffic since boot (nettop)
    t_nettop.join(30)
    rn = nettop_box.get("r")
    rows = parse_nettop(rn.out) if rn is not None else []
    if not rows:
        why = "brak polecenia" if rn is not None and rn.missing else ("przekroczono limit czasu" if rn is not None
                                                                     and rn.timed_out else "brak danych")
        ctx.limit(f"nettop nie zwrócił danych ({why}) – nie ustalono, ile danych wysłały poszczególne procesy")
    total_out = sum(r["bytes_out"] for r in rows)
    traffic: list[dict] = []
    top_exes = []
    for r in rows:
        name, exe = _proc_name_exe(procs, r["pid"], r["name"])
        r["process"], r["exe"] = name, exe
        if exe and not is_apple_path(exe) and os.path.exists(exe):
            top_exes.append(exe)
    ctx.codesign.prefetch(top_exes[:120])
    for i, r in enumerate(rows):
        label, si = sign(r["exe"])
        if i < MAX_TRAFFIC:
            traffic.append({"process": r["process"], "pid": r["pid"], "exe": r["exe"], "bytes_out": r["bytes_out"],
                            "bytes_in": r["bytes_in"], "signer": label})
        status = si.status if si is not None else ("apple" if label == "Apple" else None)
        if not r["exe"] or status is None:
            continue   # unknown executable (exited / not readable): listed, not judged
        sigs = exfil_signals(r["exe"], r["bytes_out"], r["bytes_in"], status, label or "", home)
        if not sigs:
            continue
        det = combine(sigs)
        title = "Możliwy wyciek danych" if det is not None and det.score >= 10 else "Duży transfer wychodzący"
        f = ctx.add_finding("network", f"{title}: {r['process']} wysłał {fmt_bytes(r['bytes_out'])}",
                            f"pid {r['pid']} (ruch)", sigs,
                            {"pid": r["pid"], "process": r["process"], "exe": r["exe"], "signer": label,
                             "bytes_out": r["bytes_out"], "bytes_in": r["bytes_in"], "since_boot": audit["boot_time"]})
        if f and f.score >= 10:
            ctx.add_target(r["exe"], "proces wysyłający dużo danych", 2)

    # ---- traffic history
    items, reason = read_netusage(ctx.options.get("netusage_db", NETUSAGE_DB))
    if reason:
        audit["traffic_history"] = {"available": False, "reason": reason, "items": []}
        ctx.limit(f"Historia ruchu sieciowego (netusage.sqlite) niedostępna – {reason}")
    else:
        audit["traffic_history"] = {"available": True, "reason": None, "items": items}

    audit["listening"] = listening
    audit["connections"] = conns[:MAX_CONNECTIONS]
    audit["traffic"] = traffic
    summary["listening_all_interfaces"] = len({(d["pid"], d["port"]) for d in listening
                                               if d["exposure"] == "all" and d["proto"].startswith("tcp")})
    summary["public_connections"] = sum(1 for c in conns if c["public"])
    summary["processes_online"] = len({c["pid"] for c in conns if c["public"]})
    summary["ioc_hits"] = sum(1 for c in conns if c["ioc"])
    summary["uploaded_bytes_since_boot"] = total_out
    if len(conns) > MAX_CONNECTIONS:
        ctx.inventory["network_audit_connections_total"] = len(conns)


# --------------------------------------------------------------------------- remote access: catalogs

_X = re.IGNORECASE
# (slug used in signal names, display name, regex over app/plist/process names and executable paths)
REMOTE_TOOLS: list[tuple[str, str, re.Pattern]] = [(s, n, re.compile(rx, _X)) for s, n, rx in (
    ("TeamViewer", "TeamViewer", r"teamviewer"),
    ("AnyDesk", "AnyDesk", r"anydesk|philandro"),
    ("RustDesk", "RustDesk", r"rustdesk|carriez"),
    ("Splashtop", "Splashtop", r"splashtop|\bsrstreamer|\bsrserver|\bsrfeature"),
    ("LogMeIn", "LogMeIn", r"logmein|\blmiguardian|\blmigui"),
    ("GoTo", "GoTo Resolve / GoToAssist / GoToMyPC", r"gotoassist|gotomypc|goto ?resolve|\bg2ax"),
    ("ScreenConnect", "ConnectWise ScreenConnect", r"screenconnect|connectwise ?control"),
    ("BeyondTrust", "BeyondTrust / Bomgar", r"bomgar|beyondtrust|\bsdcust\b|remote support customer client"),
    ("ChromeRemoteDesktop", "Pulpit zdalny Chrome (Chrome Remote Desktop)",
     r"chromoting|chrome ?remote ?desktop|chromeremotedesktop|remoting_me2me_host|remote_assistance_host"),
    ("VNC", "Serwer VNC (RealVNC / TigerVNC / x11vnc …)",
     r"realvnc|vnc ?server|vncserver|vncagent|x11vnc|tigervnc|tightvnc|ultravnc|vine ?server|osxvnc"),
    ("NoMachine", "NoMachine", r"nomachine|\bnxserver\b|\bnxnode\b|\bnxd\b"),
    ("Parsec", "Parsec", r"\bparsec(?:d)?(?:\.app)?\b|tv\.parsec"),
    ("ZohoAssist", "Zoho Assist", r"zoho ?assist|\bza_connect|zohours"),
    ("Atera", "Atera (RMM)", r"atera ?agent|com\.atera\b|\bateraagent"),
    ("NinjaRMM", "NinjaOne / NinjaRMM", r"ninjarmm|ninjaone|ninja ?rmm"),
    ("Kaseya", "Kaseya (RMM)", r"kaseya|\bagentmon\b"),
    ("JumpDesktop", "Jump Desktop Connect", r"jump ?desktop ?connect|com\.p5sys\.jump\.connect|jumpconnect"),
    ("Remotix", "Remotix / Screens Connect", r"remotix ?agent|com\.nulana\.remotix|screens ?connect|com\.edovia\.screens\.connect"),
    ("DWService", "DWService", r"dwagent|dwservice|dwagsvc"),
    ("MeshAgent", "MeshCentral MeshAgent", r"meshagent|mesh_services|meshcentral"),
    ("Supremo", "Supremo", r"\bsupremo\b|\bnanosystems\b"),
    ("Ammyy", "Ammyy Admin", r"ammyy"),
    ("HopToDesk", "HopToDesk", r"hoptodesk"),
    ("Getscreen", "Getscreen.me", r"getscreen"),
    ("SimpleHelp", "SimpleHelp", r"simplehelp|simple-help"),
    ("TacticalRMM", "Tactical RMM", r"tacticalagent|tacticalrmm|tacticalrpc"),
    ("Action1", "Action1 (RMM)", r"\baction1(?:_agent|_remote|\.app|agent)?\b"),
    ("Pulseway", "Pulseway", r"pulseway"),
    ("NAble", "N-able / Take Control", r"\bn-able\b|take ?control ?(?:agent|viewer)|basupsrvc|\bmspagent\b"),
    ("Datto", "Datto RMM", r"\bdatto ?rmm|\baemagent|centrastage"),
    ("NetSupport", "NetSupport Manager", r"netsupport"),
    ("ISLOnline", "ISL Online", r"islonline|\bisl ?(?:light|alwayson)\b"),
    ("RemotePC", "RemotePC", r"\bremotepc\b"),
    ("Sunlogin", "Sunlogin / AweSun", r"sunlogin|awesun|aweray"),
    ("ToDesk", "ToDesk", r"\btodesk\b"),
    ("AnyViewer", "AnyViewer", r"anyviewer"),
    ("FleetDeck", "FleetDeck", r"fleetdeck"),
)]
# conferencing apps & VPNs of the same vendors are not remote-control agents
REMOTE_EXCLUDE = re.compile(r"hamachi|gotomeeting|goto ?meeting|gotowebinar|goto ?webinar|g2mupdate|g2mlauncher", _X)

VPN_TOOLS: list[tuple[str, str, re.Pattern]] = [(s, n, re.compile(rx, _X)) for s, n, rx in (
    ("Tailscale", "Tailscale (VPN / sieć mesh)", r"tailscale|io\.tailscale|\bipnextension\b"),
    ("ZeroTier", "ZeroTier (VPN / sieć mesh)", r"zerotier"),
    ("WireGuard", "WireGuard (VPN)", r"wireguard"),
    ("NetBird", "NetBird (VPN / sieć mesh)", r"netbird"),
    ("Hamachi", "LogMeIn Hamachi (VPN)", r"hamachi"),
)]
# parents for which `ssh -D` is the editor's own remote-development transport (VS Code Remote-SSH & co.)
EDITOR_PARENTS = re.compile(r"(?i)code helper|visual studio code|cursor|windsurf|vscodium|zed|jetbrains|"
                            r"pycharm|intellij|webstorm|goland|clion|rider|fleet|nova")

# process base name -> (display name, base score). Matched on the executable/process name.
TUNNEL_TOOLS = {
    "ngrok": ("ngrok", 40), "cloudflared": ("Cloudflare Tunnel (cloudflared)", 40), "frpc": ("frp (frpc)", 40),
    "frps": ("frp (frps)", 40), "chisel": ("chisel", 40), "bore": ("bore", 40), "lt": ("localtunnel", 40),
    "localtunnel": ("localtunnel", 40), "zrok": ("zrok", 40), "inlets": ("inlets", 40), "rathole": ("rathole", 40),
    "playit": ("playit.gg", 40), "tunnelto": ("tunnelto", 40), "tmole": ("tunnelmole", 40),
    "loophole": ("loophole", 40), "pagekite": ("PageKite", 40), "pagekite.py": ("PageKite", 40),
    "sish": ("sish", 40), "pinggy": ("Pinggy", 40),
}
TUNNEL_SERVICES = re.compile(r"pinggy\.io|serveo\.net|localhost\.run|localtunnel\.me|tuns\.sh|srv\.us|"
                             r"ngrok|trycloudflare\.com|lhr\.life|ssh\.localhost\.run", _X)
_SSH_REVERSE = re.compile(r"^-[46AaCfGgKkMNnqsTtVvXxYy]*R")
_SSH_DYNAMIC = re.compile(r"^-[46AaCfGgKkMNnqsTtVvXxYy]*D")
_NC_LISTEN = re.compile(r"^-[A-Za-z]*l")


def match_remote_tool(text: str) -> tuple[str, str] | None:
    if not text or REMOTE_EXCLUDE.search(text):
        return None
    for slug, name, rx in REMOTE_TOOLS:
        if rx.search(text):
            return slug, name
    return None


def match_vpn(text: str) -> tuple[str, str] | None:
    for slug, name, rx in VPN_TOOLS:
        if text and rx.search(text):
            return slug, name
    return None


def classify_tunnel(cmdline: list[str] | None, name: str = "", exe: str | None = None) -> dict | None:
    """Recognise tunnels / reverse proxies from a process. Returns {name, score, detail, info} or None."""
    argv = [str(a) for a in (cmdline or [])]
    base = os.path.basename(exe or (argv[0] if argv else "") or name).lower()
    base_n = os.path.basename(name or "").lower()
    text = " ".join(argv)
    if base in ("ssh", "autossh") or base_n in ("ssh", "autossh"):
        args = argv[1:]
        reverse = any(_SSH_REVERSE.match(a) for a in args) or "RemoteForward" in text
        dynamic = any(_SSH_DYNAMIC.match(a) for a in args) or "DynamicForward" in text
        svc = TUNNEL_SERVICES.search(text)
        if reverse and svc:
            return {"name": f"Tunel SSH do usługi {svc.group(0)}", "score": 45,
                    "detail": "odwrócony tunel SSH (ssh -R) do publicznej usługi tunelującej – usługa z tego Maca "
                              "jest dostępna z Internetu", "info": False, "evidence": redact(text, 200)}
        if reverse:
            return {"name": "Odwrócony tunel SSH (ssh -R)", "score": 40,
                    "detail": "ssh -R udostępnia port tego Maca na zdalnym serwerze – ktoś po drugiej stronie może "
                              "łączyć się z usługami tego komputera", "info": False, "evidence": redact(text, 200)}
        if dynamic:
            return {"name": "Proxy SOCKS przez SSH (ssh -D)", "score": 25,
                    "detail": "ssh -D tworzy serwer proxy SOCKS przekazujący ruch tego Maca przez zdalny serwer "
                              "(nie daje dostępu do tego komputera z zewnątrz)", "info": False,
                    "evidence": redact(text, 200)}
        return None
    key = base if base in TUNNEL_TOOLS else (base_n if base_n in TUNNEL_TOOLS else None)
    if key == "lt" and "--port" not in argv and "-p" not in argv:
        key = None   # 'lt' is too short a name to trust without localtunnel's arguments
    if key is None and base in ("node", "bun", "deno", "npx") and re.search(r"localtunnel[/\\]|/\.bin/lt\b", text):
        key = "localtunnel"
    if key:
        disp, score = TUNNEL_TOOLS[key]
        if key == "cloudflared" and argv and "tunnel" not in argv:
            return {"name": disp, "score": 0, "info": True, "evidence": redact(text, 200),
                    "detail": "cloudflared działa bez trybu 'tunnel' (np. proxy DNS lub dostęp do sieci firmowej)"}
        return {"name": disp, "score": score, "info": False, "evidence": redact(text or base, 200),
                "detail": f"{disp} wystawia usługę z tego Maca do Internetu (tunel / odwrotne proxy)"}
    if base in ("nc", "ncat", "netcat") and any(_NC_LISTEN.match(a) for a in argv[1:]):
        return {"name": f"{base} w trybie nasłuchu", "score": 40, "info": False, "evidence": redact(text, 200),
                "detail": f"{base} nasłuchuje połączeń – typowy sposób na zdalną powłokę (bind shell)"}
    if base == "socat" and re.search(r"(?i)\b(?:tcp|tcp4|tcp6|udp|openssl|ssl)[46]?-listen", text):
        return {"name": "socat w trybie nasłuchu", "score": 40, "info": False, "evidence": redact(text, 200),
                "detail": "socat nasłuchuje połączeń i przekazuje je dalej (przekierowanie / zdalna powłoka)"}
    return None


# --------------------------------------------------------------------------- remote access: parsers

_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                                       "Nov", "Dec"), 1)}
_WHO_RX = re.compile(r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
                     r"(?P<time>\d{1,2}:\d{2})\s*(?:\((?P<host>.*)\))?\s*$")
_LAST_RX = re.compile(r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?:(?P<host>\S+)\s+)?"
                      r"(?P<wd>Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
                      r"(?P<time>\d{1,2}:\d{2})(?P<rest>.*)$")


def _date_guess(mon: str, day: str, hm: str, now: float | None = None) -> tuple[int, int, int, int, int] | None:
    m = _MONTHS.get(mon)
    if not m:
        return None
    lt = time.localtime(now if now is not None else time.time())
    h, mi = (int(x) for x in hm.split(":"))
    y = lt.tm_year
    if (m, int(day)) > (lt.tm_mon, lt.tm_mday + 1):
        y -= 1
    return y, m, int(day), h, mi


def _remote_host(host: str | None) -> str | None:
    """Host column of who/last -> remote address, or None for local/tmux/screen/X sessions."""
    if not host:
        return None
    h = host.strip()
    if not h or h.startswith((":", "tmux", "screen", "mosh")) or h in ("localhost", "127.0.0.1", "::1", "-"):
        return None
    if re.match(r"^:?\d+(\.\d+)?$", h):   # X display like :0 / 0.0
        return None
    return h


def host_kind(host: str) -> str:
    """public | lan | unknown for a who/last host column."""
    a = _ip(host)
    if a is not None:
        if a.is_loopback:
            return "lan"
        return "public" if is_public_ip(str(a)) else "lan"
    h = host.lower().rstrip(".")
    if h.endswith((".local", ".lan", ".home", ".internal", ".localdomain", ".home.arpa")) or "." not in h:
        return "lan"
    return "unknown"


def parse_who(text: str, now: float | None = None) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        m = _WHO_RX.match(line.rstrip())
        if not m:
            continue
        d = _date_guess(m.group("mon"), m.group("day"), m.group("time"), now)
        since = f"{d[0]:04d}-{d[1]:02d}-{d[2]:02d} {d[3]:02d}:{d[4]:02d}" if d else None
        out.append({"user": m.group("user"), "tty": m.group("tty"), "from": _remote_host(m.group("host")),
                    "since": since})
    return out


def parse_last(text: str, now: float | None = None) -> list[dict]:
    """`last` output (newest first, no year): the year is inferred and decremented at each wrap."""
    out = []
    lt = time.localtime(now if now is not None else time.time())
    year = lt.tm_year
    prev: tuple[int, int] | None = None
    for line in (text or "").splitlines():
        m = _LAST_RX.match(line.rstrip())
        if not m:
            continue
        user = m.group("user")
        mon, day = _MONTHS.get(m.group("mon")), int(m.group("day"))
        if not mon:
            continue
        if prev is None:
            if (mon, day) > (lt.tm_mon, lt.tm_mday + 1):
                year -= 1
        elif (mon, day) > prev:
            year -= 1
        prev = (mon, day)
        if user in ("reboot", "shutdown", "wtmp"):
            continue
        h, mi = (int(x) for x in m.group("time").split(":"))
        host = _remote_host(m.group("host"))
        out.append({"user": user, "tty": m.group("tty"), "from": host,
                    "when": f"{year:04d}-{mon:02d}-{day:02d} {h:02d}:{mi:02d}", "remote": host is not None})
    return out


def parse_enrollment(text: str) -> tuple[bool, bool]:
    t = text or ""
    return bool(re.search(r"MDM enrollment:\s*Yes", t)), bool(re.search(r"Enrolled via DEP:\s*Yes", t))


# --------------------------------------------------------------------------- collector: remote access

MAC_SERVICES = [
    # key, display name, launchd labels (system domain), TCP ports, daemon process names, score, enabled detail
    ("ssh", "Zdalne logowanie (SSH)", ["com.openssh.sshd"], [22], set(), 15,
     "Zdalne logowanie jest włączone: każdy, kto zna hasło konta (lub ma zapisany klucz SSH), może zalogować się "
     "przez sieć i uruchamiać polecenia."),
    ("screen", "Udostępnianie ekranu (VNC)", ["com.apple.screensharing"], [5900], set(), 15,
     "Udostępnianie ekranu jest włączone: osoba znająca hasło może przez sieć widzieć ekran i sterować tym Makiem."),
    ("ard", "Apple Remote Desktop (zdalne zarządzanie)", [], [3283], {"ARDAgent"}, 15,
     "Zdalne zarządzanie jest włączone: administrator może zdalnie obserwować i sterować Makiem, kopiować pliki "
     "i uruchamiać polecenia."),
    ("aevents", "Zdalne zdarzenia Apple (Remote Apple Events)", ["com.apple.AEServer"], [3031], set(), 10,
     "Zdalne zdarzenia Apple są włączone: inne komputery mogą wysyłać polecenia AppleScript do aplikacji na tym Macu."),
    ("files", "Udostępnianie plików (SMB)", ["com.apple.smbd"], [445, 548], set(), 5,
     "Udostępnianie plików jest włączone: udostępnione foldery są dostępne przez sieć."),
]


def _launchd_loaded(label: str) -> bool:
    r = run(["/bin/launchctl", "print", f"system/{label}"], timeout=5)
    return r.rc == 0


def _add_item(audit: dict, name: str, kind: str, status: str, detail: str, risk: str) -> dict:
    item = {"name": name, "kind": kind, "status": status, "detail": detail, "risk": risk}
    audit["remote_access"].append(item)
    return item


def _app_candidates(dirs: list[str]) -> list[str]:
    """.app bundles and vendor folders directly in `dirs` and one level below."""
    out = []
    for d in dirs:
        names, _ = safe_listdir(d)
        for n in names:
            p = os.path.join(d, n)
            out.append(p)
            # browser web-app shortcut folders ("Chrome Apps.localized") hold PWA clients, not remote-control agents
            if not n.endswith(".app") and not n.endswith("Apps.localized") and os.path.isdir(p) \
                    and not os.path.islink(p):
                sub, _ = safe_listdir(p)
                out += [os.path.join(p, s) for s in sub if s.endswith(".app")]
    return out


def _launch_items(dirs: list[str]) -> list[tuple[str, str]]:
    """(plist path, text to match: file name + Label + program)."""
    out = []
    for d in dirs:
        names, _ = safe_listdir(d)
        for n in names:
            if not n.endswith(".plist"):
                continue
            p = os.path.join(d, n)
            data, _ = load_plist(p, 1 << 20)
            text = n
            if isinstance(data, dict):
                prog = data.get("Program") or ""
                args = data.get("ProgramArguments") or []
                if not prog and isinstance(args, list) and args:
                    prog = str(args[0])
                text += f" {data.get('Label', '')} {prog}"
            out.append((p, text))
    return out


def collect_remote(ctx: EnvContext) -> None:
    ctx.progress("audyt zdalnego dostępu")
    audit = _audit(ctx)
    audit["remote_access"] = []
    home = ctx.homes[0].home if ctx.homes else None
    socks = _socks(ctx)
    procs = snapshot(ctx)
    me = os.getpid()

    listen_ports: dict[int, list[dict]] = {}
    inbound: list[dict] = []
    for s in socks:
        if s.get("state") == "LISTEN" and s.get("lport"):
            listen_ports.setdefault(s["lport"], []).append(s)
    for s in socks:
        if s.get("state") == "ESTABLISHED" and s.get("lport") in listen_ports and s.get("remote") not in ("*", "") \
                and not is_loopback(s.get("remote", "")):
            inbound.append(s)
    pids_by_name: dict[str, list[int]] = {}
    for pid, i in procs.items():
        pids_by_name.setdefault(i.get("name") or "", []).append(pid)

    def public_established(pids: set[int]) -> list[str]:
        return sorted({f"{normalize_ip(s['remote'])}:{s['rport']}" for s in socks
                       if s.get("pid") in pids and s.get("state") == "ESTABLISHED" and s.get("rport")
                       and is_public_ip(s.get("remote", ""))})

    # current sessions first: an SSH login shown by `who` is not reported twice as an inbound connection
    r_who = run(["/usr/bin/who"], timeout=10)
    sessions = parse_who(r_who.out) if r_who.ok else []
    session_hosts = {x["from"] for x in sessions if x["from"]}

    # ---- 1. macOS sharing services
    svc_state: dict[str, bool] = {}
    for key, name, labels, ports, daemons, score, detail in MAC_SERVICES:
        evidence = []
        for lb in labels:
            if _launchd_loaded(lb):
                evidence.append(f"usługa launchd {lb} jest załadowana")
        for p in ports:
            for s in listen_ports.get(p, []):
                if exposure_of(s.get("local") or "*") != "localhost":
                    exe = (procs.get(s["pid"]) or {}).get("exe") or ""
                    if s["pid"] == 1 or is_apple_path(exe) or not exe:
                        evidence.append(f"port {p} nasłuchuje ({s.get('pname') or s['pid']})")
                        break
        for dname in daemons:
            if pids_by_name.get(dname):
                evidence.append(f"działa proces {dname}")
        if key == "ard":
            flag = (read_text(ARD_LAUNCHD_FLAG, 4096) or "").strip().lower()
            if flag == "enabled":
                evidence.append("RemoteManagement.launchd = enabled")
        enabled = bool(evidence)
        svc_state[key] = enabled
        sigs = []
        if enabled:
            sigs.append(Signal(f"{RA}.MacService.{key.capitalize()}", score, Confidence.LOW,
                               detail, evidence[:4]))
        active = [s for s in inbound if s.get("lport") in ports
                  and not (key == "ssh" and normalize_ip(s["remote"]) in session_hosts)]
        if active:
            remotes = sorted({normalize_ip(s["remote"]) for s in active})
            sigs.append(Signal(f"{RA}.MacService.{key.capitalize()}Active", 40, Confidence.MEDIUM,
                               f"trwa połączenie przychodzące do usługi „{name}” – ktoś może być teraz połączony "
                               "z tym Makiem", remotes[:5]))
        _add_item(audit, name, "macos_service", "enabled" if enabled else "disabled",
                  (detail + (" Aktywne połączenie z: " + ", ".join(sorted({normalize_ip(s['remote']) for s in active}))
                             if active else "")) if enabled or active else "wyłączone",
                  _risk(sigs))
        if sigs:
            ctx.add_finding("remote_access", f"Włączona usługa zdalnego dostępu: {name}"
                            if not active else f"Aktywne połączenie zdalne: {name}",
                            f"Ustawienia systemowe > Ogólne > Udostępnianie > {name}", sigs,
                            {"service": name, "evidence": evidence,
                             "active_from": sorted({normalize_ip(s["remote"]) for s in active})})
    ctx.posture.setdefault("remote_login", svc_state.get("ssh", False))
    ctx.posture.setdefault("screen_sharing", svc_state.get("screen", False))

    # ---- 2. third-party remote-control tools and VPN/mesh networks: installed ...
    homes = [h.home for h in ctx.homes]
    app_paths = _app_candidates(APP_DIRS + [os.path.join(h, "Applications") for h in homes])
    launch = _launch_items(SYSTEM_LAUNCH_DIRS + [os.path.join(h, "Library", "LaunchAgents") for h in homes])
    extra = []
    for d in EXTRA_DIRS:
        extra += [os.path.join(d, n) for n in safe_listdir(d)[0]]
    tools: dict[str, dict] = {}
    vpns: dict[str, dict] = {}

    def slot(table: dict, slug: str, name: str) -> dict:
        return table.setdefault(slug, {"name": name, "apps": [], "launch": [], "files": [], "pids": [], "exes": set()})
    for p in app_paths:
        b = os.path.basename(p)
        if (t := match_remote_tool(b)):
            slot(tools, *t)["apps"].append(p)
        elif (v := match_vpn(b)):
            slot(vpns, *v)["apps"].append(p)
    for p, text in launch:
        if (t := match_remote_tool(text)):
            slot(tools, *t)["launch"].append(p)
        elif (v := match_vpn(text)):
            slot(vpns, *v)["launch"].append(p)
    for p in extra:
        b = os.path.basename(p)
        if (t := match_remote_tool(b)):
            slot(tools, *t)["files"].append(p)
        elif (v := match_vpn(b)):
            slot(vpns, *v)["files"].append(p)

    # ... and running
    tunnels: list[dict] = []
    for pid, info in procs.items():
        if pid == me:
            continue
        name = info.get("name") or ""
        exe = info.get("exe") or ""
        tun = classify_tunnel(info.get("cmdline"), name, exe or None)   # before the Apple skip: /usr/bin/ssh, nc
        if tun:
            parent = procs.get(info.get("ppid")) or {}
            if tun["name"].startswith("Proxy SOCKS") and EDITOR_PARENTS.search(
                    f"{parent.get('name') or ''} {parent.get('exe') or ''}"):
                tun.update(score=0, info=True, detail="ssh -D uruchomiony przez edytor (zdalna praca na serwerze, "
                                                      "np. VS Code Remote-SSH)")
            tun.update(pid=pid, exe=exe or None, user=info.get("username"))
            tunnels.append(tun)
        if exe and is_apple_path(exe):
            continue
        if not exe and name in APPLE_DAEMON_NAMES:
            continue
        text = f"{name} {exe}"
        if (t := match_remote_tool(text)):
            e = slot(tools, *t)
            e["pids"].append(pid)
            if exe:
                e["exes"].add(exe)
        elif (v := match_vpn(text)):
            e = slot(vpns, *v)
            e["pids"].append(pid)
            if exe:
                e["exes"].add(exe)
    # nc/socat listeners whose command line is not visible (other users' processes)
    seen_tunnel_pids = {t["pid"] for t in tunnels}
    for s in socks:
        if s.get("state") != "LISTEN" or s.get("pid") in seen_tunnel_pids:
            continue
        info = procs.get(s["pid"]) or {}
        base = os.path.basename(info.get("exe") or info.get("name") or s.get("pname") or "").lower()
        if base in ("nc", "ncat", "netcat", "socat"):
            seen_tunnel_pids.add(s["pid"])
            tunnels.append({"name": f"{base} w trybie nasłuchu", "score": 40, "info": False, "pid": s["pid"],
                            "exe": info.get("exe"), "user": info.get("username"),
                            "evidence": f"{s['proto']} {s.get('local')}:{s.get('lport')}",
                            "detail": f"{base} nasłuchuje na porcie {s.get('lport')} – typowy sposób na zdalną powłokę"})

    remote_tool_count = 0
    for slug, e in sorted(tools.items()):
        remote_tool_count += 1
        pids = set(e["pids"])
        running = bool(pids)
        conns = public_established(pids) if running else []
        sigs: list[Signal] = []
        where = e["apps"] + e["launch"] + e["files"] + sorted(e["exes"])
        if running and conns:
            sigs.append(Signal(f"{RA}.{slug}Connected", 35, Confidence.MEDIUM,
                               f"{e['name']} działa i ma aktywne połączenie z Internetem – ktoś może być teraz "
                               "połączony z tym Makiem", conns[:5]))
        elif running:
            sigs.append(Signal(f"{RA}.{slug}Running", 20, Confidence.LOW,
                               f"{e['name']} działa – program pozwala na zdalne sterowanie tym Makiem; upewnij się, "
                               "że to Ty go zainstalowałeś", sorted(e["exes"])[:3] or [str(p) for p in sorted(pids)[:3]]))
        else:
            sigs.append(Signal(f"{RA}.{slug}Installed", 12 if e["launch"] else 5, Confidence.LOW,
                               f"zainstalowano {e['name']}" + (" z automatycznym uruchamianiem" if e["launch"] else "")
                               + " – upewnij się, że to Ty go zainstalowałeś", where[:3]))
        signer = None
        weak_seen = False
        for exe in sorted(e["exes"]) + [x for x in (_bundle_exe(a) for a in e["apps"]) if x]:
            label, si = _sign(ctx, exe)
            signer = signer or label
            if si is not None and si.weak and not weak_seen:
                weak_seen = True
                sigs.append(Signal(f"{RA}.{slug}Unsigned", 30, Confidence.MEDIUM,
                                   f"plik programu {e['name']} nie ma zaufanego podpisu ({label}) – możliwa podróbka",
                                   [exe]))
            odd = odd_location(exe, home)
            if odd and not any(s.name.endswith("OddLocation") for s in sigs):
                s = Signal(f"{RA}.{slug}OddLocation", 30, Confidence.MEDIUM,
                           f"{e['name']} działa z nietypowego miejsca ({', '.join(odd)})", [exe])
                sigs.append(s.scaled(0.4, f"plik podpisany: {label}") if si is not None and si.trusted else s)
        hidden = [p for p in e["launch"] if os.path.basename(p).startswith(".")]
        if hidden:
            sigs.append(Signal(f"{RA}.{slug}HiddenLaunchItem", 30, Confidence.MEDIUM,
                               f"ukryty wpis autostartu dla {e['name']}", hidden[:3]))
        status = "running" if running else "installed"
        detail = ("działa" + (f", aktywne połączenia: {', '.join(conns[:3])}" if conns else "")
                  if running else "zainstalowany") + (f"; autostart: {', '.join(os.path.basename(p) for p in e['launch'][:3])}"
                                                      if e["launch"] else "")
        if signer:
            detail += f"; podpis: {signer}"
        detail += " – program do zdalnego sterowania komputerem; upewnij się, że to Ty go zainstalowałeś"
        _add_item(audit, e["name"], "app", status, detail, _risk(sigs))
        title = f"Narzędzie zdalnego dostępu: {e['name']} ({'działa' if running else 'zainstalowane'})"
        f = ctx.add_finding("remote_access", title, (where or [e["name"]])[0], sigs,
                            {"tool": e["name"], "status": status, "apps": e["apps"], "launch_items": e["launch"],
                             "files": e["files"], "pids": sorted(pids)[:20], "exes": sorted(e["exes"]),
                             "connections": conns[:20], "signer": signer})
        if f and f.score >= 10:
            for x in sorted(e["exes"])[:3] + e["launch"][:3]:
                ctx.add_target(x, f"narzędzie zdalnego dostępu {e['name']}", 2 if f.score >= 35 else 1)

    for slug, e in sorted(vpns.items()):
        running = bool(e["pids"])
        _add_item(audit, e["name"], "tunnel", "running" if running else "installed",
                  ("działa" if running else "zainstalowany") + " – VPN / sieć prywatna: urządzenia w tej sieci mogą "
                  "łączyć się z usługami tego Maca (np. SSH, udostępnianie ekranu)", "info")

    for t in tunnels:
        sigs = [] if t.get("info") else [Signal(f"{RA}.Tunnel", t["score"], Confidence.MEDIUM, t["detail"],
                                                [t.get("evidence") or "", t.get("exe") or ""])]
        if not t.get("info"):
            remote_tool_count += 1
        _add_item(audit, t["name"], "tunnel", "running", f"{t['detail']} (pid {t['pid']})", _risk(sigs) if sigs else "info")
        if sigs:
            ctx.add_finding("remote_access", f"Tunel sieciowy: {t['name']} (pid {t['pid']})", f"pid {t['pid']}", sigs,
                            {"pid": t["pid"], "exe": t.get("exe"), "user": t.get("user"),
                             "command": t.get("evidence")})
            if t.get("exe") and not is_apple_path(t["exe"]):
                ctx.add_target(t["exe"], f"tunel sieciowy {t['name']}", 1)
    if not ctx.is_root:
        ctx.limit("Bez uprawnień administratora widać wiersze poleceń tylko procesów bieżącego użytkownika – tunele "
                  "(ssh -R, ngrok …) uruchomione przez inne konta rozpoznano tylko po nazwie programu")

    # ---- 3. current sessions (who)
    if not r_who.ok:
        ctx.limit("polecenie who nie zadziałało – nie sprawdzono bieżących sesji")
    audit["sessions"] = sessions
    for s in sessions:
        if not s["from"]:
            continue
        kind = host_kind(s["from"])
        sc = 40 if kind != "lan" else 35
        sig = Signal(f"{RA}.RemoteSession", sc, Confidence.MEDIUM,
                     f"użytkownik {s['user']} jest teraz zalogowany zdalnie z {s['from']}"
                     + (" (adres w Internecie)" if kind == "public" else " (sieć lokalna)" if kind == "lan" else ""),
                     [f"{s['user']} {s['tty']} od {s['since']} z {s['from']}"])
        _add_item(audit, f"Sesja zdalna: {s['user']} z {s['from']}", "session", "running",
                  f"aktywna sesja terminala {s['tty']} od {s['since']} z {s['from']}", _risk([sig]))
        ctx.add_finding("remote_access", f"Aktywna sesja zdalna: {s['user']} z {s['from']}",
                        f"{s['tty']} z {s['from']}", [sig], dict(s))

    # ---- 4. login history (last)
    r = run(["/usr/bin/last", "-n", "200"], timeout=15)
    logins = parse_last(r.out) if r.ok else []
    if not r.ok:
        ctx.limit("polecenie last nie zadziałało – nie sprawdzono historii logowań")
    audit["logins"] = logins
    remote_logins = [x for x in logins if x["remote"]]
    if remote_logins:
        public = [x for x in remote_logins if host_kind(x["from"]) == "public"]
        unknown = [x for x in remote_logins if host_kind(x["from"]) == "unknown"]
        recent_cut = time.strftime("%Y-%m-%d", time.localtime(time.time() - 3 * 86400))
        sigs = []
        if public:
            recent = [x for x in public if x["when"] >= recent_cut]
            sigs.append(Signal(f"{RA}.PublicLogin", 40 if recent else 30, Confidence.MEDIUM,
                               f"{len(public)} {_pl(len(public), 'zdalne logowanie', 'zdalne logowania', 'zdalnych logowań')}"
                               " z adresów w Internecie" + (" (także w ostatnich 3 dniach)" if recent else ""),
                               [f"{x['when']} {x['user']} z {x['from']}" for x in public[:5]]))
        if unknown:
            sigs.append(Signal(f"{RA}.RemoteLoginHost", 15, Confidence.LOW,
                               "zdalne logowania z nazwanych hostów spoza sieci lokalnej",
                               [f"{x['when']} {x['user']} z {x['from']}" for x in unknown[:5]]))
        if not sigs:
            sigs.append(Signal(f"{RA}.LanLogin", 5, Confidence.LOW, "zdalne logowania z sieci lokalnej",
                               [f"{x['when']} {x['user']} z {x['from']}" for x in remote_logins[:5]]))
        hosts = sorted({x["from"] for x in remote_logins})
        _add_item(audit, "Historia zdalnych logowań", "session", "present",
                  f"{len(remote_logins)} {_pl(len(remote_logins), 'zdalne logowanie', 'zdalne logowania', 'zdalnych logowań')}"
                  f" w historii (z: {', '.join(hosts[:5])}{' …' if len(hosts) > 5 else ''})", _risk(sigs))
        ctx.add_finding("remote_access", "Zdalne logowania w historii (last)", "last", sigs,
                        {"remote_logins": remote_logins[:50]})

    # ---- 5. SSH authorized_keys
    from .accounts import parse_authorized_key
    for h in ctx.homes:
        for fn in ("authorized_keys", "authorized_keys2"):
            p = os.path.join(h.home, ".ssh", fn)
            body = read_text(p, 1 << 20)
            if body is None:
                continue
            keys = [k for k in (parse_authorized_key(x) for x in body.splitlines()) if k and not k.get("invalid")]
            if not keys:
                continue
            n = len(keys)
            on = svc_state.get("ssh", False)
            comments = [k.get("comment") for k in keys if k.get("comment")]
            detail = (f"{n} {_pl(n, 'klucz', 'klucze', 'kluczy')} w {p} {_pl(n, 'pozwala', 'pozwalają', 'pozwala')} "
                      f"zalogować się bez hasła jako {h.name}" + (f" ({', '.join(comments[:3])})" if comments else "")
                      + (" – Zdalne logowanie jest WŁĄCZONE" if on else
                         " – Zdalne logowanie jest wyłączone, więc klucze obecnie nie działają"))
            sigs = [Signal(f"{RA}.SshKeysRemoteLogin", 15, Confidence.LOW,
                           f"Zdalne logowanie (SSH) jest włączone, a {n} {_pl(n, 'klucz', 'klucze', 'kluczy')} "
                           f"SSH pozwala zalogować się bez hasła jako {h.name}",
                           [f"{k.get('type')} {k.get('fingerprint')} {k.get('comment')}" for k in keys[:5]])] if on else []
            _add_item(audit, f"Klucze SSH (authorized_keys) – {h.name}", "ssh_keys", "present", detail,
                      _risk(sigs) if sigs else "info")
            if sigs:
                ctx.add_finding("remote_access", f"Logowanie kluczem SSH bez hasła: {h.name}", p, sigs,
                                {"file": p, "keys": [{"type": k.get("type"), "fingerprint": k.get("fingerprint"),
                                                      "comment": k.get("comment")} for k in keys[:20]]})

    # ---- 6. MDM enrollment
    if "mdm_enrolled" in ctx.posture:
        mdm, dep = bool(ctx.posture.get("mdm_enrolled")), bool(ctx.posture.get("dep_enrolled"))
        known = True
    else:
        r = run(["/usr/bin/profiles", "status", "-type", "enrollment"], timeout=20)
        known = bool(r.out.strip())
        mdm, dep = parse_enrollment(r.out)
        if not known:
            ctx.limit("nie udało się sprawdzić zapisu do MDM (profiles status)")
    if known:
        if mdm:
            sig = Signal(f"{RA}.MdmEnrolled", 5 if dep else 12, Confidence.LOW,
                         "komputer jest zarządzany przez organizację (MDM) – administrator może zdalnie nim zarządzać"
                         + (" (zapis automatyczny przez Apple Business/School Manager)" if dep else
                            " (zapis ręczny – upewnij się, że znasz tę organizację)"), [])
            _add_item(audit, "Zarządzanie urządzeniem (MDM)", "mdm", "enabled",
                      "komputer jest zarządzany przez organizację (MDM) – administrator może zdalnie nim zarządzać"
                      + (" (zapis przez Apple Business/School Manager)" if dep else ""), _risk([sig]))
            ctx.add_finding("remote_access", "Komputer zarządzany przez MDM", "profiles status -type enrollment",
                            [sig], {"mdm": True, "dep": dep})
        else:
            _add_item(audit, "Zarządzanie urządzeniem (MDM)", "mdm", "disabled",
                      "komputer nie jest zapisany w żadnym systemie zarządzania (MDM)", "info")

    order = {"malicious": 0, "suspicious": 1, "low": 2, "info": 3}
    kinds = {"session": 0, "app": 1, "tunnel": 2, "macos_service": 3, "ssh_keys": 4, "mdm": 5}
    status_rank = {"running": 0, "enabled": 1, "present": 2, "installed": 3, "disabled": 4}
    audit["remote_access"].sort(key=lambda i: (order.get(i["risk"], 9), status_rank.get(i["status"], 9),
                                               kinds.get(i["kind"], 9), i["name"]))
    audit["summary"]["remote_tools"] = remote_tool_count


def _bundle_exe(app: str) -> str | None:
    if not app.endswith(".app"):
        return None
    from .util import bundle_executable
    return bundle_executable(app)
