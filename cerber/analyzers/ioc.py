"""Indicator-of-compromise extraction from textual objects and the printable strings of binaries.

Everything is stored (deduped, capped) in obj.meta["iocs"]; risky categories are scored, and
if ctx.services.ioc.lookup(kind, value) is available, database hits are reported as CERTAIN-ish
IOC detections. Nothing is fetched over the network.

Precision notes (a scan of ~350k clean files drove these):
  * wallet addresses are checksum-validated (Base58Check, bech32/bech32m, EIP-55, Monero
    keccak) - Swift mangled symbols, certificate base64 and hashes look like addresses;
    they are only *scored* inside a payment/ransom demand;
  * raw-IP URLs are scored only for public, routable addresses and only when the URL points
    at a payload (executable/script/archive) or sits in a small standalone script;
  * tunnel / dynamic-DNS hosts count only as concrete subdomains (abc.ngrok-free.app), not
    as bare provider names in public-suffix / block lists;
  * documentation (man pages, markdown) and test fixtures only mention indicators.
"""
from __future__ import annotations

import hashlib
import re

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from ..filetype import is_textual
from . import register
from .scripts_common import is_documentation

MAX_TEXT = 1 << 20
MAX_STRINGS = 2 << 20
CAP = 200                      # per category, per object
_STRINGS = re.compile(rb"[\x20-\x7e]{6,}")

# --- validated TLD list (compact but covers the common + abused ones) --------------------------
TLDS = frozenset("""com net org info biz io co us uk ca de fr ru cn jp au nl se no fi dk pl it es br
in ir kr ch be at cz gr pt hu ro sk ua tr mx ar cl za nz sg hk tw th vn id ph my pk eg sa ae il
gov edu mil int name pro mobi asia xyz top club online site web app dev tech store shop cloud live
work space world life fun icu vip cc tv me ws cx to gg sh st ai bot link click download zip mov lol
su pw cf ga gq ml tk best buzz monster rest cyou sbs quest lat one team run host press email fund
cam wiki digital network solutions services agency center systems tools codes email finance""".split())

_URL = re.compile(r"""(?i)\b((?:https?|ftp|ftps|ws|wss)://[^\s"'<>()\[\]{}`|\\^]{3,512})""")
_DOMAIN = re.compile(r"(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,6}[a-z]{2,24})\b")
_IPV4 = re.compile(r"\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))\b")
_IPV6 = re.compile(r"(?i)(?<![:.\w])((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:)(?![.\w])")
_EMAIL = re.compile(r"(?i)\b([a-z0-9._%+-]{1,64}@(?:[a-z0-9-]{1,63}\.){1,4}[a-z]{2,24})\b")
_ONION = re.compile(r"(?i)\b([a-z2-7]{16}\.onion|[a-z2-7]{56}\.onion)\b")
_BTC = re.compile(r"(?<![\w$])(bc1[02-9ac-hj-np-z]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})(?![\w$])")
_ETH = re.compile(r"(?<![\w$])(0x[a-fA-F0-9]{40})(?![\w$])")
_IPV6_HINT = re.compile(r":[0-9a-fA-F]{0,4}:")        # every _IPV6 match has two colons at most 4 hex digits apart
_XMR = re.compile(r"(?<![\w$])([48][1-9A-HJ-NP-Za-km-z]{94})(?![\w$])")
_TG_TOKEN = re.compile(r"\b(\d{8,10}:[A-Za-z0-9_-]{35})\b")


def _tg_token_plausible(tok: str) -> bool:
    """A bot token's secret is random; font subsets and charset tables produce look-alikes made of alphabet
    runs ("12456789:ABCDEFGHIJQUVWXYZbcdefghij…"). Random text has ~0.5 consecutive-character steps in 35."""
    secret = tok.split(":", 1)[1]
    steps = sum(1 for a, b in zip(secret, secret[1:]) if ord(b) - ord(a) == 1)
    return steps < 6 and len(set(secret)) >= 15
_TG_API = re.compile(r"(?i)(api\.telegram\.org/bot[0-9]{6,}:[A-Za-z0-9_-]{30,})")
_DISCORD = re.compile(r"(?i)(https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{15,20}/[\w-]{60,80})")

_PASTE = ("pastebin.com", "paste.ee", "hastebin.com", "ghostbin", "rentry.co", "controlc.com",
          "0bin.net", "privatebin", "dpaste", " pastebin", "justpaste.it", "textbin", "transfer.sh",
          "anonfiles", "gofile.io", "file.io", "temp.sh", "termbin.com", "bashupload")
_TUNNEL = ("ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "duckdns.org", "no-ip.",
           "noip.com", "serveo.net", "localtunnel", "loclx.io", "portmap.io", "pagekite.me",
           "dynu.com", "hopto.org", "zapto.org", "sytes.net", "ddns.net", "myftp.", "onthewifi.com")
_SHORTENERS = ("bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly", "rebrand.ly",
               "shorturl", "ow.ly", "buff.ly", "t.me")
# provider front pages / docs, not a tunnel endpoint
_TUNNEL_SERVICE_LABELS = {"www", "api", "dashboard", "docs", "doc", "blog", "status", "help", "support",
                          "download", "downloads", "cdn", "static", "assets", "my", "account", "login",
                          "app", "mail", "community", "forum", "developers", "developer", "connect",
                          "tunnel", "portal", "admin", "ftp"}

# categories that raise the score even without a database, with per-category (score, confidence)
_RISK = {
    "onion": (25, Confidence.MEDIUM, "Tor hidden-service address"),
    "telegram_token": (45, Confidence.HIGH, "Telegram bot token (C2 / exfil channel)"),
    "discord_webhook": (40, Confidence.HIGH, "Discord webhook (common exfil channel)"),
    "raw_ip_url": (10, Confidence.LOW, "URL pointing at a bare public IP address"),
    "tunnel_host": (20, Confidence.MEDIUM, "Tunnel / dynamic-DNS host (ngrok, duckdns, serveo...)"),
    "paste_site": (5, Confidence.LOW, "Paste / anonymous-file host (payload staging)"),
}
# categories that documentation / test fixtures merely mention (not scored there)
_MENTION_ONLY_IN_DOCS = {"onion", "raw_ip_url", "tunnel_host", "paste_site", "wallet"}

# --- scoring context ----------------------------------------------------------------------------
_PAYLOAD_PATH = re.compile(
    r"(?i)/[^/?#\s]{0,120}\.(?:exe|dll|scr|msi|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|hta|jar|apk|sh|bash|zsh|"
    r"command|py|pl|bin|elf|so|dylib|dmg|pkg|zip|rar|7z|gz|tgz|xz|bz2|iso|img|lnk|docm|xlsm|"
    r"x86|x86_64|x64|i686|arm|arm7|arm64|aarch64|mips|mipsel|mpsl|ppc|sparc|m68k|sh4)(?:[?#]|$)")
_SMALL_SCRIPT_TYPES = {"script", "shell", "python", "powershell", "vbs", "javascript", "batch", "applescript",
                       "php", "perl", "ruby", "hta", "html", "url", "desktop", "email"}
SMALL_SCRIPT = 256 << 10
_TEST_PATH = re.compile(r"(?i)(?:^|/)(?:tests?|testing|testdata|test_data|fixtures?|spec|specs|__tests__|"
                        r"selftest|examples?)/|(?:^|/)test_[^/]*$|_test\.[a-z]{1,4}$|\.test\.[a-z]{1,4}$")

_PAY_CTX = re.compile(r"(?i)\b(?:ransom|decrypt(?:ion|or)?|encrypted|your (?:files|data|computer|device)|"
                      r"recover (?:your|the|all) files|payment|pay(?:ing)?|send (?:exactly|the|us|\$?\d)|"
                      r"transfer|deadline|within \d+ (?:hours|days))\b")
_COIN_CTX = re.compile(r"(?i)\b(?:bitcoin|btc|monero|xmr|ethereum|eth|usdt|tether|crypto(?:currency)?|wallet)\b")
_ETH_CTX = re.compile(r"(?i)(?:\beth(?:ereum)?\b|\bether\b|wallet|usdt|erc-?20|metamask|\bsend\b|\bpay)")


def _is_public_ip(ip: str) -> bool:
    try:
        a, b, c, _ = (int(x) for x in ip.split("."))
    except ValueError:
        return False
    if a in (0, 10, 127, 255) or a >= 224 or (a == 192 and b == 168) or (a == 169 and b == 254) \
            or (a == 172 and 16 <= b <= 31) or (a == 100 and 64 <= b <= 127) \
            or (a == 198 and b in (18, 19)):
        return False
    # RFC 5737 documentation networks (examples in docs, man pages, test fixtures)
    if (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113)) or (a, b, c) == (192, 0, 0):
        return False
    return True


def _valid_domain(d: str) -> bool:
    d = d.lower().rstrip(".")
    if len(d) > 253 or ".." in d:
        return False
    return d.rsplit(".", 1)[-1] in TLDS


def _host(url: str) -> str:
    h = re.sub(r"(?i)^\w+://", "", url).split("/", 1)[0].split("@")[-1].split(":")[0]
    return h.lower()


def _add(bag: dict, key: str, val: str):
    lst = bag.setdefault(key, [])
    if val not in lst and len(lst) < CAP:
        lst.append(val)


def _tunnel_provider(host: str) -> str | None:
    for t in _TUNNEL:
        if t in host:
            return t
    return None


def _tunnel_endpoint(host: str) -> bool:
    """abc.ngrok-free.app / x.duckdns.org - a concrete endpoint, not the provider's own site."""
    t = _tunnel_provider(host)
    if t is None or host.startswith("*"):
        return False
    i = host.find(t)
    sub = host[:i].rstrip(".")
    if not sub:
        return False
    return sub.split(".")[-1] not in _TUNNEL_SERVICE_LABELS


# --- wallet validation ----------------------------------------------------------------------------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_IDX = {c: i for i, c in enumerate(_B58)}
_BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008)
_KECCAK_ROT = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61), (28, 55, 25, 21, 56),
               (27, 20, 39, 8, 14))
_M64 = (1 << 64) - 1


def _keccak_f(a: list[int]) -> list[int]:
    for rc in _KECCAK_RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M64) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                r = _KECCAK_ROT[x][y]
                v = a[x + 5 * y]
                b[y + 5 * ((2 * x + 3 * y) % 5)] = (((v << r) | (v >> (64 - r))) & _M64) if r else v
        a = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    """Original Keccak-256 (Ethereum / Monero flavour, not NIST SHA3-256 padding)."""
    rate = 136
    p = bytearray(data)
    p.append(0x01)
    while len(p) % rate:
        p.append(0)
    p[-1] |= 0x80
    st = [0] * 25
    for off in range(0, len(p), rate):
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(p[off + 8 * i:off + 8 * i + 8], "little")
        st = _keccak_f(st)
    return b"".join(v.to_bytes(8, "little") for v in st[:4])


def _b58_int(s: str) -> int | None:
    n = 0
    for ch in s:
        v = _B58_IDX.get(ch)
        if v is None:
            return None
        n = n * 58 + v
    return n


def _btc_base58_ok(addr: str) -> bool:
    n = _b58_int(addr)
    if n is None or n >= 1 << 200:
        return False
    pad = len(addr) - len(addr.lstrip("1"))
    raw = b"\x00" * pad + (n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"")
    if len(raw) != 25 or raw[0] not in (0x00, 0x05):
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def _bech32_polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _bech32_ok(addr: str) -> bool:
    hrp, _, data = addr.rpartition("1")
    if hrp != "bc" or not 14 <= len(data) <= 74:
        return False
    vals = [_BECH.find(ch) for ch in data]
    if -1 in vals:
        return False
    chk = _bech32_polymod([ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + vals)
    ver = vals[0]
    prog_len = (len(vals) - 7) * 5 // 8
    if not 2 <= prog_len <= 40:
        return False
    if ver == 0:
        return chk == 1 and prog_len in (20, 32)
    return 1 <= ver <= 16 and chk == 0x2BC830A3


_XMR_BLOCK = {0: 0, 2: 1, 3: 2, 5: 3, 6: 4, 7: 5, 9: 6, 10: 7, 11: 8}


def _xmr_ok(addr: str) -> bool:
    out = bytearray()
    for i in range(0, len(addr), 11):
        blk = addr[i:i + 11]
        nb = _XMR_BLOCK.get(len(blk))
        n = _b58_int(blk)
        if nb is None or n is None or n >= 1 << (8 * nb):
            return False
        out += n.to_bytes(nb, "big")
    return len(out) == 69 and keccak256(bytes(out[:65]))[:4] == bytes(out[65:])


def _eip55_ok(addr: str) -> bool:
    hexpart = addr[2:]
    h = keccak256(hexpart.lower().encode()).hex()
    for ch, hc in zip(hexpart, h):
        if ch.isalpha() and (ch.isupper() != (int(hc, 16) >= 8)):
            return False
    return True


def _eth_ok(addr: str, text: str, pos: int) -> bool:
    hexpart = addr[2:]
    if len(set(hexpart.lower())) < 8:          # 0x000...0, 0xffff...: constants, not wallets
        return False
    if hexpart != hexpart.lower() and hexpart != hexpart.upper():
        return _eip55_ok(addr)                  # mixed case carries an EIP-55 checksum
    # no checksum information (40 hex digits are also SHA-1 hashes, keys, ids...): need context
    return bool(_ETH_CTX.search(text, max(0, pos - 48), pos))


MAX_WALLET_CANDIDATES = 4000     # per coin type and object
MAX_KECCAK = 128                 # pure-python keccak is ~1 ms: bound EIP-55 / Monero checks per object


def _wallets(text: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    seen: set[str] = set()
    kbudget = [MAX_KECCAK]

    def keccak_ok(check, *args) -> bool:
        if kbudget[0] <= 0:
            return False
        kbudget[0] -= 1
        return check(*args)

    def eth(a: str, p: int) -> bool:
        hexpart = a[2:]
        if hexpart != hexpart.lower() and hexpart != hexpart.upper() and len(set(hexpart.lower())) >= 8:
            return keccak_ok(_eth_ok, a, text, p)
        return _eth_ok(a, text, p)

    for rx, ok in ((_BTC, lambda a, p: _bech32_ok(a) if a.startswith("bc1") else _btc_base58_ok(a)),
                   (_ETH, eth),
                   (_XMR, lambda a, p: keccak_ok(_xmr_ok, a))):
        if rx is _ETH and "0x" not in text:
            continue
        n = 0
        for m in rx.finditer(text):
            a = m.group(1)
            n += 1
            if n > MAX_WALLET_CANDIDATES or len(out) >= CAP:     # bounded work on huge string dumps
                break
            if a in seen:
                continue
            try:
                valid = ok(a, m.start())
            except (ValueError, OverflowError):
                valid = False
            if valid:
                seen.add(a)
                out.append((a, m.start()))
    return out


def _extract(text: str) -> tuple[dict[str, list[str]], list[tuple[str, int]]]:
    # Each regex below runs only when a literal its every match must contain is present (a substring test
    # is ~50x cheaper than a regex pass): exactly the same results, a fraction of the time on normal files.
    bag: dict[str, list[str]] = {}
    urls = []
    low = text.lower()
    for m in (_URL.finditer(text) if "://" in text else ()):
        u = m.group(1).rstrip(".,);]'\"")
        urls.append(u)
        _add(bag, "url", u)
        host = _host(u)
        if _IPV4.fullmatch(host) and _is_public_ip(host):
            _add(bag, "raw_ip_url", u)
        if _tunnel_endpoint(host):
            _add(bag, "tunnel_host", u)
        if any(p in host for p in _PASTE):
            _add(bag, "paste_site", u)
        if any(host == s or host.endswith("." + s) for s in _SHORTENERS):
            _add(bag, "shortener", u)
        if len(bag.get("url", ())) >= CAP:
            break
    for m in (_EMAIL.finditer(text) if "@" in text else ()):
        if _valid_domain(m.group(1).split("@", 1)[1]):
            _add(bag, "email", m.group(1))
    email_hosts = {e.split("@", 1)[1].lower() for e in bag.get("email", ())}
    for m in _DOMAIN.finditer(text):
        d = m.group(1).lower().rstrip(".")
        if _valid_domain(d) and d not in email_hosts and not _IPV4.fullmatch(d):
            if _tunnel_endpoint(d) and not (m.start() > 0 and text[m.start() - 1] == "*"):
                _add(bag, "tunnel_host", d)
            if any(p == d or d.endswith("." + p.strip()) for p in (p.strip() for p in _PASTE)):
                _add(bag, "paste_site", d)
            _add(bag, "domain", d)
    for m in _IPV4.finditer(text):
        _add(bag, "ip", m.group(1))
    for m in (_IPV6.finditer(text) if _IPV6_HINT.search(text) else ()):
        if m.group(1).count(":") >= 2 and not re.fullmatch(r"(?:0{0,4}:){2,}0{0,4}", m.group(1)):
            _add(bag, "ipv6", m.group(1))
    for rx, key, need in ((_ONION, "onion", ".onion"), (_TG_TOKEN, "telegram_token", ":"),
                          (_TG_API, "telegram_token", "api.telegram.org/bot"),
                          (_DISCORD, "discord_webhook", "/api/webhooks/")):
        if need not in low:
            continue
        for m in rx.finditer(text):
            if rx is _TG_TOKEN and not _tg_token_plausible(m.group(1)):
                continue
            _add(bag, key, m.group(1))
    wallets = _wallets(text)
    for a, _ in wallets:
        _add(bag, "wallet", a)
    return bag, wallets


def extract_iocs(text: str) -> dict[str, list[str]]:
    return _extract(text)[0]


def _tunnel_is_list(bag: dict) -> bool:
    """Several different tunnel/DDNS providers in one object = a public-suffix or block list."""
    provs = {_tunnel_provider(_host(v) if "://" in v else v) for v in bag.get("tunnel_host", ())}
    return len(provs - {None}) >= 3


@register
class IOCAnalyzer(Analyzer):
    name = "ioc"
    order = 70

    def applies(self, obj: ScanObject) -> bool:
        return obj.size >= 8

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        textual = is_textual(obj)
        if textual:
            text = obj.text(MAX_TEXT)
        else:
            text = b"\n".join(_STRINGS.findall(obj.data[:MAX_STRINGS])).decode("latin-1")
        if not text:
            return
        bag, wallets = _extract(text)
        if not bag:
            return
        obj.meta["iocs"] = bag
        mention_only = textual and is_documentation(obj)
        for key, (score, conf, desc) in _RISK.items():
            vals = bag.get(key)
            if not vals or (mention_only and key in _MENTION_ONLY_IN_DOCS):
                continue
            if key == "raw_ip_url":
                # unit-test fixtures are full of sample endpoints
                vals = [] if _TEST_PATH.search(obj.display_path) else self._raw_ip_scored(obj, vals, textual)
            elif key == "tunnel_host" and _tunnel_is_list(bag):
                vals = []
            elif key == "paste_site":
                # a raw paste link (pastebin.com/raw/xyz), not the bare provider name
                vals = [v for v in vals if "://" in v and "/" in v.split("://", 1)[1].rstrip("/")]
            if vals:
                ctx.detect(obj, Detection(f"IOC:{key.title().replace('_', '')}", "ioc", conf, score,
                                          desc, vals[:8], pua=key == "paste_site"))
        if wallets and textual and not mention_only and obj.size <= SMALL_SCRIPT:
            demand = [a for a, pos in wallets if self._payment_context(text, pos)]
            if demand:
                ctx.detect(obj, Detection("IOC:Wallet", "ioc", Confidence.LOW, 15,
                                          "Cryptocurrency address in a payment / ransom demand", demand[:8]))
        self._lookup(ctx, obj, bag, text)

    @staticmethod
    def _raw_ip_scored(obj: ScanObject, vals: list[str], textual: bool) -> list[str]:
        """Payload URLs always; any public raw-IP URL only in a small standalone script."""
        payload = []
        for u in vals:
            rest = u.split("://", 1)[-1]
            slash = rest.find("/")
            if slash >= 0 and _PAYLOAD_PATH.search(rest[slash:]):
                payload.append(u)
        if payload:
            return payload
        if textual and obj.size <= SMALL_SCRIPT and obj.ftype in _SMALL_SCRIPT_TYPES:
            return vals
        return []

    @staticmethod
    def _payment_context(text: str, pos: int) -> bool:
        lo, hi = max(0, pos - 600), pos + 300
        return bool(_PAY_CTX.search(text, lo, hi)) and bool(_COIN_CTX.search(text, lo, hi))

    # TLDs that are also source/data file extensions: "bytestream.cc", "setup.py", "install.sh" in a
    # binary's strings are file names far more often than hosts, so only URL hosts are looked up
    _FILENAME_TLDS = {"cc", "py", "sh", "pl", "rs", "md", "so", "zip", "mov", "mk", "ml", "gd", "nu", "app",
                      "sb", "pm", "tf", "cs", "ps", "vc", "sc", "sx", "gz", "bz", "ts", "js", "rb", "go", "mm"}

    def _lookup(self, ctx: ScanContext, obj: ScanObject, bag: dict, text: str = "") -> None:
        svc = getattr(getattr(ctx, "services", None), "ioc", None)
        look = getattr(svc, "lookup", None)
        if not callable(look):
            return
        url_hosts = {_host(u) for u in bag.get("url", ())}
        domains = [d for d in bag.get("domain", ())
                   if d in url_hosts or d.rsplit(".", 1)[-1] not in self._FILENAME_TLDS]
        # bare dotted quads are often version numbers ("2.26.99.68"): only IPs used as URL hosts or
        # with a port are looked up
        ips = [i for i in bag.get("ip", ())
               if i in url_hosts or (text and re.search(re.escape(i) + r":\d{2,5}\b", text))]
        checks = ([("url", u) for u in bag.get("url", ())[:40]]
                  + [("domain", d) for d in domains[:40]]
                  + [("ip", i) for i in ips[:40]])
        for kind, val in checks:
            try:
                threat = look(kind, val)
            except Exception as exc:  # noqa: BLE001
                obj.errors.append(f"ioc.lookup: {exc!r}")
                return
            if threat:
                ctx.detect(obj, Detection(f"IOC:{threat}", "ioc", Confidence.HIGH, 60,
                                          f"Known-bad {kind} in threat database", [val]))
