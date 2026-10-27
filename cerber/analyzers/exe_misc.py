"""Executable helpers shared by the exe_* analyzers + DEX / Java / pyc / wasm analysis.

Shared part (imported by exe_pe / exe_elf / exe_macho / exe_unpack):
    sampled_entropy()      bounded entropy of a byte range (entropy_fast on a sample)
    string_hits()          one case-insensitive multi-literal pass (YARA engine; UTF-16LE too for PE)
                           -> Hits(key -> matched labels)
    apply_rules()          data-driven string rules shared by all executable formats
    printable_strings()    NUL/length-delimited ASCII strings (bounded)

Analyzer "exe_misc" (order 45):
    ftype dex         -> DEX string table: SMS / accessibility / device-admin / overlay abuse,
                         dynamic code loading, root tools
    ftype java_class  -> constant pool: Runtime.exec, ProcessBuilder, class loaders, reflection,
                         known Java RAT packages
    ftype jar         -> entry names only (members are extracted by the archive analyzer):
                         Adwind/jRAT resource names, RAT package paths
    ftype pyc         -> header/version, strings of the marshalled code (no unmarshal):
                         loaders, shellcode runners, stealers, keyloggers, reverse shells
    ftype wasm        -> header sanity, crypto-miner markers

Detections (engine "heuristic"; <Area> = PE | ELF | MachO | PYC | DEX | Java | WASM):
    Heur:<Area>.Ransom.ShadowCopyDeletion   40-50  vssadmin/wmic/wbadmin/bcdedit recovery destruction
    Heur:<Area>.Ransom.Note                 30-35  ransom-note phrases (+ Tor/Bitcoin payment hints)
    Heur:<Area>.HackTool.Mimikatz           60 pua mimikatz command/module strings
    Heur:<Area>.CredentialDumping.LSASS     30     lsass + MiniDumpWriteDump / comsvcs MiniDump
    Heur:<Area>.Stealer.BrowserCredentials  30-35  many browser profile paths + credential DB names
    Heur:<Area>.Stealer.BrowserKeys          8-40  several "<Browser> Safe Storage" keychain items
    Heur:<Area>.Stealer.CryptoWallets       25-35  wallet extension IDs / wallet file paths
    Heur:<Area>.Stealer.Messengers          30     Telegram tdata / Discord leveldb / FileZilla ...
    Heur:<Area>.Stealer.DiscordToken        30     Discord token regex / "dQw4w9WgXcQ:" prefix
    Heur:<Area>.Stealer.Keychain            30     keychain DB path + `security` dumping commands
    Heur:<Area>.Stealer.PasswordValidation  35     `dscl . authonly` (AMOS-style password check)
    Heur:<Area>.Stealer.PasswordPrompt      30-45  AppleScript "display dialog ... with hidden answer"
    Heur:<Area>.Stealer.UserData            20     Notes / Messages / Safari cookies collection
    Heur:<Area>.Stealer.WithExfil           20     stealer indicators + webhook/IP-lookup channel
    Heur:<Area>.Exfil.Webhook               10-20  Telegram bot API / Discord webhooks / file drops
    Heur:<Area>.Exfil.ArchiveUpload         20     ditto/zip + curl POST file=@
    Heur:<Area>.CryptoAddressRegex          10     embedded wallet-address regexes (>= 3 coin types)
    Heur:<Area>.ClipboardHijacker           40     wallet regexes (>= 2 coins) + clipboard read/write
    Heur:<Area>.ReverseShell                30-40  /dev/tcp + interactive shell, nc -e ...
    Heur:<Area>.ShcCompiledScript           20     shell script compiled with shc
    Heur:<Area>.CoinMiner                   15-40 pua  stratum URLs, xmrig, pools, donate-level
    Heur:<Area>.Miner.KillCompetitors       20     kills rival miners (kinsing, kdevtmpfsi, ...)
    Heur:<Area>.Persistence                 10     cron/systemd/rc persistence strings (ELF)
    Heur:<Area>.DefenseEvasion              15-30  iptables -F, setenforce 0, history wiping, ...
    Heur:<Area>.SSHKeyBackdoor              25     authorized_keys + embedded public key
    Heur:<Area>.Mirai.Credentials           50     Mirai default-credential list
    Heur:<Area>.Botnet.DDoS                 40     Mirai/Gafgyt attack method names
    Heur:<Area>.Persistence.WMI             30     WMI event subscription persistence
    Heur:<Area>.Persistence.Registry        15     IFEO / AppInit_DLLs / policy Run keys
    Heur:<Area>.Persistence.Autorun          5     Run key / Startup folder / schtasks
    Heur:<Area>.UACBypass                   30-45  shell\\open\\command hijack + auto-elevating binary
    Heur:<Area>.UACDisable                  15     EnableLUA + ConsentPromptBehaviorAdmin
    Heur:<Area>.DefenderTampering           20-35  Set-MpPreference / exclusions / WinDefend stop
    Heur:<Area>.LOLBinDownload              20-30  certutil -urlcache, bitsadmin /transfer, mshta http ...
    Heur:<Area>.PowerShellCradle             8-20  hidden/encoded/bypass PowerShell command lines
    Heur:<Area>.AntiVM                      10-25  VM artefact strings (and macOS: VM names + probes)
    Heur:<Area>.AnalysisToolEvasion         15-25  analyst tool process-name lists
    Heur:<Area>.HackTool.C2Implant          45     Cobalt Strike / Meterpreter implant markers
    Heur:<Area>.HackTool.Offensive          30 pua PowerSploit/Rubeus/LaZagne/SharpHound ...
    Heur:<Area>.GatekeeperBypass            15-35  spctl --master-disable / xattr -d com.apple.quarantine
    Heur:<Area>.TCCTampering                40     direct TCC.db INSERT
    Heur:<Area>.Persistence.LaunchAgent      5     LaunchAgent plist + launchctl load + RunAtLoad
    Heur:<Area>.Persistence.LoginHook       20     loginwindow LoginHook
    Heur:<Area>.Downloader                   5-10  curl|sh / chmod +x in /tmp, base64 -d | sh
    Heur:<Area>.TorOnionAddress             15     hard-coded v2/v3 .onion address
    Heur:DEX.SMSAbuse 20-30, Heur:DEX.AccessibilityAbuse 20, Heur:DEX.DeviceAdmin 20,
    Heur:DEX.DynamicCodeLoading 10, Heur:DEX.RootTools 10, Heur:DEX.BankerCombo 30, Heur:DEX.HideIcon 10
    Heur:Java.KnownRATPackage 50, Heur:Java.JarRAT.Resources 50, Heur:Java.CryptedLoader 25,
    Heur:Java.Dropper 15, Heur:Java.RuntimeExec 3
    Heur:PYC.ObfuscatedLoader 5-20, Heur:PYC.Pyarmor 10, Heur:PYC.ShellcodeRunner 35,
    Heur:PYC.Keylogger 30, Heur:PYC.ReverseShell 40, Heur:PYC.RansomwareLike 25
    Heur:WASM.CoinMiner 40 pua
"""
from __future__ import annotations

import io
import re
import struct
import zipfile
from dataclasses import dataclass
from typing import Callable, Iterable

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject, entropy_fast
from . import register

try:  # fast multi-literal matching (installed in the project venv)
    import yara  # type: ignore
except Exception:  # pragma: no cover
    yara = None
try:  # fallback accelerator
    import ahocorasick  # type: ignore
except Exception:  # pragma: no cover
    ahocorasick = None

# ---------------------------------------------------------------------------
# generic helpers
# ---------------------------------------------------------------------------
TEXT_HEAD = 64 << 20        # lowercased text view budget
TEXT_TAIL = 16 << 20
SCAN_HEAD = 160 << 20       # string-indicator scanning budget for huge binaries
SCAN_TAIL = 32 << 20


def sampled_entropy(data: bytes, start: int = 0, end: int | None = None, budget: int = 256 << 10,
                    chunks: int = 16) -> float:
    """Shannon entropy of data[start:end]; large ranges are sampled (chunks spread evenly)."""
    end = len(data) if end is None else min(end, len(data))
    start = max(0, start)
    n = end - start
    if n <= 0:
        return 0.0
    if n <= budget:
        return entropy_fast(data[start:end])
    csize = max(1, budget // chunks)
    step = n // chunks
    sample = b"".join(data[start + i * step: start + i * step + csize] for i in range(chunks))
    return entropy_fast(sample)


def lower_text(data: bytes) -> str:
    """Lowercased latin-1 view (1 byte == 1 char) bounded to TEXT_HEAD + TEXT_TAIL."""
    if len(data) > TEXT_HEAD + TEXT_TAIL:
        data = data[:TEXT_HEAD] + b"\n" + data[-TEXT_TAIL:]
    return data.decode("latin-1").lower()


_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,%d}")


def printable_strings(data: bytes, minlen: int = 4, maxlen: int = 512, limit: int = 200_000,
                      budget: int = 32 << 20) -> list[bytes]:
    rx = re.compile(rb"[\x20-\x7e]{%d,%d}" % (minlen, maxlen))
    out = []
    for m in rx.finditer(data, 0, min(len(data), budget)):
        out.append(m.group())
        if len(out) >= limit:
            break
    return out


def u16(d: bytes, o: int, be: bool = False) -> int:
    return struct.unpack_from(">H" if be else "<H", d, o)[0]


def u32(d: bytes, o: int, be: bool = False) -> int:
    return struct.unpack_from(">I" if be else "<I", d, o)[0]


def u64(d: bytes, o: int, be: bool = False) -> int:
    return struct.unpack_from(">Q" if be else "<Q", d, o)[0]


def cstr(d: bytes, o: int, maxlen: int = 1024) -> str:
    if o < 0 or o >= len(d):
        return ""
    e = d.find(b"\x00", o, o + maxlen)
    if e < 0:
        e = min(len(d), o + maxlen)
    return d[o:e].decode("utf-8", "replace")


def det(name: str, conf: Confidence, score: int, desc: str, evidence: Iterable[str] = (),
        pua: bool = False, offset: int | None = None) -> Detection:
    return Detection(name, "heuristic", conf, score, desc, [str(e)[:200] for e in evidence][:20], offset, pua)


# ---------------------------------------------------------------------------
# string indicator tables (all needles lowercase; label -> needles)
# platforms: pe, elf, macho, pyc, dex, java  ("*" = every platform)
# ---------------------------------------------------------------------------
def _same(*needles: str) -> dict[str, tuple[str, ...]]:
    return {n: (n,) for n in needles}


_ALL = ("pe", "elf", "macho", "pyc")
TABLE: dict[str, tuple[tuple[str, ...], dict[str, tuple[str, ...]]]] = {
    # ---- ransomware -------------------------------------------------------
    "shadow_delete": (("pe", "pyc"), {
        "vssadmin delete shadows": ("vssadmin delete shadows", "vssadmin.exe delete shadows",
                                    "delete shadows /all", "delete shadows /for="),
        "vssadmin resize shadowstorage": ("resize shadowstorage",),
        "wmic shadowcopy delete": ("shadowcopy delete", "shadowcopy where", "win32_shadowcopy.delete",
                                   "win32_shadowcopy | foreach-object {$_.delete"),
        "wbadmin delete": ("wbadmin delete catalog", "wbadmin delete systemstatebackup", "wbadmin delete backup"),
        "bcdedit recoveryenabled no": ("recoveryenabled no", "recoveryenabled=no"),
        "bcdedit bootstatuspolicy": ("bootstatuspolicy ignoreallfailures",),
    }),
    "ransom_note": (_ALL, _same(
        "your files have been encrypted", "your files are encrypted", "all your files have been encrypted",
        "all of your files have been encrypted", "files have been encrypted", "decrypt your files",
        "to decrypt your files", "your personal files are encrypted", "private key will be destroyed",
        "do not rename encrypted files", "do not try to decrypt", "pay the ransom", "your network has been penetrated",
        "your data has been stolen", "your documents, photos, databases", "how_to_decrypt", "how-to-decrypt",
        "readme_for_decrypt", "restore-my-files", "!!!_read_me", "decrypt_instruction", "your files are locked",
        "files are encrypted by", "buy decryptor", "purchase a decryptor", "unique decryption key")),
    "tor_pay": (_ALL, _same("tor browser", "torproject.org", "bitcoin", "monero", ".onion")),
    # ---- credential theft ---------------------------------------------------
    "mimikatz": (("pe", "pyc"), _same("sekurlsa::", "lsadump::", "kerberos::golden", "kerberos::ptt",
                                      "privilege::debug", "mimikatz", "gentilkiwi", "benjamin delpy", "mimilib",
                                      "mimidrv", "sekurlsa::logonpasswords")),
    "lsass_name": (("pe", "pyc"), _same("lsass.exe", "lsass.dmp")),
    "dump_api": (("pe", "pyc"), {"minidumpwritedump": ("minidumpwritedump",),
                                 "comsvcs minidump": ("comsvcs.dll, minidump", "comsvcs.dll minidump",
                                                      "comsvcs.dll,minidump", "comsvcs.dll#24")}),
    "browsers": (_ALL, {
        "chrome": ("google\\chrome", "google/chrome"),
        "edge": ("microsoft\\edge", "microsoft/edge"),
        "brave": ("bravesoftware",),
        "opera": ("opera software", "com.operasoftware.opera"),
        "vivaldi": ("vivaldi\\user data", "vivaldi/default", "application support/vivaldi"),
        "yandex": ("yandexbrowser", "yandex\\yandex", "yandex/yandex"),
        "chromium": ("chromium\\user data", "application support/chromium"),
        "firefox": ("mozilla\\firefox", "mozilla/firefox", "firefox/profiles", "firefox\\profiles"),
        "arc": ("arc\\user data", "arc/user data", "company.thebrowser.browser"),
        "epic": ("epic privacy browser",),
        "coccoc": ("coccoc\\browser", "coccoc/browser"),
        "comodo dragon": ("comodo\\dragon", "comodo/dragon"),
        "cent": ("centbrowser",),
        "iridium": ("iridium\\user data",),
        "torch": ("torch\\user data",),
        "orbitum": ("orbitum\\user data",),
        "kometa": ("kometa\\user data",),
        "amigo": ("amigo\\user data",),
        "sputnik": ("sputnik\\sputnik",),
        "7star": ("7star\\7star",),
        "chedot": ("chedot\\user data",),
        "thorium": ("thorium\\user data", "application support/thorium"),
        "waterfox": ("waterfox\\profiles", "waterfox/profiles"),
        "thunderbird": ("thunderbird\\profiles", "thunderbird/profiles"),
    }),
    "cred_files": (_ALL, {
        "login data": ("login data",), "web data": ("web data",), "local state": ("local state",),
        "encrypted_key": ("encrypted_key",), "logins.json": ("logins.json",), "key4.db": ("key4.db", "key3.db"),
        "signons.sqlite": ("signons.sqlite",), "cookies.sqlite": ("cookies.sqlite",),
        "formhistory.sqlite": ("formhistory.sqlite",), "cryptunprotectdata": ("cryptunprotectdata",),
        "cookies.binarycookies": ("cookies.binarycookies",),
    }),
    "safe_storage": (_ALL, {
        "chrome": ("chrome safe storage",), "brave": ("brave safe storage",),
        "edge": ("microsoft edge safe storage",), "opera": ("opera safe storage",),
        "vivaldi": ("vivaldi safe storage",), "chromium": ("chromium safe storage",),
        "yandex": ("yandex safe storage",), "arc": ("arc safe storage",), "coccoc": ("coccoc safe storage",),
    }),
    "wallet_ext": (_ALL, {
        "metamask": ("nkbihfbeogaeaoehlefnkodbefgpgknn", "ejbalbakoplchlghecdalmeeeajnimhm"),
        "phantom": ("bfnaelmomeimhlpmgjnjophhpkkoljpa",), "coinbase": ("hnfanknocfeofbddgcijnmhnfnkdnaad",),
        "tronlink": ("ibnejdfjmmkpcnlpebklmnkoeoihofec",), "binance": ("fhbohimaelbohpjbbldcngcnapndodjp",),
        "trust": ("egjidjbpglichdcondbcbdnbeeppgdph",), "exodus web3": ("aholpfdialjgjfhomihkjbmgjidlcdno",),
        "ronin": ("fnjhmkhhmkbjkkabndcnnogagogbneec",), "solflare": ("bhhhlbepdkbapadjdnnojkbgioiodbic",),
        "okx": ("mcohilncbfahbmgdjkbpemcciiolgcge",), "keplr": ("dmkamcknogkgcdfhhbddcghachkejeap",),
        "rabby": ("acmacodkjbdgmoleebolmdjonilkdbch",), "tonkeeper": ("omaabbefbmiijedngplfjmnooppbclkk",),
        "math": ("afbcbjpbpfadlkmhmclhkeeodmamcflc",), "nami": ("lpfcbjknijpeeillifnkikgncikgfhdo",),
        "yoroi": ("ffnbelfdoeiohenkjibnmadjiehjhajb",), "xdefi": ("hmeobnfnfcmdkdcmlblgagmfpfboieaf",),
        "guarda ext": ("hpglfhgfnhbgpjdenjgmdgoeiappafln",), "authenticator": ("bhghoamapcdpbohphigoooaddinpkbai",),
        "bitkeep": ("jiidiaalihmmhddjgbnbgdfflelocpak",), "martian": ("efbglgofoippbgcjepnhiblaibcnclgk",),
    }),
    "wallet_app": (_ALL, {
        "wallet.dat": ("wallet.dat",),
        "electrum": ("electrum\\wallets", "electrum/wallets"),
        "exodus": ("exodus\\exodus.wallet", "exodus/exodus.wallet", "exodus.conf.json"),
        "atomic": ("atomic\\local storage", "atomic/local storage"),
        "ethereum keystore": ("ethereum\\keystore", "ethereum/keystore"),
        "coinomi": ("coinomi\\coinomi\\wallets", "coinomi/wallets"),
        "guarda": ("guarda\\local storage", "guarda/local storage"),
        "jaxx": ("com.liberty.jaxx", "jaxx\\local storage", "jaxx/local storage"),
        "armory": ("armory\\", "application support/armory"),
        "bitcoin core": ("bitcoin\\wallets", "bitcoin/wallets"),
        "litecoin": ("litecoin\\wallets", "litecoin/wallets"),
        "monero": ("monero\\wallets", "monero/wallets"),
        "ledger live": ("ledger live\\", "ledger live/"),
        "trezor": ("@trezor\\suite-desktop", "@trezor/suite-desktop"),
        "wasabi": ("walletwasabi\\client\\wallets", "walletwasabi/client/wallets"),
        "daedalus": ("daedalus mainnet",),
        "binance app": ("binance\\app-store.json", "binance/app-store.json"),
        "zcash": ("zcash\\wallet", "zcash/wallet"),
    }),
    "messengers": (_ALL, {
        "telegram": ("telegram desktop\\tdata", "telegram desktop/tdata", "tdata\\key_datas", "key_datas"),
        "discord": ("discord\\local storage\\leveldb", "discord/local storage/leveldb", "discordcanary",
                    "discordptb", "lightcord"),
        "steam": ("loginusers.vdf",),
        "filezilla": ("recentservers.xml", "sitemanager.xml"),
        "pidgin": (".purple\\accounts.xml", ".purple/accounts.xml"),
        "signal": ("signal\\config.json", "signal/config.json"),
        "element": ("element\\local storage", "element/local storage"),
        "nordvpn": ("nordvpn\\nordvpn.exe", "user.config"),
        "openvpn": ("openvpn connect\\profiles", "openvpn connect/profiles"),
        "winscp": ("martin prikryl\\winscp",),
    }),
    "discord_token": (_ALL, _same("dqw4w9wgxcq:", "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}", "mfa\\.[\\w-]{84}",
                                  "[\\w-]{24,26}\\.[\\w-]{6}\\.[\\w-]{25,110}")),
    "exfil": (_ALL, {
        "telegram bot api": ("api.telegram.org/bot",),
        "discord webhook": ("discord.com/api/webhooks", "discordapp.com/api/webhooks"),
        "filedrop": ("https://transfer.sh", "anonfiles.com", "gofile.io/uploadfile", "store1.gofile.io",
                     "https://file.io", "pastebin.com/raw", "paste.ee/r/", "webhook.site/", "pipedream.net",
                     "requestbin.net", "requestbin.com", "requestcatcher.com", "ngrok-free.app", ".ngrok.io"),
    }),
    "ip_lookup": (_ALL, _same("api.ipify.org", "ip-api.com/json", "ipinfo.io/json", "icanhazip.com",
                              "checkip.amazonaws.com", "ifconfig.me", "myexternalip.com", "wtfismyip.com",
                              "ipwho.is", "freegeoip.app", "geolocation-db.com")),
    "wallet_regex": (_ALL, {
        "base58 class": ("a-hj-np-z", "a-km-za-hj-np-z1-9", "1-9a-hj-np-za-km-z"),
        "eth regex": ("0x[a-fa-f0-9]{40}", "0x[0-9a-fa-f]{40}", "0x[a-f0-9]{40}", "0x[0-9a-f]{40}"),
        "btc regex": ("(bc1|[13])", "^(bc1|[13])", "bc1[a-z0-9]{39,59}", "bc1q[a-z0-9]"),
        "xmr regex": ("4[0-9ab][1-9a-hj-np-za-km-z]{93}", "{93}$", "{93})"),
        "trx regex": ("^t[a-za-z0-9]{33}$", "t[a-za-z1-9]{33}"),
        "ltc regex": ("^[lm3][a-km-za-hj-np-z1-9]", "[lm3][a-km-za-hj-np-z1-9]"),
    }),
    "clipboard": (_ALL, {
        "openclipboard": ("openclipboard",), "getclipboarddata": ("getclipboarddata",),
        "setclipboarddata": ("setclipboarddata",), "addclipboardformatlistener": ("addclipboardformatlistener",),
        "nspasteboard": ("generalpasteboard", "nspasteboard"), "pbpaste": ("pbpaste",), "pbcopy": ("pbcopy",),
        "pyperclip": ("pyperclip",),
    }),
    # ---- shells / execution ---------------------------------------------------
    "devtcp": (_ALL, _same("/dev/tcp/", "/dev/udp/")),
    "shell_i": (_ALL, _same("bash -i", "sh -i >&", "/bin/sh -i", "/bin/bash -i", "sh -i 2>&1", "zsh -i >&")),
    "netcat": (_ALL, _same("nc -e /bin/", "ncat -e /bin/", "nc -c /bin/", "socat exec:", "mkfifo /tmp/",
                           "0<&196;exec 196<>", "rm /tmp/f;mkfifo", "nc -lvp", "exec 5<>/dev/tcp")),
    "shc": (("elf", "macho"), _same("neither argv[0] nor $_ works")),
    # ---- mining ---------------------------------------------------------------
    "miner": (_ALL + ("dex",), {
        "stratum": ("stratum+tcp://", "stratum+ssl://", "stratum2+tcp://", "stratum+tls://"),
        "xmrig": ("xmrig",), "xmr-stak": ("xmr-stak",),
        "donate-level": ("--donate-level", "donate-level", "donate.v2.xmrig.com", "donate.ssl.xmrig.com"),
        "cryptonight": ("cryptonight",), "randomx": ("randomx",),
        "pool": ("pool.supportxmr.com", "supportxmr.com", "moneroocean.stream", "nanopool.org", "hashvault.pro",
                 "c3pool.com", "2miners.com", "minexmr.com", "herominers.com", "unmineable.com", "nicehash.com",
                 "minergate.com", "xmrpool.eu", "f2pool.com", "ethermine.org"),
        "stratum json": ("mining.subscribe", "mining.authorize", "mining.submit"),
        "cpu throttling": ("--cpu-max-threads-hint", "--max-cpu-usage", "--cpu-priority"),
    }),
    "killer": (("elf", "pyc", "macho"), _same("kinsing", "kdevtmpfsi", "pkill -f xmrig", "killall xmrig",
                                                "pkill -9 -f", "kthreaddi", "watchbog", "pkill -f kinsing",
                                                "killall -9 kdevtmpfsi", "pkill -f sysupdate")),
    # ---- linux ------------------------------------------------------------------
    "lin_persist": (("elf", "pyc"), {
        "cron": ("@reboot", "crontab -l", "/var/spool/cron", "/etc/cron.d/", "/etc/crontab"),
        "systemd": ("systemctl enable", "/etc/systemd/system/", "wantedby=multi-user.target"),
        "rc": ("/etc/rc.local", "/etc/init.d/", "update-rc.d", "chkconfig --add"),
        "profile": ("/etc/profile.d/", "/.bashrc", "/.bash_profile"),
    }),
    "lin_defense": (("elf", "pyc"), {
        "iptables flush": ("iptables -f", "iptables -x", "iptables --flush"),
        "ufw disable": ("ufw disable",), "selinux": ("setenforce 0", "selinux=disabled"),
        "firewalld stop": ("systemctl stop firewalld", "systemctl disable firewalld", "service iptables stop"),
        "chattr": ("chattr -i", "chattr +i", "chattr -ia"),
        "history wipe": ("history -c", "unset histfile", "histfile=/dev/null", "export histsize=0"),
        "log wipe": ("rm -rf /var/log", "/var/log/wtmp", "/var/log/btmp", "echo > /var/log/"),
        "nmi watchdog": ("kernel.nmi_watchdog", "/proc/sys/kernel/nmi_watchdog"),
        "cloud agent removal": ("aliyun.service", "aegis_quartz", "/usr/local/aegis", "yunjing", "ydservice",
                                "qcloud_agent", "bcm-agent"),
    }),
    "preload_file": (("elf", "macho"), _same("/etc/ld.so.preload")),
    "ssh_keys": (("elf", "macho", "pyc"), {
        "authorized_keys": ("/.ssh/authorized_keys",),
        "embedded pubkey": ("ssh-rsa aaaab3nza", "ssh-ed25519 aaaac3nza"),
    }),
    "mirai_creds": (("elf",), _same("xc3511", "vizxv", "juantech", "7ujmko0admin", "7ujmko0vizxv", "zte521",
                                     "hi3518", "xmhdipc", "klv1234", "1001chin", "meinsm", "smcadmin", "hunt5759",
                                     "zsun1188", "tsgoingon", "zyad1234")),
    "botnet": (("elf",), _same("attack_udp", "attack_tcp", "attack_app", "attack_gre", "attack_method",
                               "udpplain", "tsource engine query", "killer_kill", "table_unlock_val", "scanner_init",
                               "dvrhelper", "lolnogtfo", "getlocalip", "scanner on", "scanner off", "udpflood",
                               "tcpflood", "httpflood", "kill_bots", "hackmylife", "ovh-bypass", "std flood")),
    "botnet_env": (("elf",), _same("/dev/watchdog", "/dev/misc/watchdog", "/proc/net/tcp", "/bin/busybox")),
    # ---- windows ----------------------------------------------------------------
    "win_wmi": (("pe", "pyc"), _same("__eventfilter", "commandlineeventconsumer", "__filtertoconsumerbinding",
                                     "activescripteventconsumer")),
    "win_persist_strong": (("pe", "pyc"), {
        "ifeo": ("image file execution options",), "appinit_dlls": ("appinit_dlls",),
        "policies run": ("policies\\explorer\\run",), "userinitmprlogonscript": ("userinitmprlogonscript",),
        "winlogon shell": ("winlogon\\shell", "winlogon\\userinit"),
    }),
    "win_persist": (("pe", "pyc"), {
        "run key": ("currentversion\\run",), "startup folder": ("start menu\\programs\\startup",),
        "schtasks": ("schtasks /create", "schtasks.exe /create", "schtasks /create"),
    }),
    "uac_hijack": (("pe", "pyc"), _same("ms-settings\\shell\\open\\command", "mscfile\\shell\\open\\command",
                                        "exefile\\shell\\open\\command", "folder\\shell\\open\\command",
                                        "delegateexecute", "launcher.systemsettings\\shell\\open\\command")),
    "uac_autoelevate": (("pe", "pyc"), _same("fodhelper", "eventvwr", "sdclt", "computerdefaults", "wsreset",
                                             "slui.exe", "cmstp", "silentcleanup", "changepk", "iscsicpl")),
    "uac_disable": (("pe", "pyc"), _same("enablelua", "consentpromptbehavioradmin", "promptonsecuredesktop")),
    "defender": (("pe", "pyc"), _same("set-mppreference", "add-mppreference", "disablerealtimemonitoring",
                                      "disableantispyware", "disablebehaviormonitoring", "disableioavprotection",
                                      "exclusionpath", "windows defender\\exclusions", "sc stop windefend",
                                      "sc delete windefend", "sc config windefend", "-removedefinitions -all")),
    "lol_strong": (("pe", "pyc"), _same("certutil -urlcache", "certutil.exe -urlcache", "certutil -decode",
                                        "bitsadmin /transfer", "mshta http", "mshta.exe http", "mshta vbscript:",
                                        "mshta javascript:", "regsvr32 /s /n /u /i:", "rundll32.exe javascript:",
                                        "rundll32 javascript:", ".downloadstring(", "downloadstring('http",
                                        "start-bitstransfer -source http")),
    "ps_flags": (("pe", "pyc"), {
        "-encodedcommand": ("-encodedcommand", " -enc "), "bypass": ("-executionpolicy bypass", "-exec bypass",
                                                                     "-ep bypass"),
        "hidden": ("-windowstyle hidden", "-w hidden", "-win hidden"), "iex": ("iex(", "iex (", "invoke-expression"),
        "webclient": ("net.webclient",), "frombase64string": ("frombase64string",),
    }),
    "win_antivm": (("pe",), _same(
        "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe", "vmsrvc.exe",
        "vmusrvc.exe", "prl_cc.exe", "prl_tools.exe", "xenservice.exe", "qemu-ga.exe", "sbiedll.dll",
        "api_log.dll", "dir_watch.dll", "pstorec.dll", "cmdvrt32.dll", "cmdvrt64.dll", "snxhk.dll", "avghookx.dll",
        "avghooka.dll", "cuckoomon.dll", "wine_get_unix_file_name", "hardware\\acpi\\dsdt\\vbox__",
        "vbox harddisk", "vmware virtual", "qemu harddisk", "sandboxie", "\\\\.\\vboxminirdrdn", "\\\\.\\vboxguest",
        "\\\\.\\hgfs", "vmhgfs.sys", "vboxmouse.sys", "vboxguest.sys", "vboxsf.sys", "vmmouse.sys",
        "software\\vmware, inc.\\vmware tools", "software\\oracle\\virtualbox guest additions")),
    "win_tools": (("pe",), _same(
        "wireshark.exe", "procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe", "ollydbg.exe",
        "x64dbg.exe", "x32dbg.exe", "idaq.exe", "idaq64.exe", "ida64.exe", "windbg.exe", "processhacker.exe",
        "fiddler.exe", "httpdebuggerui.exe", "tcpview.exe", "autoruns.exe", "immunitydebugger.exe", "dumpcap.exe",
        "pestudio.exe", "importrec.exe", "lordpe.exe", "joeboxcontrol.exe", "joeboxserver.exe", "regmon.exe",
        "filemon.exe", "sniff_hit.exe", "sysanalyzer.exe")),
    "c2_cs": (("pe",), _same("beacon.dll", "beacon.x64.dll", "%s as %s\\%s: %d", "could not spawn %s: %d",
                             "cobaltstrike", "%02d/%02d/%02d %02d:%02d:%02d")),
    "c2_msf": (("pe", "elf", "macho"), _same("metsrv", "meterpreter", "stdapi_sys_process", "priv_elevate_getsystem",
                                            "ext_server_")),
    "reflective": (("pe",), _same("reflectiveloader", "_reflectiveloader@")),
    "offensive": (("pe", "pyc"), _same("invoke-mimikatz", "invoke-reflectivepeinjection", "powersploit",
                                       "sharphound", "rubeus", "safetykatz", "lazagne", "psexesvc", "sliverpb",
                                       "bishopfox/sliver", "invoke-kerberoast", "kekeo")),
    # ---- macOS ------------------------------------------------------------------
    "mac_keychain_path": (("macho", "pyc"), _same("login.keychain-db", "/library/keychains/")),
    "mac_security_cmd": (("macho", "pyc"), _same("security find-generic-password", "security dump-keychain",
                                                  "security unlock-keychain", "security find-internet-password",
                                                  "security 2>&1 > /dev/null find-generic-password",
                                                  "find-generic-password -ga", "find-generic-password -wa",
                                                  "find-generic-password -w -s")),
    "mac_authonly": (("macho", "pyc"), _same("dscl . authonly", "dscl . -authonly", "dscl /local/default -authonly",
                                             "dscl /search -authonly", "dscl . -authonly \"")),
    "mac_hidden": (("macho", "pyc"), _same("with hidden answer", "hidden answer true")),
    "mac_dialog": (("macho", "pyc"), _same("display dialog")),
    "mac_lure": (("macho", "pyc"), _same("needs your password", "enter your password", "required application helper",
                                         "please enter your password", "update the system settings",
                                         "to launch the application", "macos wants to", "system preferences",
                                         "system settings")),
    "mac_userdata": (("macho", "pyc"), {
        "notes": ("group.com.apple.notes", "notestore.sqlite"), "messages": ("library/messages/chat.db",),
        "safari cookies": ("cookies.binarycookies",), "safari": ("library/safari/",),
        "keychains": ("library/keychains",), "telegram": ("application support/telegram desktop",),
        "desktop docs": ("/desktop/", "/documents/"),
    }),
    "mac_exfil_pack": (("macho", "pyc"), _same("ditto -c -k", "ditto -ck", "zip -r ", "zip -qr")),
    "mac_exfil_post": (("macho", "pyc"), _same("curl -f", "curl -x post", "file=@", "--data-binary @", "-f \"file=@",
                                               "--upload-file")),
    "mac_vm": (("macho",), {
        "vmware": ("vmware",), "virtualbox": ("virtualbox",), "parallels": ("parallels",), "qemu": ("qemu",),
        "apple virtual machine": ("apple virtual machine", "virtualmac"),
    }),
    "mac_vm_probe": (("macho",), _same("system_profiler sphardwaredatatype", "system_profiler spdisplaysdatatype",
                                       "sysctl -n hw.model", "ioreg -l", "ioreg -rd1 -c ioplatformexpertdevice",
                                       "sysctl -n machdep.cpu.brand_string", "system_profiler spusbdatatype")),
    "mac_gk_disable": (("macho", "pyc"), _same("spctl --master-disable", "spctl --global-disable")),
    "mac_quarantine_strip": (("macho", "pyc"), _same("xattr -d com.apple.quarantine", "xattr -rd com.apple.quarantine",
                                                     "xattr -dr com.apple.quarantine", "xattr -cr ")),
    "mac_tcc": (("macho", "pyc"), {"tcc.db": ("tcc.db",), "insert": ("insert into access", "insert or replace into access")}),
    "mac_simulator": (("macho",), _same("coresimulator", "fbsimulatorcontrol", "simctl")),
    "mac_launch": (("macho", "pyc"), {
        "agent dir": ("library/launchagents", "library/launchdaemons"),
        "launchctl": ("launchctl load", "launchctl bootstrap", "launchctl submit"),
        "runatload": ("runatload",),
    }),
    "mac_loginhook": (("macho", "pyc"), _same("com.apple.loginwindow loginhook", "com.apple.loginwindow logouthook",
                                              "loginwindow.plist loginhook")),
    "fetch": (("macho", "elf", "pyc"), _same("curl -", "curl http", "wget http", "wget -q", "curl -fssl")),
    "pipe_sh": (("macho", "elf", "pyc"), _same("| sh", "| bash", "|sh", "|bash", "| /bin/sh", "| /bin/bash")),
    "chmodx": (("macho", "elf", "pyc"), _same("chmod +x", "chmod 777", "chmod 755 /tmp", "chmod a+x")),
    "tmpdir": (("macho", "elf", "pyc"), _same("/tmp/", "/users/shared/", "/private/tmp/", "/var/tmp/", "/dev/shm/")),
    "b64_pipe": (("macho", "elf", "pyc"), _same("base64 -d |", "base64 --decode |", "base64 -d|", "base64 -d -i",
                                                 "openssl enc -d", "| base64 -d")),
    # ---- toolchain / packaging markers (informational) --------------------------
    "toolchain": (("pe", "elf", "macho"), {
        "Go": ("\xff go buildinf:", "go build id: \"", "runtime.gopanic"),
        "Rust": ("/rustc/", "rust_panic", "rust_begin_unwind"),
        "Nim": ("nimmain", "fatal.nim", "nimgc_"),
        "AutoIt": ("au3!ea06", ">>>autoit script<<<", ">>>autoit no cmdexecute<<<"),
        "NSIS": ("nullsoftinst", "nullsoft install system"),
        "InnoSetup": ("inno setup setup data", "innosetupldrwindow"),
        "PyInstaller": ("mei\x0c\x0b\x0a\x0b\x0e", "_meipass", "pyi-runtime-tmpdir"),
        "Nuitka": ("nuitka_onefile_parent", "__nuitka_binary_dir", "nuitka-onefile"),
        "py2app": ("py2app",),
        "Delphi": ("embarcadero delphi", "borland\\delphi", "software\\borland\\delphi\\rtl"),
        "InstallShield": ("installshield",),
        "WinRAR-SFX": ("winrar sfx",),
        "7z-SFX": (";!@install@!utf-8!",),
        "Electron": ("electron framework.framework", "electron_run_as_node"),
        "Qt": ("qt_version_tag",),
        "Xojo": ("xojoframework",),
        "Tauri": ("tauri://localhost",),
        "Deno": ("deno_core", "denort"),
        "Bun": ("bun:main", "/$bunfs/"),
        "Node-SEA": ("node_sea_blob",),
        "pkg(vercel)": ("pkg/prelude/bootstrap.js",),
    }),
}



class Hits:
    """key -> set of matched labels."""
    __slots__ = ("d",)

    def __init__(self) -> None:
        self.d: dict[str, set[str]] = {}

    def add(self, key: str, label: str) -> None:
        self.d.setdefault(key, set()).add(label)

    def n(self, key: str) -> int:
        return len(self.d.get(key, ()))

    def has(self, key: str, *labels: str) -> bool:
        s = self.d.get(key)
        if not s:
            return False
        return True if not labels else any(lb in s for lb in labels)

    def labels(self, key: str) -> list[str]:
        return sorted(self.d.get(key, ()))

    def evidence(self, keys: Iterable[str]) -> list[str]:
        out = []
        for k in keys:
            for lb in self.labels(k):
                out.append(f"{k}: {lb}")
        return out


def _yara_escape(s: str) -> str:
    out = []
    for ch in s:
        o = ord(ch)
        if ch in '"\\':
            out.append("\\" + ch)
        elif 0x20 <= o < 0x7F:
            out.append(ch)
        else:
            out.append("\\x%02x" % (o & 0xFF))
    return "".join(out)


class _Matcher:
    """Multi-literal, case-insensitive matcher. Uses YARA (C Aho-Corasick, ~250 MB/s), falls back to
    pyahocorasick over a lowercased latin-1 view, then to plain substring search."""

    def __init__(self, platform: str, wide: bool, extra: dict[str, dict[str, tuple[str, ...]]] | None = None):
        words: dict[str, list[tuple[str, str]]] = {}

        def add(key: str, label: str, needle: str) -> None:
            words.setdefault(needle, []).append((key, label))

        for key, (plats, labels) in TABLE.items():
            if platform not in plats and "*" not in plats:
                continue
            for label, needles in labels.items():
                for nd in needles:
                    add(key, label, nd.lower())
        for key, labels in (extra or {}).items():
            for label, needles in labels.items():
                for nd in needles:
                    add(key, label, nd.lower())
        self.words = words
        self.wide = wide
        self.rules = None
        self.idmap: dict[str, list[tuple[str, str]]] = {}
        self.auto = None
        if yara is not None:
            try:
                lines = ["rule cerber_exe_strings {", "strings:"]
                for i, (nd, vals) in enumerate(words.items()):
                    mods = "ascii wide nocase" if wide else "nocase"
                    lines.append(f'  $s{i} = "{_yara_escape(nd)}" {mods}')
                    self.idmap[f"$s{i}"] = vals
                lines.append("condition: any of them }")
                self.rules = yara.compile(source="\n".join(lines))
            except Exception:  # noqa: BLE001
                self.rules = None
        if self.rules is None and ahocorasick is not None:
            allw = dict(words)
            if wide:
                for nd, vals in words.items():
                    allw.setdefault("\x00".join(nd), []).extend(vals)
            a = ahocorasick.Automaton()
            for nd, vals in allw.items():
                a.add_word(nd, tuple(vals))
            a.make_automaton()
            self.auto = a

    def scan(self, data: bytes, hits: Hits) -> None:
        if self.rules is not None:
            try:
                for m in self.rules.match(data=data, fast=True, timeout=120):
                    for sm in m.strings:
                        for key, label in self.idmap.get(sm.identifier, ()):
                            hits.add(key, label)
                return
            except Exception:  # noqa: BLE001
                pass
        text = data.decode("latin-1").lower()
        if self.auto is not None:
            for _end, vals in self.auto.iter(text):
                for key, label in vals:
                    hits.add(key, label)
        else:  # slow fallback
            for nd, vals in self.words.items():
                if nd in text or (self.wide and "\x00".join(nd) in text):
                    for key, label in vals:
                        hits.add(key, label)


_MATCHERS: dict[tuple[str, bool, str], _Matcher] = {}


def string_hits(data: bytes, platform: str, wide: bool = False,
                extra: dict[str, dict[str, tuple[str, ...]]] | None = None, extra_id: str = "",
                text: str | None = None) -> tuple[Hits, bytes]:
    """Scan data once for every indicator of the platform. Returns (hits, the scanned bytes)."""
    key = (platform, wide, extra_id)
    m = _MATCHERS.get(key)
    if m is None:
        m = _MATCHERS[key] = _Matcher(platform, wide, extra)
    if text is not None:
        data = text.encode("latin-1", "ignore")
    elif len(data) > SCAN_HEAD + SCAN_TAIL:
        data = data[:SCAN_HEAD] + b"\n" + data[-SCAN_TAIL:]
    hits = Hits()
    m.scan(data, hits)
    return hits, data


_ONION_RE = re.compile(rb"(?<![a-z2-7])([a-z2-7]{56}|[a-z2-7]{16})\.onion(?![a-z0-9])")


def find_onions(data: bytes | str, limit: int = 5) -> list[str]:
    if isinstance(data, str):
        data = data.encode("latin-1", "ignore")
    out: list[str] = []
    pos = data.find(b".onion")
    n = 0
    while pos >= 0 and n < 2000 and len(out) < limit:
        m = _ONION_RE.search(data, max(0, pos - 57), pos + 7)
        if m:
            v = m.group(0).decode("ascii")
            if v not in out:
                out.append(v)
        pos = data.find(b".onion", pos + 6)
        n += 1
    return out


# ---------------------------------------------------------------------------
# shared rules
# ---------------------------------------------------------------------------
@dataclass
class Rule:
    suffix: str
    score: int
    conf: Confidence
    desc: str
    cond: Callable[[Hits], bool]
    keys: tuple[str, ...]
    pua: bool = False


def _n_browsers(h: Hits) -> int:
    return h.n("browsers")


STEALER_SUFFIXES = ("Stealer.BrowserCredentials", "Stealer.BrowserKeys", "Stealer.CryptoWallets",
                    "Stealer.Messengers", "Stealer.DiscordToken", "Stealer.Keychain", "Stealer.PasswordValidation",
                    "Stealer.PasswordPrompt", "Stealer.UserData")

# tiers of the same suffix: strongest first, the first matching tier wins
RULES: list[Rule] = [
    Rule("Ransom.ShadowCopyDeletion", 50, Confidence.HIGH,
         "Deletes Volume Shadow Copies / backups / recovery options (ransomware preparation)",
         lambda h: h.n("shadow_delete") >= 2, ("shadow_delete",)),
    Rule("Ransom.ShadowCopyDeletion", 40, Confidence.HIGH,
         "Deletes Volume Shadow Copies / backups / recovery options (ransomware preparation)",
         lambda h: h.n("shadow_delete") >= 1, ("shadow_delete",)),
    Rule("Ransom.Note", 35, Confidence.MEDIUM, "Contains ransom-note text",
         lambda h: h.n("ransom_note") >= 2, ("ransom_note", "tor_pay")),
    Rule("Ransom.Note", 30, Confidence.MEDIUM, "Contains ransom-note text with Tor/crypto payment instructions",
         lambda h: h.n("ransom_note") >= 1 and h.n("tor_pay") >= 1, ("ransom_note", "tor_pay")),
    Rule("HackTool.Mimikatz", 60, Confidence.HIGH, "Mimikatz credential dumping tool strings",
         lambda h: h.n("mimikatz") >= 2, ("mimikatz",), True),
    Rule("CredentialDumping.LSASS", 30, Confidence.MEDIUM, "Dumps LSASS process memory (credential theft)",
         lambda h: h.has("lsass_name") and h.has("dump_api"), ("lsass_name", "dump_api")),
    Rule("Stealer.BrowserCredentials", 35, Confidence.MEDIUM,
         "Targets saved credentials/cookies of many browsers",
         lambda h: _n_browsers(h) >= 5 and h.n("cred_files") >= 3, ("browsers", "cred_files")),
    Rule("Stealer.BrowserCredentials", 30, Confidence.MEDIUM,
         "Targets saved credentials/cookies of several browsers and decrypts them",
         lambda h: _n_browsers(h) >= 3 and h.n("cred_files") >= 3
         and (h.has("cred_files", "cryptunprotectdata", "encrypted_key") or h.n("safe_storage") >= 2),
         ("browsers", "cred_files", "safe_storage")),
    Rule("Stealer.BrowserKeys", 40, Confidence.MEDIUM,
         "Reads the keychain 'Safe Storage' keys of several browsers plus other stealer targets",
         lambda h: h.n("safe_storage") >= 3 and (h.has("mac_security_cmd") or h.n("wallet_ext") + h.n("wallet_app")
                                                 + h.n("messengers") >= 2 or h.has("exfil")),
         ("safe_storage", "mac_security_cmd", "wallet_ext", "wallet_app", "messengers", "exfil")),
    Rule("Stealer.BrowserKeys", 20, Confidence.LOW,
         "Reads the keychain 'Safe Storage' keys of many browsers (cookie/password decryption)",
         lambda h: h.n("safe_storage") >= 4, ("safe_storage",)),
    Rule("Stealer.BrowserKeys", 8, Confidence.LOW,
         "Reads the keychain 'Safe Storage' keys of several browsers (browser-data import or theft)",
         lambda h: h.n("safe_storage") == 3 or (h.n("safe_storage") == 2 and h.has("mac_security_cmd")),
         ("safe_storage", "mac_security_cmd")),
    Rule("Stealer.CryptoWallets", 35, Confidence.MEDIUM, "Targets many crypto-wallet browser extensions",
         lambda h: h.n("wallet_ext") >= 4, ("wallet_ext", "wallet_app")),
    Rule("Stealer.CryptoWallets", 30, Confidence.MEDIUM, "Targets crypto-wallet extensions and wallet files",
         lambda h: h.n("wallet_ext") >= 1 and h.n("wallet_app") >= 2, ("wallet_ext", "wallet_app")),
    Rule("Stealer.CryptoWallets", 25, Confidence.MEDIUM, "Targets several desktop crypto wallets",
         lambda h: h.n("wallet_app") >= 3, ("wallet_app",)),
    Rule("Stealer.Messengers", 30, Confidence.MEDIUM, "Targets messenger/FTP/VPN credential stores",
         lambda h: h.n("messengers") >= 3, ("messengers",)),
    Rule("Stealer.DiscordToken", 30, Confidence.MEDIUM, "Discord token grabber (token regex / encrypted token prefix)",
         lambda h: h.n("discord_token") >= 1 and (h.has("messengers", "discord") or h.n("discord_token") >= 2),
         ("discord_token", "messengers")),
    Rule("Stealer.Keychain", 30, Confidence.MEDIUM, "Dumps keychain items with the security tool",
         lambda h: h.has("mac_security_cmd") and (h.has("mac_keychain_path") or h.n("safe_storage") >= 1
                                                  or h.has("mac_security_cmd", "security dump-keychain")),
         ("mac_security_cmd", "mac_keychain_path", "safe_storage")),
    Rule("Stealer.PasswordValidation", 35, Confidence.MEDIUM,
         "Validates a harvested user password with `dscl . authonly` (AMOS-style stealer)",
         lambda h: h.n("mac_authonly") >= 1, ("mac_authonly",)),
    Rule("Stealer.PasswordPrompt", 45, Confidence.HIGH,
         "Fake password dialog: AppleScript display dialog with hidden answer and a system-settings lure",
         lambda h: h.has("mac_hidden") and h.has("mac_dialog") and h.has("mac_lure"),
         ("mac_hidden", "mac_dialog", "mac_lure")),
    Rule("Stealer.PasswordPrompt", 30, Confidence.MEDIUM,
         "Password dialog via AppleScript display dialog with hidden answer",
         lambda h: h.has("mac_hidden") and h.has("mac_dialog"), ("mac_hidden", "mac_dialog")),
    Rule("Stealer.UserData", 20, Confidence.LOW, "Collects Notes/Messages/Safari/keychain user data",
         lambda h: h.n("mac_userdata") >= 4, ("mac_userdata",)),
    Rule("Exfil.Webhook", 20, Confidence.MEDIUM, "Exfiltration via Telegram bot API / Discord webhook",
         lambda h: h.has("exfil", "telegram bot api", "discord webhook"), ("exfil",)),
    Rule("Exfil.Webhook", 10, Confidence.LOW, "Anonymous file-drop / request-bin service",
         lambda h: h.has("exfil", "filedrop"), ("exfil",)),
    Rule("Exfil.ArchiveUpload", 20, Confidence.MEDIUM, "Packs files (ditto/zip) and uploads them with curl",
         lambda h: h.has("mac_exfil_pack") and h.has("mac_exfil_post"), ("mac_exfil_pack", "mac_exfil_post")),
    Rule("ClipboardHijacker", 40, Confidence.HIGH,
         "Address regexes for several cryptocurrencies combined with clipboard read/write (clipper)",
         lambda h: h.n("wallet_regex") >= 2 and (h.has("clipboard", "setclipboarddata", "pbcopy", "nspasteboard",
                                                           "pyperclip") and h.n("clipboard") >= 2),
         ("wallet_regex", "clipboard")),
    Rule("CryptoAddressRegex", 10, Confidence.LOW, "Embedded regular expressions for several crypto-wallet addresses",
         lambda h: h.n("wallet_regex") >= 3, ("wallet_regex",)),
    Rule("ReverseShell", 40, Confidence.HIGH, "Reverse shell command line",
         lambda h: (h.has("devtcp") and h.has("shell_i")) or (h.has("netcat") and h.has("shell_i")),
         ("devtcp", "shell_i", "netcat")),
    Rule("ReverseShell", 30, Confidence.MEDIUM, "Netcat/socat/mkfifo shell plumbing",
         lambda h: h.n("netcat") >= 1 and h.has("devtcp") or h.n("netcat") >= 2, ("netcat", "devtcp")),
    Rule("ShcCompiledScript", 20, Confidence.MEDIUM, "Shell script compiled with shc (hides script source)",
         lambda h: h.has("shc"), ("shc",)),
    Rule("CoinMiner", 40, Confidence.MEDIUM, "Cryptocurrency miner", lambda h: h.n("miner") >= 3, ("miner",), True),
    Rule("CoinMiner", 25, Confidence.MEDIUM, "Cryptocurrency miner strings", lambda h: h.n("miner") == 2,
         ("miner",), True),
    Rule("CoinMiner", 15, Confidence.LOW, "Stratum mining pool URL", lambda h: h.has("miner", "stratum"),
         ("miner",), True),
    Rule("Miner.KillCompetitors", 20, Confidence.MEDIUM, "Kills competing miners / cleans other infections",
         lambda h: h.n("killer") >= 2, ("killer",)),
    Rule("Persistence", 10, Confidence.LOW, "cron/systemd/rc persistence command strings",
         lambda h: h.n("lin_persist") >= 2 and len(h.labels("lin_persist")) >= 2, ("lin_persist",)),
    Rule("DefenseEvasion", 30, Confidence.MEDIUM, "Disables firewall/SELinux/logging, wipes history",
         lambda h: h.n("lin_defense") >= 4, ("lin_defense",)),
    Rule("DefenseEvasion", 15, Confidence.LOW, "Disables firewall/SELinux/logging, wipes history",
         lambda h: h.n("lin_defense") >= 2, ("lin_defense",)),
    Rule("SSHKeyBackdoor", 25, Confidence.MEDIUM, "Adds an embedded public key to authorized_keys",
         lambda h: h.n("ssh_keys") >= 2, ("ssh_keys",)),
    Rule("Mirai.Credentials", 50, Confidence.HIGH, "Mirai-style IoT default credential list",
         lambda h: h.n("mirai_creds") >= 3, ("mirai_creds",)),
    Rule("Botnet.DDoS", 40, Confidence.MEDIUM, "IoT botnet DDoS attack/scanner strings",
         lambda h: h.n("botnet") >= 3, ("botnet", "botnet_env")),
    Rule("Persistence.WMI", 30, Confidence.MEDIUM, "WMI event subscription persistence",
         lambda h: h.n("win_wmi") >= 2, ("win_wmi",)),
    Rule("Persistence.Registry", 15, Confidence.LOW, "IFEO / AppInit_DLLs / Winlogon / policy Run key persistence",
         lambda h: h.n("win_persist_strong") >= 1, ("win_persist_strong",)),
    Rule("Persistence.Autorun", 5, Confidence.LOW, "Run key / Startup folder / scheduled task persistence",
         lambda h: h.n("win_persist") >= 2, ("win_persist",)),
    Rule("UACBypass", 45, Confidence.HIGH, "UAC bypass: shell\\open\\command hijack + auto-elevating binary",
         lambda h: h.n("uac_hijack") >= 1 and h.n("uac_autoelevate") >= 1, ("uac_hijack", "uac_autoelevate")),
    Rule("UACBypass", 30, Confidence.MEDIUM, "Registry shell\\open\\command hijack strings",
         lambda h: h.n("uac_hijack") >= 2, ("uac_hijack",)),
    Rule("UACDisable", 15, Confidence.LOW, "Disables UAC prompts (EnableLUA / ConsentPromptBehaviorAdmin)",
         lambda h: h.n("uac_disable") >= 2, ("uac_disable",)),
    Rule("DefenderTampering", 35, Confidence.MEDIUM, "Disables or excludes Microsoft Defender",
         lambda h: h.n("defender") >= 3, ("defender",)),
    Rule("DefenderTampering", 20, Confidence.MEDIUM, "Disables or excludes Microsoft Defender",
         lambda h: h.n("defender") == 2, ("defender",)),
    Rule("LOLBinDownload", 30, Confidence.MEDIUM, "Downloads payloads with living-off-the-land binaries",
         lambda h: h.n("lol_strong") >= 2, ("lol_strong",)),
    Rule("LOLBinDownload", 20, Confidence.MEDIUM, "Downloads payloads with living-off-the-land binaries",
         lambda h: h.n("lol_strong") >= 1, ("lol_strong",)),
    Rule("PowerShellCradle", 20, Confidence.MEDIUM, "Hidden/encoded PowerShell download cradle",
         lambda h: h.n("ps_flags") >= 4, ("ps_flags",)),
    Rule("PowerShellCradle", 8, Confidence.LOW, "PowerShell launched with evasive flags",
         lambda h: h.n("ps_flags") == 3, ("ps_flags",)),
    Rule("AntiVM", 25, Confidence.MEDIUM, "Checks for many virtual-machine / sandbox artefacts",
         lambda h: h.n("win_antivm") >= 4, ("win_antivm",)),
    Rule("AntiVM", 10, Confidence.LOW, "Checks for virtual-machine / sandbox artefacts",
         lambda h: h.n("win_antivm") >= 2, ("win_antivm",)),
    Rule("AntiVM", 20, Confidence.MEDIUM, "Probes hardware model for VM names (sandbox evasion)",
         lambda h: h.n("mac_vm") >= 2 and h.n("mac_vm_probe") >= 1, ("mac_vm", "mac_vm_probe")),
    Rule("AnalysisToolEvasion", 25, Confidence.MEDIUM, "Looks for analyst tools (debuggers, monitors)",
         lambda h: h.n("win_tools") >= 5, ("win_tools",)),
    Rule("AnalysisToolEvasion", 15, Confidence.LOW, "Looks for analyst tools (debuggers, monitors)",
         lambda h: h.n("win_tools") >= 3, ("win_tools",)),
    Rule("HackTool.C2Implant", 45, Confidence.HIGH, "Cobalt Strike / Meterpreter implant markers",
         lambda h: h.n("c2_cs") >= 2 or h.n("c2_msf") >= 2 or (h.has("reflective") and (h.has("c2_cs") or h.has("c2_msf"))),
         ("c2_cs", "c2_msf", "reflective")),
    Rule("HackTool.Offensive", 30, Confidence.MEDIUM, "Offensive security tooling strings",
         lambda h: h.n("offensive") >= 2, ("offensive",), True),
    Rule("GatekeeperBypass", 35, Confidence.MEDIUM, "Disables Gatekeeper (spctl --master-disable)",
         lambda h: h.has("mac_gk_disable"), ("mac_gk_disable", "mac_quarantine_strip")),
    Rule("GatekeeperBypass", 15, Confidence.LOW, "Strips the quarantine attribute from downloaded files",
         lambda h: h.has("mac_quarantine_strip"), ("mac_quarantine_strip",)),
    Rule("TCCTampering", 40, Confidence.HIGH, "Writes directly into the TCC privacy database",
         lambda h: h.has("mac_tcc", "tcc.db") and h.has("mac_tcc", "insert") and not h.has("mac_simulator"),
         ("mac_tcc",)),
    Rule("Persistence.LaunchAgent", 5, Confidence.LOW, "Installs and loads a RunAtLoad LaunchAgent/Daemon",
         lambda h: h.n("mac_launch") >= 3, ("mac_launch",)),
    Rule("Persistence.LoginHook", 20, Confidence.MEDIUM, "Sets a loginwindow LoginHook",
         lambda h: h.has("mac_loginhook"), ("mac_loginhook",)),
    Rule("Downloader", 10, Confidence.LOW, "Decodes base64 and pipes into a shell",
         lambda h: h.has("b64_pipe") and h.has("pipe_sh"), ("b64_pipe", "pipe_sh")),
    Rule("Downloader", 5, Confidence.LOW, "Downloads with curl/wget, marks executable / pipes to a shell in a temp dir",
         lambda h: h.has("fetch") and (h.has("pipe_sh") or h.has("chmodx")) and h.has("tmpdir"),
         ("fetch", "pipe_sh", "chmodx", "tmpdir")),
]


SCRIPT_RUNTIMES = {"Bun", "Node-SEA", "pkg(vercel)", "Deno"}   # embed whole JS programs: strings are not the host's


def runtime_cap(toolchain: Iterable[str]) -> dict[str, int] | None:
    return {"*": 2} if set(toolchain) & SCRIPT_RUNTIMES else None


def apply_rules(obj: ScanObject, ctx: ScanContext, area: str, hits: Hits,
                skip: set[str] | None = None, cap: dict[str, int] | None = None) -> list[str]:
    """Evaluate RULES; returns fired suffixes. cap: suffix -> max score ("*" = every rule), used to damp
    contexts where arbitrary embedded text is expected (platform tools, JS runtime bundles)."""
    fired: list[str] = []
    done: set[str] = set()
    for r in RULES:
        if r.suffix in done or (skip and r.suffix in skip):
            continue
        try:
            ok = r.cond(hits)
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            continue
        done.add(r.suffix)
        score = r.score
        if cap:
            if r.suffix in cap:
                score = min(score, cap[r.suffix])
            if "*" in cap:
                score = min(score, cap["*"])
        conf = r.conf if score >= 15 else min(r.conf, Confidence.LOW)
        ctx.detect(obj, det(f"Heur:{area}.{r.suffix}", conf, score, r.desc, hits.evidence(r.keys), r.pua))
        fired.append(r.suffix)
    stealers = [s for s in fired if s in STEALER_SUFFIXES]
    if stealers and (hits.has("exfil") or hits.n("ip_lookup") >= 1) and not (cap and "*" in cap):
        ctx.detect(obj, det(f"Heur:{area}.Stealer.WithExfil", Confidence.HIGH, 20,
                            "Stealer indicators combined with an exfiltration/IP-lookup channel",
                            hits.evidence(("exfil", "ip_lookup"))))
        fired.append("Stealer.WithExfil")
    return fired


def onion_rule(obj: ScanObject, ctx: ScanContext, area: str, text: bytes | str, hits: Hits) -> None:
    if not hits.has("tor_pay", ".onion"):
        return
    onions = find_onions(text)
    if onions:
        ctx.detect(obj, det(f"Heur:{area}.TorOnionAddress", Confidence.LOW, 15,
                            "Hard-coded Tor .onion address (C2 or ransom payment portal)", onions))


# ---------------------------------------------------------------------------
# DEX / Java / pyc / wasm
# ---------------------------------------------------------------------------
def _uleb128(d: bytes, o: int) -> tuple[int, int]:
    r = 0
    shift = 0
    for i in range(5):
        if o >= len(d):
            break
        b = d[o]
        o += 1
        r |= (b & 0x7F) << shift
        if b < 0x80:
            break
        shift += 7
    return r, o


def go_buildinfo(d: bytes) -> dict | None:
    """Go >= 1.18 build info (version + main module) from the '\\xff Go buildinf:' blob."""
    p = d.find(b"\xff Go buildinf:")
    if p < 0:
        return None
    info: dict = {"offset": p}
    try:
        flags = d[p + 15]
        if flags & 2 and p + 33 < len(d):
            ln, q = _uleb128(d, p + 32)
            if 0 < ln < 64:
                info["version"] = d[q:q + ln].decode("utf-8", "replace")
                ln2, q2 = _uleb128(d, q + ln)
                if 32 < ln2 < (1 << 20):
                    mod = d[q2 + 16:q2 + ln2 - 16].decode("utf-8", "replace")
                    for line in mod.splitlines()[:64]:
                        parts = line.split("\t")
                        if parts[0] == "path" and len(parts) > 1:
                            info["path"] = parts[1]
                        elif parts[0] == "mod" and len(parts) > 1:
                            info["module"] = parts[1]
    except Exception:  # noqa: BLE001
        pass
    return info


def dex_strings(d: bytes, limit: int = 300_000) -> list[str]:
    if len(d) < 0x70:
        return []
    n, off = struct.unpack_from("<II", d, 0x38)
    n = min(n, limit)
    if off + 4 * n > len(d):
        n = max(0, (len(d) - off) // 4)
    out = []
    ids = struct.unpack_from(f"<{n}I", d, off) if n else ()
    for so in ids:
        if so >= len(d):
            continue
        _ln, p = _uleb128(d, so)
        e = d.find(b"\x00", p, p + 4096)
        if e < 0:
            continue
        out.append(d[p:e].decode("utf-8", "replace"))
    return out


def java_utf8_constants(d: bytes, limit: int = 65535) -> list[str] | None:
    """Parse a class file constant pool and return CONSTANT_Utf8 entries (None if malformed)."""
    if len(d) < 10 or d[:4] != b"\xca\xfe\xba\xbe":
        return None
    count = u16(d, 8, True)
    o = 10
    out: list[str] = []
    i = 1
    while i < min(count, limit):
        if o >= len(d):
            return out
        tag = d[o]
        if tag == 1:
            ln = u16(d, o + 1, True)
            out.append(d[o + 3:o + 3 + ln].decode("utf-8", "replace"))
            o += 3 + ln
        elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
            o += 5
        elif tag in (5, 6):
            o += 9
            i += 1
        elif tag in (7, 8, 16, 19, 20):
            o += 3
        elif tag == 15:
            o += 4
        else:
            return out
        i += 1
    return out


JAVA_RAT_NAMES = ("jrat", "adwind", "strrat", "unrecom", "jbifrost", "alienspy", "frutas", "crossrat", "qrat",
                  "jacksbot", "sockrat", "ratty", "maskedrat", "sparta", "unknownrat", "jsocket")
_JAVA_RAT_RE = re.compile(r"(?:^|/)(" + "|".join(JAVA_RAT_NAMES) + r")(?:/|$)", re.I)
ADWIND_RESOURCES = ("drop.box", "mega.download", "sky.drive")

PYC_NAME_RULES = {
    # pyc code objects store names/constants as separate strings
    "loader_exec": ("exec", "eval"),
    "loader_decode": ("b64decode", "decompress", "loads", "a85decode", "b85decode", "b32decode", "fromhex"),
    "loader_mod": ("marshal", "zlib", "base64", "lzma", "bz2", "codecs"),
}


@register
class MiscExeAnalyzer(Analyzer):
    name = "exe_misc"
    order = 45

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype in ("dex", "java_class", "pyc", "wasm", "jar")

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        fn = getattr(self, "_" + obj.ftype, None)
        if fn:
            fn(obj, ctx)

    # -- DEX --------------------------------------------------------------------
    def _dex(self, obj: ScanObject, ctx: ScanContext) -> None:
        d = obj.data
        strings = dex_strings(d)
        ver = d[4:7].decode("latin-1", "replace")
        obj.meta["dex"] = {"version": ver, "strings": len(strings)}
        if not strings:
            obj.errors.append("dex: no string table")
            return
        low = {s.lower() for s in strings if len(s) < 300}
        blob = "\n".join(low)

        def cnt(words):
            return [w for w in words if w in blob]

        sms = cnt(("sendtextmessage", "smsmanager", "android.provider.telephony.sms_received", "abortbroadcast",
                   "getmessagesfromintent", "createfrompdu", "content://sms", "sendmultiparttextmessage"))
        acc = cnt(("accessibilityservice", "performglobalaction", "dispatchgesture", "getrootinactivewindow",
                   "accessibilitynodeinfo", "action_set_text", "findaccessibilitynodeinfosbyviewid"))
        admin = cnt(("devicepolicymanager", "locknow", "resetpassword", "wipedata", "deviceadminreceiver",
                     "add_device_admin"))
        overlay = cnt(("system_alert_window", "type_application_overlay", "type_system_alert", "type_phone"))
        dyn = cnt(("dalvik/system/dexclassloader", "dalvik/system/inmemorydexclassloader",
                   "dalvik/system/basedexclassloader", "ldalvik/system/dexclassloader;"))
        root = cnt(("/system/xbin/su", "/system/bin/su", "superuser.apk", "eu.chainfire.supersu", "com.topjohnwu.magisk"))
        hide = cnt(("setcomponentenabledsetting", "component_enabled_state_disabled"))
        if len(sms) >= 3:
            sc = 30 if "abortbroadcast" in sms else 20
            ctx.detect(obj, det("Heur:DEX.SMSAbuse", Confidence.MEDIUM, sc, "Sends/intercepts SMS messages", sms))
        if len(acc) >= 4:
            ctx.detect(obj, det("Heur:DEX.AccessibilityAbuse", Confidence.MEDIUM, 20,
                                "Accessibility service automation (screen reading / gesture injection)", acc))
        if len(admin) >= 3:
            ctx.detect(obj, det("Heur:DEX.DeviceAdmin", Confidence.MEDIUM, 20,
                                "Device administrator abuse (lock / wipe / reset password)", admin))
        if dyn:
            ctx.detect(obj, det("Heur:DEX.DynamicCodeLoading", Confidence.LOW, 10,
                                "Loads DEX code at runtime (DexClassLoader)", dyn))
        if len(root) >= 2:
            ctx.detect(obj, det("Heur:DEX.RootTools", Confidence.LOW, 10, "Looks for / uses root tools", root))
        if len(hide) >= 2:
            ctx.detect(obj, det("Heur:DEX.HideIcon", Confidence.LOW, 10, "Hides its launcher icon", hide))
        if len(acc) >= 3 and overlay and (len(sms) >= 2 or len(admin) >= 2):
            ctx.detect(obj, det("Heur:DEX.BankerCombo", Confidence.HIGH, 30,
                                "Accessibility + overlay + SMS/device-admin combination typical of banking trojans",
                                acc + overlay + sms + admin))
        hits, _ = string_hits(blob.encode("latin-1", "ignore"), "dex")
        apply_rules(obj, ctx, "DEX", hits)

    # -- Java class ---------------------------------------------------------------
    def _java_class(self, obj: ScanObject, ctx: ScanContext) -> None:
        utf = java_utf8_constants(obj.data)
        if utf is None:
            obj.errors.append("java: malformed class file")
            return
        major = u16(obj.data, 6, True) if len(obj.data) >= 8 else 0
        obj.meta["java"] = {"major_version": major, "utf8_constants": len(utf)}
        s = set(utf)
        rats = sorted({m.group(1).lower() for u in utf if "/" in u for m in [_JAVA_RAT_RE.search(u)] if m})
        if rats:
            ctx.detect(obj, det("Heur:Java.KnownRATPackage", Confidence.HIGH, 50,
                                "Class belongs to a known Java RAT package", rats))
        runtime_exec = "java/lang/Runtime" in s and "exec" in s
        pb = "java/lang/ProcessBuilder" in s
        loader = bool(s & {"defineClass", "java/net/URLClassLoader"})
        reflect = len(s & {"java/lang/reflect/Method", "invoke", "forName", "getDeclaredMethod", "setAccessible"}) >= 4
        crypt = "javax/crypto/Cipher" in s and bool(s & {"java/util/Base64", "decodeBuffer", "getDecoder"})
        ev = [x for x in ("java/lang/Runtime", "java/lang/ProcessBuilder", "defineClass", "java/net/URLClassLoader",
                          "java/lang/reflect/Method", "javax/crypto/Cipher") if x in s]
        if loader and crypt and reflect:
            ctx.detect(obj, det("Heur:Java.CryptedLoader", Confidence.MEDIUM, 25,
                                "Decrypts and defines classes at runtime via reflection (crypter stub)", ev))
        elif (runtime_exec or pb) and loader and reflect:
            ctx.detect(obj, det("Heur:Java.Dropper", Confidence.LOW, 15,
                                "Executes commands and loads classes dynamically via reflection", ev))
        elif runtime_exec:
            ctx.detect(obj, det("Heur:Java.RuntimeExec", Confidence.LOW, 3, "Executes OS commands (Runtime.exec)", ev))
        text = "\n".join(u for u in utf if len(u) < 400).lower()
        hits, _ = string_hits(b"", "pyc", text=text)
        apply_rules(obj, ctx, "Java", hits)

    # -- JAR (entry names only; extraction is done by the archive analyzer) -------------
    def _jar(self, obj: ScanObject, ctx: ScanContext) -> None:
        try:
            zf = zipfile.ZipFile(io.BytesIO(obj.data))
            names = zf.namelist()[:100_000]
        except Exception as exc:  # noqa: BLE001
            obj.errors.append(f"jar: {exc!r}")
            return
        low = [n.lower() for n in names]
        res = [n for n in low if n.rsplit("/", 1)[-1] in ADWIND_RESOURCES]
        if res:
            ctx.detect(obj, det("Heur:Java.JarRAT.Resources", Confidence.HIGH, 50,
                                "JAR contains Adwind/jRAT configuration resources", res))
        rats = sorted({m.group(1) for n in low for m in [_JAVA_RAT_RE.search(n)] if m})
        if rats:
            ctx.detect(obj, det("Heur:Java.KnownRATPackage", Confidence.HIGH, 50,
                                "JAR contains a known Java RAT package", rats))
        classes = [n for n in low if n.endswith(".class")]
        obj.meta["jar"] = {"entries": len(names), "classes": len(classes)}

    # -- pyc ------------------------------------------------------------------------
    def _pyc(self, obj: ScanObject, ctx: ScanContext) -> None:
        d = obj.data
        magic = u16(d, 0)
        obj.meta["pyc"] = {"magic": magic, "python": pyc_version(magic)}
        body = d[16:] if len(d) > 16 else b""
        strs = printable_strings(body, 3, 4096, 100_000, 16 << 20)
        names = {s.decode("latin-1") for s in strs if len(s) <= 64}
        text = b"\n".join(strs).decode("latin-1").lower()
        ev = []
        exe = [n for n in PYC_NAME_RULES["loader_exec"] if n in names]
        dec = [n for n in PYC_NAME_RULES["loader_decode"] if n in names]
        mod = [n for n in PYC_NAME_RULES["loader_mod"] if n in names]
        big_blob = max((len(s) for s in strs), default=0) >= 2048 and any(
            len(s) >= 2048 and re.fullmatch(rb"[A-Za-z0-9+/=_\-]+", s[:4096]) for s in strs)
        if exe and dec and mod:
            ev = exe + dec + mod
            if big_blob:
                ctx.detect(obj, det("Heur:PYC.ObfuscatedLoader", Confidence.MEDIUM, 20,
                                    "Decodes a large embedded blob and executes it (exec+b64/zlib/marshal)", ev))
            else:
                ctx.detect(obj, det("Heur:PYC.ObfuscatedLoader", Confidence.LOW, 5,
                                    "exec/eval combined with decoding/unmarshalling", ev))
        if "__pyarmor__" in names or "pyarmor_runtime" in text or "__pyarmor_enter" in text:
            ctx.detect(obj, det("Heur:PYC.Pyarmor", Confidence.LOW, 10, "PyArmor-protected bytecode", ["pyarmor"]))
        if "ctypes" in names and ({"VirtualAlloc", "VirtualAllocEx", "mmap"} & names) and \
                ({"CreateThread", "RtlMoveMemory", "CFUNCTYPE", "CreateRemoteThread", "WriteProcessMemory"} & names):
            ctx.detect(obj, det("Heur:PYC.ShellcodeRunner", Confidence.HIGH, 35,
                                "ctypes memory allocation + thread/function pointer (shellcode runner)",
                                sorted(names & {"ctypes", "VirtualAlloc", "VirtualAllocEx", "mmap", "CreateThread",
                                                "RtlMoveMemory", "CFUNCTYPE", "CreateRemoteThread",
                                                "WriteProcessMemory"})))
        if ("pynput" in names or "pynput.keyboard" in text) and {"Listener", "on_press"} & names and \
                ({"smtplib", "requests", "urlopen", "SMTP"} & names or "webhooks" in text or "api.telegram.org" in text):
            ctx.detect(obj, det("Heur:PYC.Keylogger", Confidence.HIGH, 30,
                                "Keyboard listener with network/mail exfiltration", ["pynput", "Listener"]))
        if "socket" in names and "dup2" in names and ({"subprocess", "pty", "os"} & names) and \
                ("/bin/sh" in text or "/bin/bash" in text or "cmd.exe" in text):
            ctx.detect(obj, det("Heur:PYC.ReverseShell", Confidence.HIGH, 40,
                                "socket + dup2 + shell (reverse shell)", ["socket", "dup2"]))
        crypto = {"AES", "Fernet", "encrypt", "ChaCha20"} & names
        if crypto and {"walk", "listdir", "scandir"} & names and {"remove", "unlink", "rename"} & names and \
                ("ransom" in text or "bitcoin" in text or "decrypt your" in text or ".onion" in text):
            ctx.detect(obj, det("Heur:PYC.RansomwareLike", Confidence.MEDIUM, 25,
                                "Encrypts while walking directories and references ransom/payment",
                                sorted(crypto)))
        hits, _ = string_hits(b"", "pyc", text=text)
        apply_rules(obj, ctx, "PYC", hits)
        onion_rule(obj, ctx, "PYC", text, hits)

    # -- wasm -----------------------------------------------------------------------
    def _wasm(self, obj: ScanObject, ctx: ScanContext) -> None:
        d = obj.data
        ver = u32(d, 4) if len(d) >= 8 else -1
        obj.meta["wasm"] = {"version": ver}
        if ver != 1:
            obj.errors.append(f"wasm: unexpected version {ver}")
        text = lower_text(d)
        strong = [w for w in ("cryptonight", "coinhive", "cryptoloot", "cryptonight_hash", "randomx_calculate_hash",
                              "cn_slow_hash", "webminer", "minero.cc") if w in text]
        if strong:
            ctx.detect(obj, det("Heur:WASM.CoinMiner", Confidence.MEDIUM, 40,
                                "WebAssembly crypto-miner (CryptoNight/RandomX/Coinhive markers)", strong, pua=True))


# Python bytecode magic numbers (little-endian u16 of the first two bytes)
_PYC_MAGIC = [(3379, "3.6"), (3394, "3.7"), (3413, "3.8"), (3425, "3.9"), (3439, "3.10"), (3495, "3.11"),
              (3531, "3.12"), (3571, "3.13"), (3627, "3.14"), (3700, "3.15")]
PYC_MAGIC_FOR_VERSION = {"3.6": 3379, "3.7": 3394, "3.8": 3413, "3.9": 3425, "3.10": 3439, "3.11": 3495,
                         "3.12": 3531, "3.13": 3571, "3.14": 3627}


def pyc_version(magic: int) -> str:
    best = "unknown"
    for m, v in _PYC_MAGIC:
        if magic >= m:
            best = v
    if magic < 3000:
        return "2.x" if 20000 <= magic < 63000 else "unknown"
    return best
