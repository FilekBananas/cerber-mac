"""SSH (authorized_keys, client config, sshd config) and sudoers.

Privacy: key material is never stored - only key type, a SHA-256 fingerprint,
the comment and the names of options."""
from __future__ import annotations

import base64
import hashlib
import os
import re

from ..core import Confidence
from .model import Signal
from .patterns import classify_path, command_signals, expand, redact
from .util import EnvContext, lstat_info, read_text, safe_listdir, world_writable

E = "Heur:Env.SSH"
KEY_TYPES = ("ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
             "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-rsa-cert-v01@openssh.com",
             "ssh-ed25519-cert-v01@openssh.com")


def _split_options(line: str) -> tuple[str, str]:
    """Split 'opt1,opt2="a b" ssh-ed25519 AAAA comment' into (options, rest)."""
    in_q = False
    for i, c in enumerate(line):
        if c == '"':
            in_q = not in_q
        elif c in " \t" and not in_q:
            return line[:i], line[i:].strip()
    return line, ""


def parse_authorized_key(line: str) -> dict | None:
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    opts = ""
    if not s.startswith(KEY_TYPES):
        opts, s = _split_options(s)
    parts = s.split(None, 2)
    if len(parts) < 2:
        return {"invalid": True}
    ktype, blob = parts[0], parts[1]
    comment = parts[2] if len(parts) > 2 else ""
    try:
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip("=")
    except Exception:  # noqa: BLE001
        fp = "invalid"
    opt_names = []
    command = None
    for m in re.finditer(r'([A-Za-z-]+)(?:="((?:[^"\\]|\\.)*)")?', opts):
        opt_names.append(m.group(1))
        if m.group(1).lower() == "command":
            command = m.group(2) or ""
    return {"type": ktype, "fingerprint": fp, "comment": comment[:80], "options": opt_names, "command": command}


def collect_ssh(ctx: EnvContext) -> None:
    ctx.progress("SSH i sudoers")
    keys_inv = ctx.inv("ssh_authorized_keys")
    remote_login = ctx.posture.get("remote_login")
    for h in ctx.homes:
        sshdir = os.path.join(h.home, ".ssh")
        for name in ("authorized_keys", "authorized_keys2"):
            p = os.path.join(sshdir, name)
            body = read_text(p, 1 << 20)
            if body is None:
                continue
            keys = [k for k in (parse_authorized_key(l) for l in body.splitlines()) if k]
            for k in keys:
                keys_inv.append(dict(k, user=h.name, file=p, command=redact(k["command"]) if k.get("command") else None))
            sigs: list[Signal] = []
            if keys:
                sigs.append(Signal(f"{E}.AuthorizedKeys", 5, Confidence.LOW,
                                   f"{len(keys)} klucz(y) pozwala na logowanie SSH jako {h.name}"
                                   + (" (Zdalne logowanie jest włączone)" if remote_login else ""),
                                   [f"{k.get('type')} {k.get('fingerprint')} {k.get('comment')}" for k in keys[:5]]))
            for k in keys:
                if k.get("command") is not None:
                    cmd = k["command"]
                    sigs.append(Signal(f"{E}.ForcedCommand", 10, Confidence.LOW, "klucz ma wymuszone polecenie", [redact(cmd)]))
                    sigs += command_signals(cmd, E, "polecenie authorized_keys")
                if "environment" in [o.lower() for o in k.get("options", [])]:
                    sigs.append(Signal(f"{E}.KeyEnvironment", 10, Confidence.LOW, "klucz ustawia zmienne środowiskowe", []))
            if name == "authorized_keys2":
                sigs.append(Signal(f"{E}.AuthorizedKeys2", 10, Confidence.LOW,
                                   "obecny przestarzały plik authorized_keys2", [p]))
            if world_writable(p) or world_writable(sshdir):
                sigs.append(Signal(f"{E}.WritableKeys", 30, Confidence.MEDIUM,
                                   "authorized_keys (lub ~/.ssh) jest zapisywalny dla wszystkich", [p]))
            ctx.add_finding("ssh", f"SSH authorized_keys użytkownika {h.name}", p, sigs,
                            {"keys": [dict(k, command=redact(k["command"]) if k.get("command") else None) for k in keys],
                             "file": lstat_info(p)}, allow_zero=True)
        # client config: ProxyCommand / LocalCommand / Match exec run arbitrary commands
        cfg = os.path.join(sshdir, "config")
        body = read_text(cfg, 1 << 20)
        if body is not None:
            cmds = []
            for line in body.splitlines():
                m = re.match(r"^\s*(ProxyCommand|LocalCommand|KnownHostsCommand|Match\s+.*\bexec)\s*=?\s*(.+)$", line, re.I)
                if m:
                    cmds.append((m.group(1), m.group(2)))
            ctx.inventory.setdefault("ssh_config_commands", []).extend(
                {"file": cfg, "directive": d, "command": redact(c, 200)} for d, c in cmds)
            sigs = []
            for d, c in cmds:
                sigs += command_signals(c, E, f"konfiguracja ssh {d}")
            ctx.add_finding("ssh", f"Konfiguracja klienta SSH użytkownika {h.name}", cfg, sigs,
                            {"commands": [{"directive": d, "command": redact(c, 200)} for d, c in cmds]})
    # server config
    for f in ["/etc/ssh/sshd_config"] + [os.path.join("/etc/ssh/sshd_config.d", n)
                                         for n in safe_listdir("/etc/ssh/sshd_config.d")[0]]:
        body = read_text(f, 1 << 20)
        if body is None:
            continue
        sigs = []
        for line in body.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = re.match(r"(?i)^(AuthorizedKeysFile|AuthorizedKeysCommand|PermitRootLogin|ForceCommand|PermitEmptyPasswords)\s+(.+)$", s)
            if not m:
                continue
            key, val = m.group(1).lower(), m.group(2)
            ctx.inventory.setdefault("sshd_settings", []).append({"file": f, "setting": m.group(1), "value": redact(val, 120)})
            if key == "authorizedkeyscommand":
                sigs.append(Signal(f"{E}.KeysCommand", 20, Confidence.MEDIUM, "sshd pobiera klucze przez polecenie", [redact(val)]))
            if key == "authorizedkeysfile" and any(classify_path(expand(v)).has("tmp", "shared") for v in val.split()):
                sigs.append(Signal(f"{E}.KeysFileTemp", 40, Confidence.HIGH,
                                   "sshd czyta klucze z lokalizacji tymczasowej/współdzielonej", [val]))
            if key == "permitemptypasswords" and val.lower() == "yes":
                sigs.append(Signal(f"{E}.EmptyPasswords", 25, Confidence.MEDIUM, "sshd dopuszcza puste hasła", [s]))
            if key == "permitrootlogin" and val.lower() == "yes":
                sigs.append(Signal(f"{E}.RootLogin", 10, Confidence.LOW, "sshd dopuszcza logowanie roota hasłem", [s]))
            if key == "forcecommand":
                sigs += command_signals(val, E, "sshd ForceCommand")
        ctx.add_finding("ssh", f"Konfiguracja sshd {f}", f, sigs, {})

    # sudoers
    readable = False
    for f in ["/etc/sudoers"] + [os.path.join("/etc/sudoers.d", n) for n in safe_listdir("/etc/sudoers.d")[0]]:
        body = read_text(f, 1 << 20)
        if body is None:
            if os.path.exists(f):
                ctx.limit(f"{f} jest nieczytelny (wymaga roota)")
            continue
        readable = True
        sigs = []
        for line in body.splitlines():
            s = line.strip()
            if not s or s.startswith("#") and not s.startswith(("#include", "#includedir")):
                continue
            if re.search(r"^Defaults\b.*!authenticate\b", s):
                sigs.append(Signal("Heur:Env.Sudo.NoAuthenticate", 30, Confidence.MEDIUM,
                                   "sudo skonfigurowane bez uwierzytelniania", [s]))
            elif re.search(r"\bNOPASSWD\s*:\s*ALL\b", s) and not s.startswith("%admin"):
                sigs.append(Signal("Heur:Env.Sudo.NopasswdAll", 20, Confidence.MEDIUM,
                                   "sudo bez hasła dla wszystkich poleceń", [redact(s)]))
            elif re.search(r"NOPASSWD\s*:.*(?:/tmp/|/Users/Shared/|/\.[A-Za-z])", s):
                sigs.append(Signal("Heur:Env.Sudo.NopasswdTemp", 35, Confidence.MEDIUM,
                                   "sudo bez hasła dla programu w lokalizacji tymczasowej/ukrytej", [redact(s)]))
            if re.search(r"^Defaults\b.*env_keep\s*\+?=.*\b(?:DYLD_|LD_PRELOAD)", s):
                sigs.append(Signal("Heur:Env.Sudo.KeepDyld", 30, Confidence.MEDIUM,
                                   "sudo zachowuje zmienne DYLD_* (wstrzykiwanie bibliotek do procesów roota)", [s]))
        ctx.add_finding("sudo", f"sudoers {f}", f, sigs, {"file": lstat_info(f)})
    ctx.inventory["sudoers_checked"] = readable
