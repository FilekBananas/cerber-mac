"""Speed shortcuts must never change what is detected.

* lazy PE signatures: the pre-check finds every file that is (or can contain) a Windows executable;
* TLSH candidates: the SQL lower bound returns the same nearest neighbour as the full scan of the band;
* Python literal tokenizer: identical tokens to the original combined regex;
* IOC extraction: literal pre-filters keep every indicator.

    .venv/bin/python -m unittest tests.test_speed_paths -v
"""
from __future__ import annotations

import os
import random
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerber.analyzers import ioc  # noqa: E402
from cerber.deobf import textops  # noqa: E402
from cerber.engines.hashdb import HashDB  # noqa: E402
from cerber.engines.ioc_fuzzy import tlsh_lval  # noqa: E402
from cerber.scanner import may_hold_windows_exe  # noqa: E402

try:
    import tlsh
except ImportError:  # pragma: no cover
    tlsh = None


class PreCheckTest(unittest.TestCase):
    def test_windows_holders(self):
        d = tempfile.mkdtemp()
        txt = os.path.join(d, "notes.txt")
        Path(txt).write_text("hello")
        macho = os.path.join(d, "tool")
        Path(macho).write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 64)
        self.assertFalse(may_hold_windows_exe([txt, macho]))
        exe = os.path.join(d, "setup.bin")
        Path(exe).write_bytes(b"MZ\x90\x00" + b"\0" * 64)
        self.assertTrue(may_hold_windows_exe([txt, exe]))
        z = os.path.join(d, "a.data")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("x.txt", "x")
        self.assertTrue(may_hold_windows_exe([txt, z]))                 # by content, not by name
        self.assertTrue(may_hold_windows_exe([txt, os.path.join(d, "missing.dmg")]))   # by extension
        self.assertFalse(may_hold_windows_exe([os.path.join(d, "missing")]))


@unittest.skipIf(tlsh is None, "py-tlsh missing")
class TlshBoundTest(unittest.TestCase):
    def test_same_nearest_neighbour(self):
        rnd = random.Random(7)
        base = [bytes(rnd.getrandbits(8) for _ in range(rnd.randint(2048, 6000))) for _ in range(12)]
        hashes = []
        for b in base:                                   # families of mutated variants → real neighbours
            for _ in range(25):
                m = bytearray(b)
                for _ in range(rnd.randint(0, 400)):
                    m[rnd.randrange(len(m))] = rnd.getrandbits(8)
                h = tlsh.hash(bytes(m))
                if h and h != "TNULL":
                    hashes.append(h)
        d = tempfile.mkdtemp()
        p = os.path.join(d, "h.sqlite")
        con = sqlite3.connect(p)
        con.execute("CREATE TABLE tlsh(tlsh TEXT PRIMARY KEY, lval INTEGER, name TEXT) WITHOUT ROWID")
        for i, h in enumerate(hashes[1::2]):
            stored = h if i % 2 else h[2:]               # the real DB holds both spellings
            con.execute("INSERT OR IGNORE INTO tlsh VALUES (?,?,?)", (stored, tlsh_lval(h), f"Fam{i}"))
        con.commit()
        con.close()
        db = HashDB(p)

        def best(rows, h):
            b = (10 ** 9, None)
            for c, n in rows:
                dd = tlsh.diff(h, c)
                if dd < b[0]:
                    b = (dd, n)
            return b
        checked = 0
        for h in hashes[::2]:
            lv = tlsh_lval(h)
            full = best(db.tlsh_candidates(lv, 1), h)
            fast = best(db.tlsh_candidates_within(h, lv, 1, 50), h)
            if full[0] <= 50:
                self.assertEqual(full, fast)
                checked += 1
            else:
                self.assertTrue(fast[1] is None or fast[0] > 50)
        self.assertGreater(checked, 20)


class PyTokensTest(unittest.TestCase):
    def test_identical_to_combined_regex(self):
        rx = textops._LIT_RX["python"]
        rnd = random.Random(3)
        alphabet = "rbufRBUFx_ '\"\\\n9é"
        cases = ["'a'b'c'", "rb'x' Rb\"y\" xrb'z' brb'q' f'{a}' _b'w' 9r'v' ub'' \"\"\"d\"\"\" r'''t''' 'open",
                 Path(textops.__file__).read_text()]
        cases += ["".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 50))) for _ in range(20000)]
        for t in cases:
            self.assertEqual([(m.start(), m.end(), m.group(0)) for m in rx.finditer(t)],
                             list(textops._py_tokens(t)), repr(t[:60]))


class IocPrefilterTest(unittest.TestCase):
    def test_indicators_still_found(self):
        text = ("see http://203.0.113.9/a.sh and 2001:db8:85a3:0:0:8a2e:370:7334, mail bob@example.com, "
                "x.ONION 3g2upl4pq6kufc4m.onion api.Telegram.org/bot123456:" + "A" * 35 +
                " https://discord.com/api/webhooks/123456789012345678/" + "a" * 68)
        bag = ioc.extract_iocs(text)
        self.assertIn("http://203.0.113.9/a.sh", bag.get("url", []))
        self.assertTrue(any("2001:db8" in v for v in bag.get("ipv6", [])))
        self.assertIn("bob@example.com", bag.get("email", []))
        self.assertIn("3g2upl4pq6kufc4m.onion", bag.get("onion", []))
        self.assertTrue(bag.get("telegram_token"))
        self.assertTrue(bag.get("discord_webhook"))
        self.assertEqual(ioc.extract_iocs("plain words only, nothing here"), {})


if __name__ == "__main__":
    unittest.main()
