"""Console + HTML reports (Polish UI)."""
from __future__ import annotations

import html
import json
import os
import sys

VERDICT_PL = {"MALICIOUS": "ZŁOŚLIWY", "PUA": "NIECHCIANY (PUA)", "SUSPICIOUS": "PODEJRZANY", "INFO": "INFO",
              "CLEAN": "CZYSTY"}
COLORS = {"MALICIOUS": "\033[1;31m", "PUA": "\033[1;35m", "SUSPICIOUS": "\033[1;33m", "INFO": "\033[36m",
          "CLEAN": "\033[32m"}
RESET = "\033[0m"


def _c(verdict: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{COLORS.get(verdict, '')}{text}{RESET}"


def human_bytes(n: float) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return str(n)


def print_console(report: dict, show_info: bool = False, env: dict | None = None) -> None:
    p = print
    p("")
    p("═" * 78)
    p(f" CERBER – raport skanowania   {report['started']} → {report['finished']} ({report['seconds']} s)")
    p("═" * 78)
    p(f" Pliki: {report['files']:,}   dane: {human_bytes(report['bytes'])}   obiekty (z rozpakowanymi): "
      f"{report['objects']:,}")
    p(f" Wzorce/sygnatury w bazach: {report.get('patterns_total', 0):,}")
    c = report["counts"]
    p(" Wynik: " + "  ".join(_c(k, f"{VERDICT_PL[k]}: {c.get(k, 0)}") for k in
                             ("MALICIOUS", "PUA", "SUSPICIOUS", "INFO", "CLEAN")))
    if report.get("timeouts"):
        p(f" Przekroczony czas (częściowy skan): {report['timeouts']}")
    if report.get("skipped_count"):
        p(f" Pominięte (brak dostępu itp.): {report['skipped_count']}")
    if report.get("cloud_only"):
        p(f" Pominięte – tylko w chmurze (iCloud itp.), nie ma ich na dysku: {report['cloud_only']}")
    if report.get("cache_hits"):
        p(f" Niezmienione od poprzedniego skanu (pamięć skanów, liczone jako czyste): {report['cache_hits']:,}")
    if env:
        print_env(env)
    shown = [r for r in report["results"] if show_info or r["verdict"] != "INFO"]
    if shown:
        p("─" * 78)
    for r in shown:
        v = r["verdict"]
        p(_c(v, f" [{VERDICT_PL[v]}] ") + f"{r['path']}")
        p(f"     wynik: {r.get('score', 0)}  główne wykrycie: {r.get('primary') or '-'}  "
          f"typ: {r.get('ftype', '?')}  sha256: {r.get('sha256', '')[:16]}…")
        dets = sorted(r["detections"], key=lambda d: (["INFO", "LOW", "MEDIUM", "HIGH", "CERTAIN"]
                                                      .index(d["confidence"]), d["score"]), reverse=True)
        for d in dets[:8]:
            where = d["object"].rsplit(">>", 1)[-1] if ">>" in d["object"] else ""
            where = f"  [w: {where}]" if where else ""
            p(f"       · {d['name']}  ({d['engine']}, {d['confidence']}, +{d['score']}){where}")
            if d.get("description"):
                p(f"         {d['description'][:150]}")
        if len(dets) > 8:
            p(f"       … i {len(dets) - 8} więcej")
        ai = r.get("ai")
        if ai:
            p(f"     AI: {ai_family_text(ai)} ({ai.get('confidence', 0):.2f}) {ai.get('points', 0):+d} pkt – "
              f"{ai.get('summary_pl', '')[:200]}")
            for a in ai.get("accusations") or []:
                p(f"       AI ocenia {a.get('name')}: {AI_VERDICT_PL.get(a.get('verdict'), ('?',))[0]} "
                  f"({float(a.get('confidence') or 0):.2f}, {int(a.get('points') or 0):+d}) {str(a.get('reason_pl', ''))[:120]}")
        if r.get("quarantined"):
            p(f"     → przeniesiono do kwarantanny (id {r['quarantined']})")
    if not shown:
        p(_c("CLEAN", " Nie znaleziono zagrożeń."))
    p("═" * 78)


def print_env(env: dict) -> None:
    p = print
    p("─" * 78)
    p(" Środowisko systemu:")
    post = env.get("posture", {})
    for k, v in list(post.items())[:14]:
        p(f"   {k}: {v}")
    findings = env.get("findings", [])
    bad = [f for f in findings if f.get("score", 0) >= 15 or f.get("confidence") in ("HIGH", "CERTAIN")]
    p(f"   Znaleziska: {len(findings)} (istotne: {len(bad)})")
    for f in sorted(bad, key=lambda f: -f.get("score", 0))[:30]:
        p(f"   ! [{f.get('category')}] {f.get('title')}  ({f.get('name')}, +{f.get('score')})")
        p(f"       {f.get('location', '')[:150]}")
    for lim in env.get("limitations", [])[:8]:
        p(f"   (ograniczenie) {lim}")


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#667085;--line:#e4e7ec;--mal:#d92d20;--pua:#9e3bd1;
--sus:#dc6803;--info:#1570ef;--ok:#079455}
@media (prefers-color-scheme: dark){:root{--bg:#0f1115;--card:#171a21;--fg:#e6e8ee;--muted:#98a2b3;--line:#2a2f3a}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}.muted{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.tile b{display:block;font-size:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin:12px 0}
.v{display:inline-block;padding:2px 8px;border-radius:6px;color:#fff;font-weight:600;font-size:12px}
.MALICIOUS{background:var(--mal)}.PUA{background:var(--pua)}.SUSPICIOUS{background:var(--sus)}
.INFO{background:var(--info)}.CLEAN{background:var(--ok)}
code{font:12px ui-monospace,Menlo,monospace;word-break:break-all}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-top:1px solid var(--line);padding:5px 6px;text-align:left;vertical-align:top}
details summary{cursor:pointer;color:var(--muted)}
.qbtn{display:none;margin-left:8px;padding:2px 10px;border-radius:6px;background:var(--mal);color:#fff;font-weight:600;
font-size:12px;text-decoration:none}.qdone{margin-left:8px;color:var(--ok);font-weight:600;font-size:12px}
.qnote{margin-left:8px;color:var(--muted);font-size:12px}
.sev{display:inline-block;padding:1px 7px;border-radius:6px;font-size:11.5px;font-weight:600;color:#fff;background:#98a2b3}
.sev-malicious{background:var(--mal)}.sev-pua{background:var(--pua)}.sev-suspicious{background:var(--sus)}
.sev-low{background:var(--info)}.sev-ok{background:var(--ok)}
"""

QUARANTINE_SCORE = 60               # SUSPICIOUS/PUA from this score up count as high risk (quarantine button)


def high_risk(r: dict) -> bool:
    """Files the user is offered to quarantine: MALICIOUS, or SUSPICIOUS/PUA with a high score. Nothing is
    ever moved without the user's click."""
    v = r.get("verdict")
    return v == "MALICIOUS" or (v in ("SUSPICIOUS", "PUA") and (r.get("score") or 0) >= QUARANTINE_SCORE)


def quarantine_offer(r: dict) -> bool:
    """Shown (only inside Cerber.app's report window, which re-checks the JSON) next to high-risk real files."""
    path = str(r.get("path") or "")
    return high_risk(r) and path.startswith("/") and ">>" not in path and not r.get("quarantined")


SEV_PL = {"malicious": "groźne", "pua": "niechciane", "suspicious": "podejrzane", "low": "niskie", "info": "info"}


def _n(v, spec: str = "") -> str:
    """A number from report data – formatted, or escaped text when it is not a number. Results of sandboxed
    scans are produced by a process that parsed untrusted files, so nothing in them is trusted as markup."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        try:
            return format(v, spec)
        except (TypeError, ValueError):
            pass
    return html.escape(str(v))


def _f(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _safe_href(url) -> str:
    """Only http(s) links in reports (no javascript:, data:, file:)."""
    u = str(url or "").strip()
    return u if u.lower().startswith(("https://", "http://")) and not any(c in u for c in "\x00\r\n\t") else "#"


# reports are also opened in ordinary browsers (JavaScript on): no script, no external resource, ever
REPORT_CSP = ('<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; '
              'img-src data:; base-uri \'none\'; form-action \'none\'">')


def _monitor_html(mon: dict | None, e, table) -> str:
    """Mega: what the live watch saw during the scan session."""
    if not mon:
        return ""
    st = mon.get("stats") or {}
    out = [f'<h2>Sieć i zachowanie na żywo (w trakcie skanu)</h2><div class="card"><p>{e(str(mon.get("started")))} → '
           f'{e(str(mon.get("ended")))} · sprawdzeń: {_n(mon.get("polls", 0))} (co {_n(mon.get("interval_s", 5), 'g')} s) · '
           f'nowe połączenia z Internetem: {_n(st.get("public_new", 0))} · nowe otwarte porty: {_n(st.get("listening_new", 0))} · '
           f'połączenia przychodzące: {_n(st.get("inbound", 0))} · nowe logowania: {_n(st.get("sessions_new", 0))} · '
           f'wysłano w trakcie: {human_bytes(st.get("uploaded_bytes") or 0)} · alarmy: {_n(st.get("alerts", 0))} · '
           f'przeskanowane nowe pliki/programy: {_n(mon.get("targets_scanned", 0))}</p></div>']
    out.append('<h3>Zdarzenia</h3><div class="card">' + table(
        ["czas", "waga", "co", "szczegóły", "proces", "adres"],
        [[x.get("time"), SEV_PL.get(x.get("severity"), x.get("severity")), x.get("title"), x.get("detail"),
          x.get("process"), x.get("host") or x.get("remote")] for x in mon.get("events") or []]) + "</div>")
    out.append('<h3>Nowe połączenia z Internetem</h3><div class="card">' + table(
        ["czas", "proces", "adres", "port", "host", "podpis"],
        [[x.get("time"), x.get("process"), x.get("remote"), x.get("port"), x.get("host"), x.get("signer")]
         for x in mon.get("new_public") or []]) + "</div>")
    if mon.get("uploads"):
        out.append('<h3>Wysyłka danych w trakcie skanu</h3><div class="card">' + table(
            ["proces", "wysłano", "odebrano", "podpis"],
            [[x.get("process"), human_bytes(x.get("bytes_out") or 0), human_bytes(x.get("bytes_in") or 0),
              x.get("signer")] for x in mon["uploads"]]) + "</div>")
    if mon.get("limitations"):
        out.append('<p class="muted">' + "<br>".join(e(str(x)) for x in mon["limitations"]) + "</p>")
    return "".join(out)


def _network_html(net: dict | None, e) -> str:
    if not net:
        return ""
    def table(head: list[str], rows: list[list]) -> str:
        if not rows:
            return "<p class=\"muted\">brak</p>"
        th = "".join(f"<th>{e(h)}</th>" for h in head)
        body = "".join("<tr>" + "".join(f"<td>{e(str(c if c is not None else ''))}</td>" for c in r) + "</tr>"
                       for r in rows)
        return f"<table><tr>{th}</tr>{body}</table>"
    out = [_monitor_html(net.get("monitor"), e, table)]
    if not net.get("summary"):
        return "".join(out)
    s = net.get("summary") or {}
    out += [f'<h2>Sieć i zdalny dostęp</h2><div class="card"><p>Start systemu: {e(str(net.get("boot_time", "?")))} · '
           f'porty otwarte na wszystkich interfejsach: {_n(s.get("listening_all_interfaces", 0))} · połączenia publiczne: '
           f'{_n(s.get("public_connections", 0))} · narzędzia zdalnego dostępu: {_n(s.get("remote_tools", 0))} · '
           f'trafienia IOC: {_n(s.get("ioc_hits", 0))} · wysłano od startu: '
           f'{human_bytes(s.get("uploaded_bytes_since_boot") or 0)}</p></div>']
    ra = net.get("remote_access") or []
    out.append('<h3>Zdalny dostęp</h3><div class="card">' + table(
        ["co", "rodzaj", "stan", "ryzyko", "szczegóły"],
        [[x.get("name"), x.get("kind"), x.get("status"), x.get("risk"), x.get("detail")] for x in ra]) + "</div>")
    out.append('<h3>Porty nasłuchujące (połączenia przychodzące)</h3><div class="card">' + table(
        ["port", "protokół", "dostępny z", "proces", "usługa", "podpis"],
        [[x.get("port"), x.get("proto"), x.get("exposure"), x.get("process"), x.get("service"), x.get("signer")]
         for x in net.get("listening") or []]) + "</div>")
    out.append('<h3>Połączenia wychodzące</h3><div class="card">' + table(
        ["proces", "adres", "port", "host", "stan", "IOC"],
        [[x.get("process"), x.get("remote"), x.get("port"), x.get("host"), x.get("state"), x.get("ioc")]
         for x in (net.get("connections") or []) if x.get("public")][:300]) + "</div>")
    out.append('<h3>Ruch od startu systemu (kto ile wysłał)</h3><div class="card">' + table(
        ["proces", "wysłano", "odebrano", "podpis"],
        [[x.get("process"), human_bytes(x.get("bytes_out") or 0), human_bytes(x.get("bytes_in") or 0), x.get("signer")]
         for x in net.get("traffic") or []]) + "</div>")
    th = net.get("traffic_history") or {}
    if th.get("available"):
        out.append('<h3>Historia ruchu</h3><div class="card">' + table(
            ["proces", "wysłano", "odebrano", "pierwszy raz", "ostatni raz"],
            [[x.get("process"), human_bytes(x.get("bytes_out") or 0), human_bytes(x.get("bytes_in") or 0),
              x.get("first_seen"), x.get("last_seen")] for x in th.get("items") or []][:300]) + "</div>")
    else:
        out.append(f'<p class="muted">Historia ruchu niedostępna: {e(str(th.get("reason", "")))}</p>')
    sl = net.get("syslog") or {}
    if sl:
        if sl.get("available"):
            c = sl.get("counts") or {}
            w = sl.get("window") or {}
            out.append(f'<h3>Logi systemowe</h3><div class="card"><p>XProtect: {_n(c.get("xprotect_scans", 0))} skanów, '
                       f'{_n(c.get("xprotect_detections", 0))} wykryć · Gatekeeper: {_n(c.get("gatekeeper_blocks", 0))} blokad, '
                       f'{_n(c.get("gatekeeper_overrides", 0))} obejść · SSH: {_n(c.get("ssh_accepted", 0))} udanych, '
                       f'{_n(c.get("ssh_failed", 0))} nieudanych · nieudane hasła: {_n(c.get("auth_failures", 0))} · nowe elementy '
                       f'w tle: {_n(c.get("new_login_items", 0))}</p><p class="muted">Szczegółowe wpisy od '
                       f'{e(str(w.get("persist_since") or w.get("from") or "?"))}</p>'
                       + table(["kiedy", "waga", "co", "szczegóły"],
                               [[x.get("time"), SEV_PL.get(x.get("severity"), x.get("severity")), x.get("title"),
                                 x.get("detail")] for x in sl.get("events") or []]) + "</div>")
        else:
            out.append(f'<p class="muted">Logi systemowe niedostępne: {e(str(sl.get("reason") or ""))}</p>')
    lan = net.get("lan") or {}
    if lan:
        gw, wf = lan.get("gateway") or {}, lan.get("wifi") or {}
        out.append(f'<h3>Sieć lokalna</h3><div class="card"><p>Wi‑Fi: {e(str(wf.get("security_label") or "?"))} · '
                   f'router {e(str(gw.get("ip") or "?"))} ({e(str(gw.get("mac") or "?"))}) · wpisów ARP: '
                   f'{_n(lan.get("arp_entries", 0))}</p>'
                   + (table(["MAC", "adresy", "dlaczego"], [[x.get("mac"), ", ".join(x.get("ips") or []), x.get("reason")]
                                                           for x in lan["arp_suspicious"]]) if lan.get("arp_suspicious") else "")
                   + "</div>")
    if "certificates" in net:
        certs = net.get("certificates") or []
        out.append('<h3>Certyfikaty zaufane ręcznie</h3><div class="card">' + (table(
            ["nazwa", "rodzaj", "ryzyko", "ważny do", "wyjaśnienie"],
            [[x.get("name"), x.get("kind"), SEV_PL.get(x.get("risk"), x.get("risk")), x.get("not_after"),
              x.get("explanation")] for x in certs]) if certs else
            '<p>Brak – nikt nie dodał certyfikatu pozwalającego podsłuchiwać ruch HTTPS.</p>') + "</div>")
    out.append('<h3>Logowania</h3><div class="card">' + table(
        ["użytkownik", "terminal", "skąd", "kiedy", "zdalne"],
        [[x.get("user"), x.get("tty"), x.get("from"), x.get("when"), "tak" if x.get("remote") else ""]
         for x in (net.get("sessions") or []) + (net.get("logins") or [])][:200]) + "</div>")
    return "".join(out)


AI_VERDICT_PL = {"confirmed": ("trafny", "sev-malicious"), "refuted": ("chybiony", "sev-ok"),
                 "unsure": ("niepewne", "")}
AI_MATCH_PL = {"same": "to ta rodzina", "similar": "podobne do rodziny", "different": "szkodliwe, ale inna rodzina",
               "benign": "wygląda na legalne oprogramowanie"}


def ai_family_text(ai: dict) -> str:
    match = ai.get("family_match")
    if match in ("same", "similar") and ai.get("family"):
        return f"{AI_MATCH_PL[match]} {ai['family']}"
    if match in AI_MATCH_PL:
        return AI_MATCH_PL[match]
    return str(ai.get("family") or {"benign": "legalne oprogramowanie", "other": "inna szkodliwa rodzina"}
               .get(ai.get("choice"), ai.get("category") or ""))           # older reports: family classifier


def _ai_html(ai: dict | None, e) -> str:
    """"Ocena zarzutów przez AI": every accusation → trafny / chybiony / niepewne, confidence, reason, ±points."""
    if not ai:
        return ""
    cap = ai.get("cap") or 15
    head = (f"<p><b>Ocena zarzutów przez AI:</b> {e(ai_family_text(ai))} (pewność {_n(ai.get('confidence', 0), '.2f')}"
            f"{'' if ai.get('agree', True) else ', odpowiedzi niezgodne'}) – {e(ai.get('summary_pl', ''))}")
    pts = ai.get("points")
    if pts is not None:
        raw = ai.get("points_raw", pts)
        head += f" <b>{_n(pts, '+d')} pkt</b>" + (f" <span class='muted'>(z {_n(raw, '+d')}, limit ±{_n(cap)})</span>" if raw != pts else "")
    head += f" <span class='muted'>(AI nie decyduje: zmienia wynik najwyżej o {_n(cap)} pkt)</span></p>"
    accs = ai.get("accusations") or []
    if not accs:
        return head
    rows = []
    for a in accs:
        label, cls = AI_VERDICT_PL.get(a.get("verdict"), (str(a.get("verdict")), ""))
        notes = ("" if a.get("agree", True) else " · niezgodne") + ("" if a.get("grounded", True) else " · cytat spoza pliku")
        quote = f"<br><code>{e(str(a.get('quote', ''))[:160])}</code>" if a.get("quote") else ""
        rows.append(f"<tr><td><code>{e(str(a.get('name')))}</code></td><td><span class='sev {cls}'>{e(label)}</span></td>"
                    f"<td>{_n(a.get('confidence') or 0, '.2f')}<span class='muted'>{e(notes)}</span></td>"
                    f"<td>{e(str(a.get('reason_pl', '')))}{quote}</td><td>{_n(a.get('points') or 0, '+d')}</td></tr>")
    return (head + "<table><tr><th>zarzut</th><th>ocena AI</th><th>pewność</th><th>uzasadnienie</th><th>punkty</th></tr>"
            + "".join(rows) + "</table>")


def _detonation_html(det: dict | None, e) -> str:
    """What a script did when it was run for a few seconds in the sealed detonation sandbox."""
    if not det or not det.get("ran"):
        return ""
    beh = "".join(f"<li><b>{e(str(b.get('title')))}</b> – {e(str(b.get('detail', '')))}"
                  + (f"<br><code>{e(' | '.join(str(x) for x in (b.get('evidence') or [])[:3])[:400])}</code>"
                     if b.get("evidence") else "") + "</li>" for b in det.get("behaviors") or [])
    net = ", ".join(e(str(n.get("url") or n.get("target"))) + (f" ({e(str(n['ioc']))})" if n.get("ioc") else "")
                    for n in (det.get("network") or [])[:15])
    stages = "".join(f"<pre><code>{e(str(st.get('source_preview', ''))[:600])}</code></pre>"
                     for st in (det.get("stages") or [])[:3])
    return (f'<div class="card"><p><b>Zachowanie w zamkniętym sandboksie</b> ({e(str(det.get("kind")))}, '
            f'{_n(det.get("seconds", 0))} s{", przerwano po limicie czasu" if det.get("timed_out") else ""}): '
            f'{e(str(det.get("verdict")))}</p>' + (f"<ul>{beh}</ul>" if beh else "<p>Nic podejrzanego.</p>")
            + (f"<p>Adresy: {net}</p>" if net else "")
            + (f"<p>Pliki-przynęty: <code>{e(', '.join(str(x) for x in (det.get('files_read') or [])[:10]))}</code></p>"
               if det.get("files_read") else "")
            + (f"<p>Odkodowane etapy:</p>{stages}" if stages else "") + "</div>")


def _cloud_html(cf: dict | None) -> str:
    """Mega: risky cloud-only files that were downloaded for the scan (cerber/cloudfetch.py)."""
    if not cf:
        return ""
    e = html.escape
    kinds = ", ".join(f"{e(str(k))}: {_n(n)}" for k, n in (cf.get("kinds") or {}).items())
    rows = [("Ryzykowne pliki tylko w chmurze", f"{_n(cf.get('candidates', 0), ',')}"),
            ("Pobrane i przeskanowane", f"{_n(cf.get('fetched', 0), ',')} ({human_bytes(cf.get('bytes') or 0)})"
             + (f" – {kinds}" if kinds else "")),
            ("Oddane z powrotem do chmury", f"{_n(cf.get('evicted', 0), ',')}")]
    if cf.get("kept"):
        rows.append(("Zostawione na dysku (coś znaleziono)", f"{_n(cf['kept'], ',')}"))
    if cf.get("local"):
        rows.append(("Pliki z folderów, których lista była tylko w chmurze", f"{_n(cf['local'], ',')}"))
    if cf.get("dirs_listed") or cf.get("dirs_left"):
        rows.append(("Foldery z chmury odczytane / nieodczytane", f"{_n(cf.get('dirs_listed', 0), ',')} / {_n(cf.get('dirs_left', 0), ',')}"))
    left = (cf.get("over_limit") or 0) + (cf.get("too_big") or 0) + (cf.get("failed") or 0)
    if left:
        rows.append(("Niepobrane (limit 1500 plików / 3 GB / 30 min, za duże lub błąd)", f"{left:,}"))
    body = "".join(f"<tr><td>{a}</td><td>{b}</td></tr>" for a, b in rows)
    note = ("Zdjęcia, filmy, muzyka i zwykłe dokumenty zostają w chmurze – same niczego nie uruchomią."
            + (" Chmura przestała odpowiadać, więc część plików nie została pobrana." if cf.get("stalled") else ""))
    return (f'<h2>Pliki z chmury (iCloud itp.)</h2><div class="card"><table>{body}</table>'
            f'<p class="muted">{note}</p></div>')


NET_KIND_PL = {"connection": "połączenie", "listen": "nowy port", "inbound": "przychodzące", "session": "logowanie",
               "process": "proces", "traffic": "wysyłanie", "autostart": "autostart", "file": "plik",
               "gateway": "router", "log": "dziennik", "permission": "uprawnienia"}


def write_netguard_html(data: dict, path: str) -> str:
    """Daily report of the background network & remote-access guard (reports/siec-YYYYMMDD.html)."""
    e = html.escape
    st = data.get("status") or {}
    evs = data.get("events") or []
    alarms = [x for x in evs if x.get("severity") in ("suspicious", "pua", "malicious")]
    low = [x for x in evs if x.get("severity") == "low"]

    def rows(items: list[dict]) -> str:
        if not items:
            return '<p class="muted">Brak.</p>'
        out = ['<table><tr><th>czas</th><th>waga</th><th>rodzaj</th><th>co</th><th>szczegóły</th><th>program</th>'
               '<th>adres</th></tr>']
        for x in items:
            sev = str(x.get("severity") or "info")
            prog = x.get("process") or ""
            if x.get("exe"):
                prog = f'{e(str(prog))}<br><code>{e(str(x["exe"]))}</code>'
            else:
                prog = e(str(prog))
            out.append(f'<tr><td>{e(str(x.get("time") or ""))}</td><td><span class="sev sev-{e(sev)}">'
                       f'{e(SEV_PL.get(sev, sev))}</span></td><td>{e(NET_KIND_PL.get(x.get("kind"), x.get("kind") or ""))}'
                       f'</td><td>{e(str(x.get("title") or ""))}</td><td>{e(str(x.get("detail") or ""))}</td>'
                       f'<td>{prog}</td><td><code>{e(str(x.get("host") or x.get("remote") or ""))}</code></td></tr>')
        return "".join(out) + "</table>"

    tiles = "".join(f'<div class="tile"><span class="muted">{e(lbl)}</span><b>{_n(val)}</b></div>' for lbl, val in (
        ("alarmy", len(alarms)), ("niskie", len(low)), ("nowe połączenia z Internetem", st.get("public_new", 0)),
        ("połączenia przychodzące", st.get("inbound", 0)), ("nowe otwarte porty", st.get("listening_new", 0)),
        ("logowania", st.get("sessions_new", 0)), ("wysłano", human_bytes(st.get("uploaded_bytes") or 0))))
    lim = "".join(f"<li>{e(str(x))}</li>" for x in st.get("limitations") or [])
    doc = f"""<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{REPORT_CSP}<title>Cerber – sieć i zdalny dostęp</title>
<style>{CSS}</style></head><body><main><h1>Cerber – sieć i zdalny dostęp</h1>
<p class="muted">{e(str(data.get("date") or ""))} · nadzór od {e(str(data.get("started") or ""))} · aktualizacja
{e(str(data.get("updated") or ""))} · sprawdzanie co {_n(st.get("interval_s", 10), 'g')} s · dziennik systemowy przejrzany do
{e(str(st.get("log_checked") or "—"))} · uprawnienia prywatności: {"śledzone" if st.get("permissions") else "niedostępne (brak Pełnego dostępu do dysku)"}</p>
<div class="grid">{tiles}</div>
<h2>Alarmy</h2><div class="card">{rows(alarms)}</div>
<h2>Do sprawdzenia</h2><div class="card">{rows(low)}</div>
<details><summary>Wszystkie zdarzenia ({len(evs)})</summary><div class="card">{rows(evs)}</div></details>
<h2>Co jest sprawdzane</h2><div class="card"><ul>
<li>połączenia z Internetem: adresy z list zagrożeń (ThreatFox, URLhaus), skrypty i programy bez podpisu na nietypowych
portach, regularne „meldowanie się” do serwera (beaconing), duże wysyłki danych</li>
<li>zdalny dostęp: nowe otwarte porty (SSH, VNC, pulpit zdalny), połączenia przychodzące, zdalne logowania, programy do
zdalnego sterowania (TeamViewer, AnyDesk …), tunele (ngrok, cloudflared, ssh -R)</li>
<li>nowe uprawnienia: nagrywanie ekranu, Dostępność (sterowanie komputerem), odczyt klawiatury, mikrofon, kamera</li>
<li>dziennik systemowy co 5 min: logowania SSH i udostępnianie ekranu, zgadywanie haseł, uprawnienia administratora,
blokady XProtect</li>
<li>zmiany plików startowych powłoki, zmiana routera (ARP spoofing), nowe programy w /tmp i /Users/Shared</li></ul>
<p class="muted">Nic nie jest wysyłane do sieci. Zawartości szyfrowanego ruchu (HTTPS) nie da się podejrzeć; połączenia
krótsze niż kilka sekund mogą zostać niezauważone.</p>{f"<ul>{lim}</ul>" if lim else ""}</div>
</main></body></html>"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path + ".tmp", "w") as fh:
        fh.write(doc)
    os.replace(path + ".tmp", path)
    return path


def _cases_html(cases: list | None, e) -> str:
    """Programs judged as a whole: process + network + autostart + files (cerber/correlate.py)."""
    if not cases:
        return ""
    sev = {"malicious": "MALICIOUS", "suspicious": "SUSPICIOUS", "low": "INFO"}
    out = ['<h2>Powiązane zagrożenia (proces + sieć + autostart + pliki)</h2>']
    for c in cases:
        dims = " · ".join(f"{k} {v}" for k, v in (c.get("dims") or {}).items() if v)
        rows = "".join(f"<li>{e(str(r))}</li>" for r in c.get("reasons") or [])
        files = "".join(f"<li><code>{e(str(f.get('path')))}</code> – {e(str(f.get('verdict')))}</li>"
                        for f in (c.get("files") or [])[:15])
        out.append(f'<div class="card"><span class="v {sev.get(c.get("severity"), "INFO")}">{e(str(c.get("severity")))}'
                   f'</span> <b>{e(str(c.get("name")))}</b> · wynik {_n(c.get("score"))} <p class="muted"><code>'
                   f'{e(str(c.get("exe") or c.get("key")))}</code><br>pochodzenie: {e(str(c.get("origin") or "—"))}'
                   f'<br>wymiary: {e(dims)}</p><ul>{rows}</ul>'
                   + (f"<p>Połączenia: {e(', '.join(str(x) for x in c.get('connections') or []))}</p>" if c.get("connections") else "")
                   + (f"<p>Porty: {e(', '.join(str(x) for x in c.get('listening') or []))}</p>" if c.get("listening") else "")
                   + (f"<p>Pliki pakietu:</p><ul>{files}</ul>" if files else "") + "</div>")
    return "".join(out)


def write_html(report: dict, path: str, env: dict | None = None) -> str:
    e = html.escape
    c = report["counts"]
    tiles = "".join(f'<div class="tile"><span class="v {k}">{VERDICT_PL[k]}</span><b>{_n(c.get(k, 0), ',')}</b></div>'
                    for k in ("MALICIOUS", "PUA", "SUSPICIOUS", "INFO", "CLEAN"))
    rows = []
    for i, r in enumerate(report["results"]):
        dets = "".join(
            f"<tr><td><code>{e(str(d['name']))}</code></td><td>{e(str(d['engine']))}</td><td>{e(str(d['confidence']))}</td>"
            f"<td>+{_n(d['score'])}</td><td>{e(str(d['object']).rsplit('>>', 1)[-1] if '>>' in str(d['object']) else 'plik')}</td>"
            f"<td>{e(str(d.get('description', ''))[:200])}</td></tr>" for d in r["detections"][:40])
        ai_html = _ai_html(r.get("ai"), e)
        qhtml = (f'<a class="qbtn" data-i="{i}" href="cerber-report://quarantine/{i}">Do kwarantanny</a>'
                 if quarantine_offer(r) else
                 '<span class="qdone">✓ w kwarantannie</span>' if r.get("quarantined") else "")
        rows.append(
            f'<div class="card"><span class="v {e(str(r["verdict"]))}">{e(VERDICT_PL.get(r["verdict"], str(r["verdict"])))}</span> '
            f'<code>{e(str(r["path"]))}</code>{qhtml}<p class="muted">wynik {_n(r.get("score", 0))} · {e(str(r.get("ftype")))} · '
            f'{human_bytes(r.get("size", 0))} · sha256 <code>{e(str(r.get("sha256", "")))}</code></p>{ai_html}'
            f'{_detonation_html(r.get("detonation"), e)}'
            f'<table><tr><th>wykrycie</th><th>silnik</th><th>pewność</th><th>punkty</th><th>obiekt</th><th>opis</th></tr>'
            f'{dets}</table></div>')
    env_html = ""
    if env:
        items = "".join(f"<tr><td>{e(str(f.get('category')))}</td><td>{e(str(f.get('title')))}</td>"
                        f"<td><code>{e(str(f.get('location', ''))[:200])}</code></td><td>+{_n(f.get('score', 0))}</td></tr>"
                        for f in sorted(env.get("findings", []), key=lambda f: -_f(f.get("score", 0)))[:200])
        post = "".join(f"<tr><td>{e(str(k))}</td><td>{e(str(v))}</td></tr>" for k, v in env.get("posture", {}).items())
        env_html = (f'<h2>Środowisko</h2><div class="card"><table>{post}</table></div>'
                    f'<div class="card"><table><tr><th>kategoria</th><th>znalezisko</th><th>lokalizacja</th>'
                    f'<th>punkty</th></tr>{items}</table></div>')
    net_html = _cases_html((env or {}).get("cases"), e) + _network_html(report.get("network"), e)
    sb = report.get("sandbox") or {}
    if sb:
        iso = "".join(f"<li>{e(str(x))}</li>" for x in sb.get("isolation", []))
        hit = "".join(f"<li>{e(str(x))}</li>" for x in sb.get("limits_hit", []))
        env_html += (f'<h2>Sandbox</h2><div class="card"><p>Rozpakowano {_n(sb.get("extracted_files", 0), ',')} plików '
                     f'({human_bytes(sb.get("extracted_bytes", 0))}).</p><ul>{iso}</ul>'
                     + (f'<p><b>Osiągnięte limity:</b></p><ul>{hit}</ul>' if hit else "") + "</div>")
    repo = report.get("repo") or {}
    if repo:
        skipped = "".join(f"<tr><td><code>{e(str(x.get('path')))}</code></td><td>{human_bytes(x.get('size') or 0)}</td>"
                          f"<td>{e(str(x.get('reason')))}</td></tr>"
                          for x in (repo.get("partial") or []) + (repo.get("skipped") or [])[:300])
        env_html += (f'<h2>Repozytorium</h2><div class="card"><p><a href="{e(_safe_href(repo.get("url", "")))}">'
                     f'{e(str(repo.get("owner", "")))}/{e(str(repo.get("name", "")))}</a> · {e(str(repo.get("ref", "")))} · '
                     f'{e(str(repo.get("description") or ""))}</p>'
                     + (f'<table><tr><th>plik</th><th>rozmiar</th><th>jak sprawdzono</th></tr>{skipped}</table>'
                        if skipped else "") + "</div>")
    env_html += net_html
    dbs = e(json.dumps(report.get("databases", {}), ensure_ascii=False, indent=1, default=str))
    cloud_note = (f" · pominięto {_n(report['cloud_only'], ',')} elementów tylko w chmurze (iCloud itp.) – nie ma ich na dysku"
                  if report.get("cloud_only") else "")
    if report.get("cache_hits"):
        cloud_note += (f" · {_n(report['cache_hits'], ',')} plików niezmienionych od poprzedniego skanu pominięto"
                       " (pamięć skanów)")
    env_html += _cloud_html(report.get("cloud_fetch"))
    doc = f"""<!doctype html><html lang="pl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{REPORT_CSP}<title>Raport Cerber</title><style>{CSS}</style></head>
<body><main><h1>Cerber – raport skanowania</h1>
<p class="muted">{e(str(report['started']))} → {e(str(report['finished']))} · {_n(report['seconds'])} s · {_n(report['files'], ',')} plików ·
{human_bytes(report['bytes'])} · {_n(report['objects'], ',')} obiektów · {_n(report.get('patterns_total', 0), ',')} wzorców w bazach{cloud_note}</p>
<div class="grid">{tiles}</div>{env_html}<h2>Wykrycia</h2>{''.join(rows) or '<p>Nie znaleziono zagrożeń.</p>'}
<details><summary>Bazy i opcje</summary><pre><code>{dbs}</code></pre></details></main></body></html>"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(doc)
    return path
