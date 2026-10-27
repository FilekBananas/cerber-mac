"""HTML / HTA / SVG: script blocks, data: URIs, event-handler/javascript: code, entity decoding."""
from __future__ import annotations

import html as _html
import re
from dataclasses import dataclass

from .primitives import Budget, Layer, b64decode_loose, classify, excerpt, url_unquote

_ATTR = re.compile(r"""([\w:-]{1,40})\s*=\s*(?:"([^"]{0,400})"|'([^']{0,400})'|([^\s>]{1,400}))""")
_DATA_URI = re.compile(r"data:([\w.+-]{1,80}/[\w.+-]{1,80})?((?:;[\w.+-]{1,40}=[\w.+-]{1,80})*)(;base64)?,"
                       r"([A-Za-z0-9+/=%_\-]{64,})")
_SKIP_TYPES = ("json", "template", "html", "x-tmpl", "handlebars", "mustache", "importmap", "text/plain",
               "x-shader", "shader", "markdown", "text/x-", "speculationrules")


@dataclass
class ScriptBlock:
    start: int
    lang: str          # javascript | vbs
    code: str
    attrs: dict


def _attrs(tag: str) -> dict[str, str]:
    out = {}
    for m in _ATTR.finditer(tag):
        out[m.group(1).lower()] = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
        if len(out) > 40:
            break
    return out


def script_blocks(text: str, limit: int = 400, max_total: int = 32 << 20) -> list[ScriptBlock]:
    """Linear scan for <script ...>...</script> (tolerates a missing closing tag)."""
    out: list[ScriptBlock] = []
    low = text.lower()
    pos = 0
    total = 0
    while len(out) < limit:
        i = low.find("<script", pos)
        if i < 0:
            break
        j = low.find(">", i)
        if j < 0:
            break
        tag = text[i:j + 1]
        k = low.find("</script", j)
        end = k if k >= 0 else len(text)
        code = text[j + 1:end]
        pos = end + 1 if k >= 0 else len(text)
        attrs = _attrs(tag[7:-1])
        typ = (attrs.get("type") or "").lower()
        lang_attr = (attrs.get("language") or "").lower()
        if any(s in typ for s in _SKIP_TYPES) and "javascript" not in typ and "vbscript" not in typ:
            continue
        lang = "vbs" if ("vbscript" in typ or "vbscript" in lang_attr or "vbs" == lang_attr) else "javascript"
        if code.strip():
            total += len(code)
            if total > max_total:
                break
            out.append(ScriptBlock(i, lang, code, attrs))
    return out


def data_uris(text: str, budget: Budget, limit: int = 64) -> list[tuple[str, bytes, str, str]]:
    """Decode data: URIs -> list of (mime, payload, ftype, excerpt). Images are skipped unless SVG."""
    out = []
    if "data:" not in text:
        return out
    for m in _DATA_URI.finditer(text):
        if len(out) >= limit or budget.expired():
            break
        mime = (m.group(1) or "text/plain").lower()
        if mime.startswith(("image/", "font/", "audio/", "video/")) and "svg" not in mime:
            continue
        if mime in ("application/font-woff", "application/x-font-woff", "application/x-font-ttf",
                    "application/vnd.ms-fontobject", "application/font-sfnt"):
            continue
        body = m.group(4)
        if m.group(3):
            data = b64decode_loose(url_unquote(body))
        else:
            data = url_unquote(body).encode("utf-8", "replace")
        if not data or not budget.charge(len(data)):
            continue
        kind, ftype, payload, _ = classify(data)
        out.append((mime, payload if kind != "junk" else data, ftype, excerpt(m.group(0)[:100])))
    return out


def unescape_entities(text: str, max_len: int = 16 << 20) -> str:
    if "&#" not in text and "&" not in text:
        return text
    if len(text) > max_len:
        return text
    try:
        return _html.unescape(text)
    except Exception:
        return text


_HANDLER = re.compile(r"""(?i)\son(?:load|click|error|mouseover|focus|submit|change|input|copy|paste|keydown|keyup|pageshow|beforeunload)\s*=\s*(?:"([^"]{16,4000})"|'([^']{16,4000})')""")
_JS_HREF = re.compile(r"""(?i)\b(?:href|src|action)\s*=\s*["']\s*javascript:([^"']{16,4000})""")


def inline_handlers(text: str, limit: int = 200) -> str:
    """Concatenate event-handler attribute code and javascript: URLs into one JS text."""
    parts = []
    for rx in (_HANDLER, _JS_HREF):
        for m in rx.finditer(text):
            parts.append(unescape_entities(m.group(1) or (m.group(2) if m.lastindex and m.lastindex > 1 else "") or ""))
            if len(parts) >= limit:
                break
    return ";\n".join(p for p in parts if p)


def layers_from_html(text: str, budget: Budget) -> list[Layer]:
    layers: list[Layer] = []
    for sb in script_blocks(text):
        if budget.expired():
            break
        if len(sb.code.strip()) < 24:
            continue
        ext = sb.lang
        layers.append(Layer(f"html-script-{ext}", sb.code.encode("utf-8", "replace"), sb.lang, "text", sb.lang,
                            excerpt(sb.code[:80]), {"attrs": {k: v for k, v in list(sb.attrs.items())[:8]}}))
    handlers = inline_handlers(text)
    if len(handlers) >= 64:
        layers.append(Layer("html-handlers", handlers.encode("utf-8", "replace"), "javascript", "text", "javascript",
                            excerpt(handlers[:80])))
    for mime, payload, ftype, src in data_uris(text, budget):
        if ftype in ("text", "json", "xml") and not any(k in mime for k in ("html", "javascript", "svg", "vbscript", "hta")):
            continue
        lang = "html" if ("html" in mime or "svg" in mime) else ("javascript" if "javascript" in mime else None)
        layers.append(Layer("html-data-uri", payload, lang, "text" if lang else "binary", ftype, src, {"mime": mime}))
    return layers
