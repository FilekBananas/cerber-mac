"""Web / scripting: JavaScript & JScript/WSH, HTML/HTA, PHP/Perl/Ruby webshells,
and .url/.desktop shortcuts."""
from __future__ import annotations

import re

from ..core import Analyzer, Confidence, Detection, ScanContext, ScanObject
from . import register
from .scripts_common import C, R, make_script_analyzer

# --------------------------------------------------------------------------- JavaScript / JScript
JS_RULES = [
    R("DynExec", r"\beval\s*\(|new\s+Function\s*\(|\bsetTimeout\s*\(\s*['\"]|\bsetInterval\s*\(\s*['\"]|"
      r"\bexecScript\s*\(", 0, "Dynamic code execution", "exec",
      need="eval|function|settimeout|setinterval|execscript"),
    # the sinks are case-sensitive: "atob(e)),function(t){" is a minified callback, not Function(...)
    R("DecodeExec", r"(?-i:\beval|\bFunction)\s*\(\s*(?:function\s*\(\s*\)\s*\{\s*return\s+)?atob\s*\(|"
      r"\batob\s*\([^\n)]{0,60}\)\s*\)?\s*[;,)]?\s*(?-i:\beval|\bFunction)\s*\(", 15,
      "Decodes base64 and executes it", "decode,exec", need="atob"),
    R("WshShell", r"ActiveXObject\s*\(\s*['\"]WScript\.Shell['\"]|new\s+ActiveXObject\s*\(\s*['\"]Shell\.Application|"
      r"WScript\.Shell", 15, "Executes commands via WScript.Shell (JScript/WSH)", "exec",
      need="wscript.shell|shell.application"),
    R("HttpDownload", r"ActiveXObject\s*\(\s*['\"](?:MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest|ADODB\.Stream)|"
      r"XMLHttpRequest\s*\(|\bfetch\s*\(\s*['\"]https?:", 0, "Downloads a remote resource", "download",
      need="msxml2|winhttp|adodb.stream|xmlhttprequest|fetch"),
    R("SaveToDisk", r"\.SaveToFile\s*\(|\.WriteLine\s*\([^\n]{0,80}\.exe", 0,
      "Writes a payload to disk", "download", need="savetofile|writeline"),
    R("NodeChildProcess", r"require\s*\(\s*['\"]child_process['\"]\s*\)|\bchild_process\b|"
      r"\.exec(?:Sync)?\s*\(|\.spawn(?:Sync)?\s*\(", 0, "Spawns a child process (Node)", "exec",
      need="child_process|.exec|.spawn"),
    R("NodeRemoteRequire", r"require\s*\(\s*['\"]https?://", 30, "Requires a module from a URL", "download,exec",
      need="require"),
    R("ClipboardHijack", r"navigator\s*\.\s*clipboard\s*\.\s*writeText\s*\(", 0,
      "Writes to the clipboard (fake-captcha ClickFix technique)", "clipboard",
      need="clipboard"),
    R("ClickFixLure", r"(?i)(?:i['\s]*m not a robot|verify (?:you are|you're) (?:a )?human|"
      r"press\s+win\s*\+\s*r|windows\s*\+\s*r|\bhold\s+the\s+windows\s+key)", 0,
      "Fake-CAPTCHA / ClickFix social-engineering text", "lure",
      need="not a robot|human|win + r|win+r|windows key"),
    R("Exfil", r"new\s+Image\s*\(\s*\)[^\n]{0,40}\.src\s*=[^\n]{0,40}(?:document\.cookie|btoa)|"
      r"\.send\s*\([^\n]{0,40}(?:document\.cookie|btoa)", 0, "Exfiltrates data to a remote endpoint",
      "exfil", need="new image|.send"),
]
JS_COMBOS = [
    C("ClickFixClipboard", "clipboard,lure", 45,
      "Fake-CAPTCHA page that plants a command in the clipboard", window=4000),
]
make_script_analyzer("JsAnalyzer", "js", {"javascript"}, "javascript", JS_RULES,
                     combos=JS_COMBOS, head_exclude=b"<?php")

# --------------------------------------------------------------------------- HTML / HTA
HTML_RULES = JS_RULES + [
    R("HtaApplication", r"<hta:application\b", 15, "HTML Application (HTA)", "exec", need="hta:application"),
    R("HtmlSmuggling",
      r"<a[^>]{0,200}\bdownload\b[^>]{0,200}href\s*=\s*['\"](?:data:|blob:)|"
      r"msSaveOrOpenBlob\s*\([^\n]{0,80}atob\s*\(|"
      r"(?:createObjectURL|new\s+Blob)\s*\([^\n]{0,120}atob\s*\(", 20,
      "HTML smuggling: reconstructs a file in the browser and offers it for download", "smuggling",
      need="download|mssaveoropenblob|createobjecturl|blob"),
    R("DownloadExecutableName",
      r"\.download\s*=\s*['\"][^'\"\n]{1,80}\.(?:exe|scr|msi|js|jse|vbs|vbe|wsf|hta|bat|cmd|ps1|lnk|iso|img|vhdx?|"
      r"zip|rar|7z|dmg|pkg|command|jar)['\"]|"
      r"<a\b[^>]{0,200}\bdownload\s*=\s*['\"][^'\"\n]{1,80}\.(?:exe|scr|msi|js|jse|vbs|vbe|wsf|hta|bat|cmd|ps1|"
      r"lnk|iso|img|vhdx?|zip|rar|7z|dmg|pkg|command|jar)['\"]", 0,
      "Offers an executable/archive file name for download", "download", need="download"),
    # building blocks of smuggling when decode and Blob are further apart than HtmlSmuggling's
    # 120-character window (the payload literal usually sits in between)
    R("BlobUrl", r"\bnew\s+Blob\s*\(|URL\s*\.\s*createObjectURL\s*\(|msSaveOrOpenBlob\s*\(", 0,
      "Builds a Blob / object URL in the browser", "blob", need="blob"),
    R("Base64Decode", r"\batob\s*\(|Uint8Array\s*\.\s*from\s*\(\s*atob|base64ToArrayBuffer", 0,
      "Decodes base64 in the browser", "b64", need="atob|base64toarraybuffer"),
    R("HiddenIframe",
      r"<iframe[^>]{0,300}(?:width\s*=\s*['\"]?0|height\s*=\s*['\"]?0|display\s*:\s*none|visibility\s*:\s*hidden)[^>]{0,300}src",
      20, "Hidden iframe", "hidden", need="<iframe"),
    R("MetaRefreshScript", r"<meta[^>]{0,120}http-equiv\s*=\s*['\"]refresh['\"][^>]{0,200}(?:data:|javascript:)", 20,
      "meta-refresh redirect to a data:/javascript: URL", "exec", need="http-equiv"),
]
HTML_COMBOS = JS_COMBOS + [
    C("SmugglingDownload", "smuggling", 30, "HTML smuggling that reconstructs an executable client-side",
      "download,decode"),
    # base64 -> Blob -> <a download="x.zip|exe|iso..."> : the whole chain, not any single step
    C("SmugglingChain", "blob,b64,download", 25,
      "Decodes base64 into a Blob and offers it as an executable/archive download", window=2000),
]
make_script_analyzer("HtmlAnalyzer", "html", {"html", "hta"}, "html", HTML_RULES, combos=HTML_COMBOS)

# --------------------------------------------------------------------------- PHP webshell
PHP_RULES = [
    R("EvalSuperglobal",
      r"(?:eval|assert|create_function)\s*\(\s*(?:stripslashes\s*\(\s*)?\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b", 50,
      "Executes attacker-controlled request data (webshell)", "exec", need="$_post|$_get|$_request|$_cookie|$_server"),
    R("SystemSuperglobal",
      r"(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*(?:stripslashes\s*\(\s*)?"
      r"\$_(?:POST|GET|REQUEST|COOKIE)\b", 50, "Runs shell commands from request data (webshell)",
      "exec", need="$_post|$_get|$_request|$_cookie"),
    R("BackateExec", r"`\s*\$_(?:POST|GET|REQUEST)", 40, "Backtick execution of request data", "exec",
      need="$_post|$_get|$_request"),
    R("PregReplaceEval", r"preg_replace\s*\(\s*['\"][^'\"]{0,40}/[a-z]*e[a-z]*['\"]", 40,
      "preg_replace /e modifier (code execution)", "exec", need="preg_replace"),
    R("DynamicCall", r"\$_(?:GET|POST|REQUEST)\s*\[[^\]]{0,20}\]\s*\(|\$\{?\$", 25,
      "Variable function / variable-variable call from request data", "exec", need="$_get|$_post|$_request|${$"),
    R("Uploader", r"move_uploaded_file\s*\(|\$_FILES\b", 15, "File upload handler", "upload", need="move_uploaded_file|$_files"),
    R("DecodeExec", r"(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|"
      r"pack)\s*\(", 40, "Decodes a blob and executes it (packed webshell)", "decode,exec",
      need="eval|assert"),
    R("Download", r"(?:file_get_contents|curl_exec|fsockopen|fopen)\s*\(\s*['\"]?https?://", 5,
      "Downloads a remote resource", "download", need="file_get_contents|curl_exec|fsockopen|fopen"),
    R("ObfIndirect", r"\$[a-z_]\w*\s*\(\s*\$[a-z_]\w*\s*\)\s*;.{0,40}(?:base64|gzinflate)", 20,
      "Indirect call through decoded variable", "decode,exec", need="base64|gzinflate"),
]
make_script_analyzer("PhpAnalyzer", "php", {"php"}, "php", PHP_RULES, head_marker=b"<?php")

# --------------------------------------------------------------------------- Perl / Ruby
PERL_RUBY_RULES = [
    R("ReverseShell", r"IO\.popen\s*\(\s*['\"]\s*[|]|fsockopen\s*\([^\n]{0,120}(?:exec|/bin/sh|system)|"
      r"\bfork\b[^\n]{0,60}\bexec\b[^\n]{0,60}/bin/|"
      r"TCPSocket[^\n]{0,160}(?:exec\s*\(|system\s*\(|/bin/sh)", 25,
      "Socket/pipe wired to a shell (reverse shell)", "exec,exfil",
      need="io.popen|fsockopen|fork|tcpsocket"),
    # piping to sendmail/less/sort is everyday Perl; a pipe into an interpreter or out of a
    # downloader is what droppers do
    R("OpenPipe", r"open\s*\(\s*[^,]{0,40},\s*['\"]\s*[|]|open\s*\(\s*['\"]\s*[|]", 0,
      "open() to a command pipe", "exec", need="open"),
    R("OpenPipeShell",
      r"open\s*\(\s*(?:[^,]{0,40},\s*)?['\"]\s*\|\s*(?:/usr)?(?:/bin/)?(?:ba|z|k)?sh\b|"
      r"open\s*\(\s*(?:[^,]{0,40},\s*)?['\"]\s*\|\s*(?:/usr/bin/)?(?:python[0-9.]*|perl|ruby|osascript)\b|"
      r"open\s*\(\s*(?:[^,]{0,40},\s*)?['\"][^'\"\n]{0,40}\b(?:curl|wget)\b[^'\"\n]{0,200}\|\s*['\"]", 15,
      "open() pipes into a shell/interpreter or out of a downloader", "exec", need="open"),
    # backticks with variables (`cd $dir && pwd`) are everyday Perl/Ruby: capability tag only
    R("Backtick", r"`[^`\n]{0,120}(?:\$\{?\w+|https?://)[^`\n]{0,60}`|%x[\(\{\[]", 0,
      "Backtick / %x command execution", "exec", need="`|%x"),
    R("BacktickDownload", r"`[^`\n]{0,80}\b(?:curl|wget)\b[^`\n]{0,160}https?://[^`\n]{0,120}`", 10,
      "Backtick command downloads remote content", "download,exec", need="curl|wget"),
    R("SystemExec", r"\bsystem\s*\(|\bexec\s*\(|Kernel\.(?:system|exec)|\beval\s*\(", 0,
      "Command / code execution", "exec", need="system|exec|eval"),
    R("Download", r"LWP::|Net::HTTP|Net::FTP|open-uri|URI\.open|Net::Telnet", 0, "Network client",
      "download", need="lwp|net::http|net::ftp|open-uri|uri.open|net::telnet"),
    R("DecodeExec", r"(?:eval|system)\s*\([^\n]{0,60}(?:decode_base64|Base64\.decode64|pack\s*\(\s*['\"]H|"
      r"Zlib::Inflate)", 30, "Decodes and executes a payload", "decode,exec", need="eval|system"),
]
PERL_ONLY_RULES = PERL_RUBY_RULES + [
    # classic Perl reverse shell: std handles duplicated onto a socket, then a shell is exec'd
    R("SocketShell",
      r"open\s*\(\s*STD(?:IN|OUT|ERR)\s*,\s*['\"][<>+]{0,2}&\s*\w+['\"]\s*\)[\s\S]{0,400}?"
      r"(?:exec|system)\s*\(?\s*['\"][^'\"\n]{0,40}/bin/(?:ba|z|k)?sh\b", 50,
      "Standard handles redirected to a socket and a shell executed (reverse shell)", "exec,exfil",
      need="stdin"),
    # dropper: LWP download to a file, then chmod +x and run it
    R("DownloadChmodRun",
      r"(?:getstore|mirror)\s*\(\s*['\"]https?://[^'\"\n]{1,300}['\"]\s*,\s*['\"]([^'\"\n]{1,200})['\"]\s*\)"
      r"[\s\S]{0,400}?(?:system|exec|`)[^\n]{0,60}chmod\s+(?:\+x|[0-7]*[1357][0-7]{0,2})\b[^\n]{0,200}\1", 45,
      "Downloads a file, makes it executable and runs it", "download,exec", need="getstore|mirror"),
]
make_script_analyzer("PerlAnalyzer", "perl", {"perl"}, "perl", PERL_ONLY_RULES, combos=[])
make_script_analyzer("RubyAnalyzer", "ruby", {"ruby"}, "ruby", PERL_RUBY_RULES, combos=[])


# --------------------------------------------------------------------------- .url / .desktop shortcuts
_URL_EXEC = re.compile(r"(?im)^\s*URL\s*=\s*(?:file:|javascript:|vbscript:|\\\\|https?://[^\s]+\.(?:exe|scr|hta|js|vbs|ps1|bat|cmd|jar))")
_URL_ICON_REMOTE = re.compile(r"(?im)^\s*IconFile\s*=\s*(?:https?://|\\\\)")
_DESKTOP_EXEC = re.compile(r"(?im)^\s*Exec\s*=\s*(.{1,400})$")
_DESKTOP_BAD = re.compile(r"(?i)\b(?:curl|wget)\b[^\n]{0,120}\|\s*(?:bash|sh)|/dev/tcp/|base64\s+(?:-d|--decode)|"
                          r"bash\s+-c|sh\s+-c|python[0-9.]*\s+-c|osascript\b|\beval\b")


@register
class ShortcutAnalyzer(Analyzer):
    name = "shortcut"
    order = 56

    def applies(self, obj: ScanObject) -> bool:
        return obj.ftype in ("url", "desktop") and 16 <= obj.size <= (256 << 10)

    def analyze(self, obj: ScanObject, ctx: ScanContext) -> None:
        text = obj.text(256 << 10)
        if obj.ftype == "url":
            m = _URL_EXEC.search(text)
            if m:
                ctx.detect(obj, Detection("Heur:Shortcut.UrlToPayload", "heuristic", Confidence.HIGH, 30,
                                          "Internet shortcut points to a script/executable/UNC path",
                                          [m.group(0)[:160]]))
            mi = _URL_ICON_REMOTE.search(text)
            if mi:
                ctx.detect(obj, Detection("Heur:Shortcut.RemoteIcon", "heuristic", Confidence.MEDIUM, 15,
                                          "Shortcut loads its icon from a remote host (credential theft)",
                                          [mi.group(0)[:120]]))
        else:  # .desktop
            m = _DESKTOP_EXEC.search(text)
            hidden = re.search(r"(?im)^\s*(?:NoDisplay|Hidden)\s*=\s*true", text)
            if m and _DESKTOP_BAD.search(m.group(1)):
                score = 45 if hidden else 35
                ctx.detect(obj, Detection("Heur:Shortcut.DesktopExec", "heuristic", Confidence.HIGH, score,
                                          "Desktop entry runs a download/exec/reverse-shell command",
                                          [m.group(1)[:160]]))
                ctx.add_child(obj, m.group(1).encode("utf-8", "replace"), "desktop/exec.sh", kind="decoded",
                              meta={"script_lang": "shell"})
