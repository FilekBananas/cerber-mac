"""PowerShell detection rules (also applied to decoded PowerShell layers)."""
from __future__ import annotations

from .scripts_common import COMBOS, C, R, make_script_analyzer

RULES = [
    # download
    R("DownloadString", r"\.DownloadString\s*\(|Net\.WebClient|System\.Net\.WebClient", 5,
      "Downloads a string from the web", "download", need="download|webclient"),
    R("DownloadFile", r"\.DownloadFile\s*\(|Start-BitsTransfer|Invoke-WebRequest|\bIWR\b|Invoke-RestMethod",
      5, "Fetches a remote resource", "download", need="download|bitstransfer|invoke-web|iwr|invoke-rest"),
    R("Certutil", r"certutil(?:\.exe)?\s+[^\n]{0,80}?-urlcache", 30,
      "certutil used as a downloader", "download,exec", need="certutil"),
    # execution
    R("InvokeExpression", r"(?:Invoke-Expression|\bIEX\b)\s*[\(\$'\"@]", 10,
      "Invoke-Expression executes a dynamic string", "exec", need="invoke-expression|iex"),
    R("ScriptBlockCreate", r"\[scriptblock\]\s*::\s*create\s*\(", 15,
      "Builds and runs a dynamic script block", "exec", need="scriptblock"),
    R("EncodedCommand", r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/]{40,}|frombase64string\s*\(", 15,
      "Encoded PowerShell command / base64 payload", "exec,decode", need="-enc|frombase64"),
    # a bare "CreateThread" / "[Runtime.InteropServices.Marshal]" (SecureString -> BSTR) is everyday
    # code and documentation; only real in-memory loading primitives score on their own
    R("ReflectiveLoad", r"\[(?:system\.)?reflection\.assembly\]\s*::\s*(?:load|loadfile|loadfrom|unsafeloadfrom)\s*\(|"
      r"getdelegateforfunctionpointer\s*\(|\bgetdelegatefortype\b", 30,
      "In-memory assembly / shellcode loading", "exec",
      need="reflection.assembly|getdelegatefor"),
    R("Win32MemoryApi", r"\bvirtualalloc(?:ex)?\b|\bcreate(?:remote)?thread\b|\bwriteprocessmemory\b|"
      r"\bvirtualprotect\b|\[(?:system\.)?runtime\.interopservices\.marshal\]\s*::\s*copy\s*\(", 0,
      "Native memory / thread API", "shellcode",
      need="virtualalloc|createthread|createremotethread|writeprocessmemory|virtualprotect|marshal]"),
    R("PInvokeKernel32", r"\[dllimport\s*\(\s*['\"]kernel32|add-type\b[^\n]{0,300}(?:dllimport|kernel32)|"
      r"definedynamicassembly\s*\(", 0, "P/Invoke of native Windows APIs", "pinvoke",
      need="dllimport|add-type|definedynamicassembly"),
    # evasion
    R("AmsiBypass", r"amsiinitfailed|amsiutils|amsiscanbuffer|\[ref\]\.assembly\.gettype\s*\(\s*['\"]system\.management\.automation\.amsi",
      45, "AMSI (Antimalware Scan Interface) bypass", "evasion,exec", need="amsi"),
    R("DisableDefender", r"set-mppreference\s+[^\n]{0,80}?-disable(?:realtimemonitoring|ioavprotection|behaviormonitoring)|"
      r"add-mppreference\s+[^\n]{0,60}?-exclusionpath", 45,
      "Disables Microsoft Defender protection", "evasion", need="mppreference"),
    R("ExecutionPolicyBypass", r"-ex(?:ecutionpolicy)?\s+bypass|-nop(?:rofile)?\b", 5,
      "Bypasses execution policy / profile", "evasion", need="bypass|-nop"),
    R("HiddenWindow", r"-w(?:indowstyle)?\s+hidden|-noni|createnowindow", 5,
      "Runs with a hidden window", "hidden", need="hidden|-noni|createnowindow"),
    # persistence
    R("RunKeyPersistence", r"(?:currentversion\\run|hkcu:.{0,40}\\run|hklm:.{0,40}\\run)", 20,
      "Registry Run-key persistence", "persist", need="\\run"),
    R("ScheduledTask", r"register-scheduledtask|schtasks(?:\.exe)?\s+/create|new-scheduledtask", 15,
      "Scheduled-task persistence", "persist", need="scheduledtask|schtasks"),
    R("WmiPersistence", r"__eventfilter|commandlineeventconsumer|set-wmiinstance\s+[^\n]{0,60}subscription", 30,
      "WMI event-subscription persistence", "persist", need="eventfilter|eventconsumer|subscription"),
    # credentials / exfil
    R("CredentialAccess", r"convertfrom-securestring|get-credential|mimikatz|sekurlsa|lsass|"
      r"invoke-mimikatz|dumpcreds", 25, "Credential access / dumping", "cred",
      need="securestring|get-credential|mimikatz|sekurlsa|lsass|dumpcreds"),
    R("Exfil", r"\.UploadString\s*\(|\.UploadFile\s*\(|\.UploadData\s*\(", 10,
      "Uploads data to a remote endpoint", "exfil", need="upload"),
    # a REST POST is ordinary API/CI usage: capability only (feeds the CredentialExfil combo)
    R("RestPost", r"invoke-(?:restmethod|webrequest)\s+[^\n]{0,160}?-method\s+['\"]?post", 0,
      "POSTs data to a web endpoint", "exfil", need="-method"),
]

PS_COMBOS = COMBOS + [
    C("ShellcodeInjection", "shellcode,pinvoke", 35,
      "P/Invokes native memory/thread APIs (shellcode loader)", window=4000),
]

make_script_analyzer("PowerShellAnalyzer", "ps1", {"powershell"}, "powershell", RULES, combos=PS_COMBOS)
