var app = Application("System Events");
var out = app.doShellScript("echo AAAA | base64 -D | sh");
