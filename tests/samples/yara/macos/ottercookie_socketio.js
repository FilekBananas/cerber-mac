// Inert YARA fixture for CERBER_MacOS_OtterCookie_JS
const io = require("socket.io-client");
const socket = io("http://example.invalid:3306");
socket.on("command", (cmd) => {
  if (cmd == "ss_stop") {}
  if (cmd == "ss_upf") {}
  if (cmd == "ss_upd") {}
  if (cmd == "ss_del") {}
});
