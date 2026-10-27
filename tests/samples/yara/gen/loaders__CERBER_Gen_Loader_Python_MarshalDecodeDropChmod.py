import marshal, base64, os
blob = base64.b64decode('AAAA')
f = open('/tmp/example_placeholder', 'wb')
f.write(blob)
os.chmod('/tmp/example_placeholder', 0o755)
exec(marshal.loads(blob))
