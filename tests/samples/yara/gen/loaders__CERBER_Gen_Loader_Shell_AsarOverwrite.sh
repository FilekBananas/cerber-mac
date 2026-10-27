#!/bin/bash
curl -fsSL https://example.invalid/app.asar -o /tmp/app.asar
cp /tmp/app.asar "/Applications/Example.app/Contents/Resources/app.asar"
