Browsers will typically encrypt these credentials using the [Windows Data Protection API](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/) (DPAPI) and store them in a local database.  Adversaries may be able to read and decrypt this database to obtain the original plaintext passwords [T1555.003]

Most Chromium-based browsers keep a SQLite database in the path `%LOCALAPPDATA%\<vendor>\<browser>\User Data\Default\Login Data`.
For example, Chrome stores its database at `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`.

Tools like SharpChrome can automatically read and decrypt credentials from the database.
```
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpChrome\bin\Release\SharpChrome.exe logins
```

> This technique can be used from a medium-integrity context.

