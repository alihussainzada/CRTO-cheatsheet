
```shell
# User enumeration
ldapsearch (objectClass=user) -a sAMAccountName,memberOf,servicePrincipalName,msDS-AllowedToDelegateTo,userAccountControl
# Computer enumeration
ldapsearch (objectClass=computer) -a sAMAccountName,operatingSystem,dNSHostName,msDS-AllowedToActOnBehalfOfOtherIdentity
# Group enumeration
ldapsearch (objectClass=group) -a sAMAccountName,member
```

Find admins:
```
ldapsearch "(&(objectCategory=person)(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=contoso,DC=com))" --attributes sAMAccountName
```

