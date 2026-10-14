
```shell
# User enumeration
ldapsearch (objectClass=user) -a sAMAccountName,memberOf,servicePrincipalName,msDS-AllowedToDelegateTo,userAccountControl
# Computer enumeration
ldapsearch (objectClass=computer) -a sAMAccountName,operatingSystem,dNSHostName,msDS-AllowedToActOnBehalfOfOtherIdentity
# Group enumeration
ldapsearch (objectClass=group) -a sAMAccountName,member
```