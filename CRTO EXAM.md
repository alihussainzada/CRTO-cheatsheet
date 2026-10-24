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



# note
is admin:
```
 Niall Wallace
```
id dub domain


