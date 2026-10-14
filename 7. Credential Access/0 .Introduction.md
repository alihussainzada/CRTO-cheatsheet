_Credential Access_ is a tactic [TA0006] where an adversary attempts to steal the authentication material of users.  This can include usernames, plaintext passwords, password hashes, and Kerberos tickets.

Some credential access techniques can be performed as a standard user; others require local administrative privileges; and others require Domain Admin privileges.

This chapter will cover the following techniques:

- Credentials from Web Browsers [T1555.003]
- Windows Credential Manager [T1555.004]
- LSASS Memory [T1003.001]
- Security Account Manager [T1003.002]
- LSA Secrets [T1003.004]
- Cached Domain Credentials [T1003.005]
- Kerberoasting [T1558.003]
- AS-REP Roasting [T1558.004]