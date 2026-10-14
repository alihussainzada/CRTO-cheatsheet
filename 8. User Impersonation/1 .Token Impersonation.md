_Token Impersonation_ is a technique where an adversary impersonates an access token belonging to another user.  Those tokens can be created if the adversary knows the plaintext credentials of a user, or they can be stolen from processes running in other logon sessions.

## make_token
An adversary uses the plaintext credentials of a user to create a new access token, and then impersonates it.
```
make_token CONTOSO\rsteel Passw0rd!
```

## steal_token
This is a technique where an adversary "steals" the primary access token from a process running as a different user.
Identify a target process using the `ps` command or Process Explorer first.
```
ps

steal_token 5248
```
> This technique _does_ require a high-integrity session.

## rev2self
To instruct Beacon to stop impersonating a token, whether made or stolen, run the `rev2self` command.  This calls the [RevertToSelf](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself) API under the hood.

## token-store
The downside of the steal_token command is that if you drop impersonation and the process subsequently closes, you can no longer impersonate it again.  Beacon has a token "store" where you can permanently hold a reference to the token, even after the process has closed.  This works because tokens are reference counted by the kernel, so they won't be disposed if something is holding an active handle to it.

The `token-store` command is used to manage tokens, such as:

- `token-store steal` to steal a token and add it to the store.    
- `token-store show` to print the tokens in the store.
- `token-store use` to use a token in the store.
- `token-store remove` to remove a token from the store.

```
beacon> token-store steal 5248

beacon> token-store use 0
```