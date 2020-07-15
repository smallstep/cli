# Frequently Asked Questions

These are some commonly asked questions on the topics of PKI, TLS, X509,
cryptography, threshold-cryptography, command-line-interfaces etc.
Hopefully we will reduce the amount of hand-waving in these responses as we add
more features to the Step toolkit over time.

## Why don't you allow the use of Environment Variables for passwords (instead of files, e.g. --password-file)?

`systemd` discourages using the environment for secrets because it doesn't
consider it secure and exposes a unit's environment over dbus:

> Note that environment variables are not suitable for passing secrets (such as
> passwords, key material, …) to service processes. Environment variables
> set for a unit are exposed to unprivileged clients via D-Bus IPC, and generally
> not understood as being data that requires protection. Moreover, environment
> variables are propagated down the process tree, including across security
> boundaries (such as setuid/setgid executables), and hence might leak to
> processes that should not have access to the secret data.

For container, namespace, and/or non-systemd scenarios I could see an argument
for the convenience. But only using the option in those cases would need to be
drilled into users, and we generally don't like software that lets users
stumble upon insecure patterns.

For posterity, if you've secured your environment and rely on it for secrets:

step-ca --password-file <(echo -n "$STEP_CA_PASSWORD")

is a workaround if you prefer to have your passwords in the environment.
