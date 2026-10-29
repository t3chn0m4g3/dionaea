# Build and run this fork

The root Dockerfile builds Dionaea 0.12.5 on Ubuntu 26.04. It bundles libemu
and runs as uid/gid 2000 with `cap_net_bind_service`. Paths remain under
`/opt/dionaea`: configuration in `etc/dionaea`, service roots and quarantine
in `var/dionaea`, logs in `var/log`.

```sh
docker build -t dionaea:local .
tests/functional/run.sh
```

The image starts `/opt/dionaea/sbin/dionaea` directly and uses SIGINT to stop.
There is no initialization entrypoint or `DIONAEA_FORCE_INIT` environment API.
Mount prepared configuration read-only at `/opt/dionaea/etc/dionaea` and mount
writable data/log directories at `/opt/dionaea/var/dionaea` and
`/opt/dionaea/var/log`. Mount `roots/{ftp,tftp,www,upnp}` read-only individually.
These directories must be accessible to uid/gid 2000. Keep stdin and TTY off.

Use [the functional harness](../tests/functional/README.md) for an isolated
container and protocol examples. Its configuration mirrors T-Pot's services;
production ports and configuration are supplied by the T-Pot image.

SMB2 captures authentication only; SMB1 captures file uploads. Readable legacy
SMB1 passwords are stored in credentials; NTLM responses are never passwords.
Uploads are kept at mode 0440 in `binaries/`, separate from all service roots.
The store cap is optional in the fork and 1 GiB in T-Pot. Download destinations
are public only unless an isolated lab explicitly allows a private CIDR.
