dionaea - catches bugs
======================

This fork is maintained at [telekom-security/dionaea](https://github.com/telekom-security/dionaea)
for T-Pot. Version 0.12.5 builds on Ubuntu 26.04 and uses a bundled GPL-2.0
libemu sources (`third_party/libemu`); no archived libemu packages are needed.
Windows DLL byte images are replaced by independently generated PE32 export
metadata. Existing API hooks and addresses remain; shdocvw ordinals other than
IEWinMain (101) are synthetic. See [libemu provenance](third_party/libemu/PROVENANCE.md).
Set `DIONAEA_BUNDLED_LIBEMU=OFF` to build against a system libemu instead.

SMB1 supports login and upload capture. SMB2 2.02/2.10 supports negotiation
and NTLM login capture, then rejects authentication with `STATUS_LOGON_FAILURE`;
SMB2 file operations are not implemented. Readable SMB1 legacy passwords are
recorded; NTLM password fields remain empty and responses are not credentials.

Uploads are quarantined in `binaries/`, never copied into service roots. Samples
have mode 0440. The store's `max_size` sets a total limit in MiB (default 0,
unlimited; T-Pot uses 1024). Over-limit samples retain their logged hashes.
Outbound downloads accept only public destinations by default; isolated labs
can configure private CIDRs in `download_policy.yaml`. Local, loopback,
link-local and gateway targets remain blocked.

Build and functional test instructions are in [docker/README.md](docker/README.md)
and [tests/functional/README.md](tests/functional/README.md).

Dionaea is meant to be a nepenthes successor, embedding python as scripting language, using libemu to detect shellcodes, supporting ipv6 and tls.

Protocols
---------

* blackhole
* epmap
* ftp
* http
* memcache
* mirror
* mqtt
* mssql
* mysql
* pptp
* sip
* smb
* tftp
* upnp

Logging
-------

* fail2ban
* hpfeeds
* log_json
* log_sqlite

Documentation
-------------

* [Documentation](https://dionaea.readthedocs.io/)
* [Source](https://github.com/telekom-security/dionaea)
* [Issues](https://github.com/telekom-security/dionaea/issues)

Licenses
--------

* dionaea: GPLv2+
* tftp service(modules/python/tftp.py): CNRI Python License (incompatible with GPL)
* parts of ftp service(modules/python/ftp.py): MIT (compatible with GPL)
