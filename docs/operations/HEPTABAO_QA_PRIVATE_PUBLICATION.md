# Private publication of disposable QA files

The LDAP fixture helper `private(path, text)` delegates to
`heptabao.transport.private_write_text`. JSON callers continue to use
`private_write`; JSON strings retain their quoted canonical representation.
Exact-text publication preserves UTF-8 bytes and trailing newlines, including
empty files. It does not add a JSON envelope or a trailing newline.

Both entry points use the same existing descriptor-bound publisher: an existing
caller-owned parent must have no group/other permissions, and an existing leaf
must be a caller-owned private regular file, not a symbolic link. A new exclusive
0600 temporary file is written and fsynced before an atomic descriptor-relative
rename. The directory is then fsynced. Replacing one hard-link name does not
truncate the other linked inode or an already-open reader. Create-only callers
retain no-replacement publication. Temporary files are cleaned on failure.

A failure before rename preserves the previous destination. A failure after
rename (for example directory fsync) can leave the new file visible: an exception
is not proof that no publication occurred. Do not blindly retry external effects.
The fixture is owned by the invoking user; same-UID processes and root remain
trusted. Parent ancestors are not a new security boundary, and this is filesystem
isolation, not encryption or a claim that a static-analysis alert is dismissed.

Only disposable fixture configuration, password-hashed LDIF, and safe reports
belong on these paths. LDAP bind credentials retain their existing anonymous-pipe
transport. The helper neither moves them into files nor changes the product's
authorization, storage schema, TLS policy, OpenBao comparison scope or CI gates.

Regression entry points:

```sh
PYTHONPATH=qa/openbao-acceptance:clients/python python -m unittest discover \
  -s qa/openbao-acceptance/tests -p test_ldap_private_publication.py
PYTHONPATH=clients/python python -m unittest discover \
  -s clients/python/tests -p test_private_text_publication.py
```

On macOS, descriptor-bound clients accept the platform's fixed root-owned
`/var`, `/tmp` and `/etc` aliases only after exact owner, mode and link-target
verification, then walk `/private/...` without following later links. Arbitrary
caller-controlled aliases remain rejected. A custom `TMPDIR` is therefore not a
substitute for the same descriptor and private-mode checks.
