# Conditional signed UID parser design — not a dispatchable repair

This is a source-only design. Frozen lexical SOURCE25 b4fcfb45f14951671c37b6ac5190bbb51de5165b is unchanged and its slot has not been initialized. No actual negative UID value or rejected column has yet been observed.

Prerequisite for this particular repair: the one newly authorized lexical projection must show every row has exactly five fields; columns 1–3 are all ASCII decimal; every rejection is solely column 4 negative_decimal; no other lexical class is rejected. If that predicate is false, this design is not applied automatically.

## Minimal candidate

Keep the exact ASCII decode, whitespace split, first-three-column decimal requirement, map(int), group filtering, and all callers. Validate only column 4 with an optional leading minus and 1–10 digits, then bound its integer to [-2147483648,4294967295]. This retains unsigned 32-bit positive display and admits only signed 32-bit negative display. Keep the observed integer value; never normalize by adding 2^32, truncate, default to zero or map to the operator.

```python
need(len(fields)==5 and all(x.isdecimal() for x in fields[:3])
     and re.fullmatch(r'-?[0-9]{1,10}',fields[3]) is not None, 'typed_process_row')
pid,ppid,pgid,uid=map(int,fields[:4])
need(-(1<<31)<=uid<=(1<<32)-1, 'typed_process_row')
```

This fragment is a prospective design, not a patched manager. The bounds are the proposed parser contract; this note does not assert the installed ps build is the referenced Apple commit. It does not broaden PID/PPID/PGID or accept plus signs, placeholders, arbitrary text or extra fields.

The manager's group-table uid is returned as data and does not grant signal authority. Actual ownership remains in the independently held primary/direct-child PPID/PGID/effective-UID/birth/WNOWAIT protocol. The only primary EUID0 exception remains exact whole/full9 pinned /bin/ps; all other command and group-member owner predicates remain unchanged.

## Public source basis

Fixed Apple adv_cmds commit 6bed8737a34dbb54782a18f47dccf933a9967a12. keyword.c (already whole in SOURCE25) defines __APPLE__ UIDFMT d and PIDFMT d; pid is pvar, ppid/pgid/uid are evar with UINT and the respective format.

New exact print.c is included. Lines 1097–1144 build the printf format from v->fmt and use fmtcheck; UINT passes the stored u_int to printf with fmtcheck(ofmt,"%*u"). pvar/evar at 1148–1166 unconditionally route their fields to printval. This confirms the field-to-format path, not the old rejected row or exact installed build provenance.

Whole primary URL: https://github.com/apple-oss-distributions/adv_cmds/blob/6bed8737a34dbb54782a18f47dccf933a9967a12/ps/print.c

The old 9-call validation remains failed1 at typed_process_row, with final input fence false. Its positive actual ps custody and exit/cleanup are retained separately. Old ps 84947/85012, old managed UNKNOWN, SDK/business qualification and current issuer qualification are unchanged.
