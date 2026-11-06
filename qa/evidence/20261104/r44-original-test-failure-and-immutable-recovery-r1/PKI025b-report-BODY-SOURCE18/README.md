# Fixed report body, original 025b BUILD

This candidate reuses the already reviewed single-chunk 33b report-body algorithm on the current INFO successor. Only the exact original 025b metadata, job, request and existing slot are bound. The new observation is one offset-0, 49,775-byte binary_read with the independently observed version and SHA-256. The body does not yet exist in this SOURCE packet.

The old 8 KiB metadata/status page behavior remains. Only the new binary observer uses 16 KiB immutable delivery pages, with the original 1 MiB payload cap and one-call/future boundary. No process, INFO replay, directory enumeration, Cargo or target reuse is proposed.

The 29 selected pure guard checks use a cloned state and no tools. They validate actual INFO binding, exact request admission, once-only and drift rejection, both page caps, whole-body EOF/SHA gates, and old state preservation. They are not host observations or product tests. The complete decoded report will be externally whole-archived before semantic failure analysis.
