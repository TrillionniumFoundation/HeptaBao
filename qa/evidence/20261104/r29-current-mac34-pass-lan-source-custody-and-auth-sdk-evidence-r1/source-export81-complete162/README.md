# Original current4e808 source-export command archive

All six authorized fixed read-only batches completed and their original SDKs, statuses and complete immutable payloads are preserved. The 81 original files total 28,080 bytes: 27 command records and each command's stdout and stderr. Whole sizes and SHA256 match the frozen plan, command records match the original detailed receipt losslessly, and both streams match each original command row. Returned file versions are retained as independent per-file observations, not an atomic snapshot.

The original 27 commands were not rerun. Their 25 exit-0 outcomes and two expected exit-1 partial-config queries remain distinct; all original command rows report reaped children and empty remaining groups. Bundle metadata was already independently closed by root and was not read again. The prior original export authority comes from the referenced source packet/root admission; this archive did not issue a new process_status for that exporter.

LAN9 source readback prerequisites were already fully published. Source3's initial lost-ACK read admission remains historical UNKNOWN, with its later reused=false observation recorded separately. No relay/import/product execution is granted here. The separately approved conditional inert publication has not yet been submitted at this archive point.
