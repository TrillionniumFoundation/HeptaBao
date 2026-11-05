# Official browser UI deployment

The TLS listener can serve a separately built OpenBao 2.7.0 UI at /ui/.
The UI source and its MPL-2.0 license remain in the UI build custody bundle.
This Rust integration adds no replacement frontend and does not claim that
a browser acceptance run has passed.

Add these fields to the existing listener JSON configuration:

    "ui": true,
    "ui_assets_dir": "/data/<official-ui-build>/dist",
    "ui_assets_manifest": "/data/<official-ui-build>/UI_dist_pins.original.json",
    "ui_assets_manifest_sha256": "<SHA256 of the exact manifest bytes>"

Omitting ui keeps the existing API-only listener behavior. UI settings require
ui=true. At startup the asset directory and manifest must be absolute physical
paths without symlinks. Files must be regular, have one physical link, and must
not be writable by group or other users. The manifest is a JSON array of
objects containing path, bytes, and sha256. Unknown manifest fields, duplicate
paths, unsafe relative paths, absent index.html, and mismatched bytes reject
startup. Limits are 4096 files, 1 MiB manifest, 32 MiB per file, and 64 MiB total.
An unknown asset suffix is validated but never served. Upstream .gitkeep
placeholders are validated but never served.

The listener reads and pins all assets before accepting connections. Requests
select that immutable table, without disk path resolution. GET and HEAD share
Content-Length and fixed MIME selection. Requests reject bodies, ambiguous
transfer framing, traversal, hidden path segments, encoded separators, and
pipelining. / and /ui redirect to /ui/. The official fixed vault cluster routes
and their client-side catchall use index.html; missing /ui/assets/ and image
resources return 404. API targets always retain their existing /v1/ dispatch.
TLS client certificate policy, rate limits, request deadlines and HTTP/2
stream admission apply equally to UI traffic.

UI responses use no-store, nosniff, same-origin referrer policy, and a CSP based
on ui/config/content-security-policy.js. The service worker may claim only the
official /v1/sys/storage/raft/snapshot scope. The final built index and real
browser execution still need validation against that CSP.

GET /v1/sys/internal/ui/resultant-acl uses ordinary authenticated admission and
the actual read permission. It renders current token and identity policies,
including identity templates, and merges identical rules using current deny,
parameter and wrapping-bound semantics. Its namespace-prefixed exact_paths
and glob_paths are advisory UI metadata; backend requests keep their actual
ACL evaluator. Root tokens receive root=true. Wrapping tokens and mount-only
metadata principals cannot acquire this projection. Finite-use tokens still
consume their normal request admission.

GET /v1/sys/internal/ui/namespaces requires a valid ordinary actor. It returns
relative descendant registry keys only when that actor can already list
sys/namespaces in the selected namespace. Otherwise it returns an empty key
list. Existing token namespace confinement and namespace retirement guards
remain in effect. This conservative discovery rule needs black-box comparison
with the official 2.7.0 endpoint before claiming complete namespace UI parity.

Source tests cover integrity admission, frozen loaded bytes, MIME and HEAD,
worker scope, SPA and missing assets, traversal and request framing, duplicate
pins, links, current ACLs and deny precedence, finite-use exhaustion,
revocation, real service/batch identity updates, and namespace actor scope.
They require the normal Data-owned test HOME/TMP setup.
