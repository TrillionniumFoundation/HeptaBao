# HeptaBao RabbitMQ runtime

This is a bounded HeptaBao secret-engine runtime, not a database provider. Its
durable state owns the manager connection, role permission templates and
lease/effect phases. The service commits `PendingIssue` or `PendingRevoke`
before management API I/O, and publishes the issue secret only after exact
provider readback. A failed provider call remains a durable reconcile target.

The scoped API is:

- `POST`/`PUT`/`GET`/`DELETE` `{mount}/config/connection`;
- `LIST` `{mount}/roles`, and `POST`/`PUT`/`GET`/`DELETE` `{mount}/roles/{name}`;
- `GET` `{mount}/creds/{role}`;
- `sys/leases/lookup`, `sys/leases/renew`, `sys/leases/revoke`, and
  `sys/leases/reconcile` for RabbitMQ lease IDs.

Configuration requires `verify_connection: true` and a host-enrolled
`rabbitmq://` endpoint. Enrollment accepts only the exact loopback/private
address and port from the server configuration, with `/` as the only path.
Requests are bounded, use an explicit close-delimited JSON response, and do
not follow redirects or resolve caller-selected DNS names. Manager credentials
are held in the encrypted state boundary; readback omits the password.

Roles carry vhost names and the exact `configure`, `write`, and `read` regular
expressions. Tags are bounded and cannot be used to add an administrator
identity through the scoped API. Issuance creates a generated `hbr_` user,
applies every configured permission, and reads back the user and each
permission before returning the password. RabbitMQ users have no native TTL,
so `sys/leases/renew` returns an explicit unsupported response instead of
pretending to extend provider state.

Revoke closes matching management-visible connections, deletes the generated
user, and requires a missing-user readback. Expiry uses the same durable
revoke path. If the provider is unavailable, the response is `503` with
`reconcile_required: true`; a restart does not forget the pending effect.

The Linux acceptance profile is
`qa/openbao-acceptance/rabbitmq_live.py`. It uses only the pinned official
`rabbitmq:4.1-management@sha256:3574a8edaca320282b9c848f0b2661566b7e74f52c1b590f401b10224d294642`
image, binds random ports to loopback, exercises real AMQP authentication,
vhost and permission denial, service/provider restart, revoke and provider
outage reconciliation, and scans the private fixture for the issued password.
The profile is Linux-only and returns 77 when Docker or the pinned image is
not available; a macOS run must not be reported as a Linux runtime pass.

This is `PARTIAL_RUNTIME` / `IMPLEMENTED_SCOPED`. Full OpenBao field parity,
TLS management transport, vhost creation, native provider renewal, HA and
lost-reply fault matrices, and independent admission remain out of scope.
