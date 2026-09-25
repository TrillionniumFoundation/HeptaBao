# Kerberos native validation boundary


## Native clock profile and current MIT fixture

The MIT fixture configures both its private `krb5.conf` and the declared role
with a 60-second native tolerance. It deliberately delays the first valid AP-REQ
for more than one second before delivery, without retrying a failed login. The
previous zero-native-skew fixture could fail that ordinary request at a second
boundary even though its role declared 60 seconds.

MIT uses `clockskew` for authenticator validation **and ticket start/end times**
(see the MIT Kerberos `krb5.conf` documentation,
https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html).
The expiry negative therefore sends a never-before-consumed short-lived ticket
after its lifetime plus the declared native tolerance and a safety margin. It
is not a claim of rejection inside MIT's grace window, nor may replay rejection
substitute for an expiry observation. The report records the native window,
positive request delay and expiry wait. Native replay caches remain enabled;
realm/service negatives, cold-cache cross-namespace replay and restart replay
checks remain mandatory. Strict endtime rejection independent of native grace,
per-mount control of the native library's clock profile and distributed clock
fault qualification are not established by this fixture.
