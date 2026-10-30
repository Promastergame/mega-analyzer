# Local fixture server

Optional local-only backend for `demo_test_apk`. It binds to loopback only and
does not contain credentials or external network calls.

Example response contract:

```text
GET /economy/coins        -> {"coins":1000}
GET /subscription/status  -> {"active":true}
GET /features             -> {"premium":true}
GET /age/verify           -> {"adult":true,"age":21}
```

The app's Java source is still useful without this server: timeout/error paths
are part of the analyzer fixture.
