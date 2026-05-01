# Go Compatibility Fixtures

Fixtures in this directory define stable wire shapes copied from or matched to
the current Go relay contract. Rust tests should compare against these files
instead of duplicating expected JSON inline.

Current fixture scope:

- `api/healthz_success.json`
- `api/sdk_domain_success.json`
- `api/method_not_allowed.json`

Future fixture groups should cover SIWE messages, ES256K JWTs, keyless signing,
reverse-session markers, and UDP datagram frames.

