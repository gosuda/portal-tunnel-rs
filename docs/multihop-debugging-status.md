# Multihop Debugging Status

Last updated: 2026-05-02 KST

## Summary

Rust relay `v2.1.8-rs.dev5` and later diagnostic builds still show an intermittent or persistent failure on a 3-hop path where `rly.best` is the middle relay:

```text
portal.thumbgo.kr -> rly.best -> s-h.day -> local service
```

The same local service and Go client can succeed when the middle relay is another Go relay:

```text
portal.thumbgo.kr -> portal.rabbitson87.dev -> s-h.day -> local service
```

This narrows the issue to Rust relay multihop behavior, especially the inbound overlay path from the Go entry relay into the Rust middle relay.

## Current Deployment State

- Target relay: `rly.best`
- Server: Debian VM at `192.168.219.123`
- Runtime container: `portal-relay`
- Current diagnostic image during investigation: `portal-relay-gofix:diag13-bookworm-arm64`
- Current logging level used for diagnostics:

```text
RUST_LOG=portal_relay=debug,yamux=debug,boringtun=warn,tokio_wireguard=info,info
```

No Git push was performed for these diagnostic changes.

## Reproduction

Local test service:

```text
127.0.0.1:18083
```

Failing 3-hop test shape:

```bash
portal-dev expose 127.0.0.1:18083 \
  --multi-hop https://portal.thumbgo.kr,https://rly.best,https://s-h.day \
  --relays https://portal.thumbgo.kr,https://rly.best,https://s-h.day \
  --discovery=false
```

The public URL is then requested through the entry relay:

```text
https://<generated-name>.portal.thumbgo.kr/health
```

Observed client-side failures include TLS EOF and request timeout.

## Confirmed Working Paths

The following paths have been confirmed during the investigation:

- Go middle relay control path works:

```text
portal.thumbgo.kr -> portal.rabbitson87.dev -> s-h.day
```

- Rust relay can reach the exit relay as the entry or direct outbound overlay peer in at least one diagnostic run:

```text
rly.best -> s-h.day
```

- `/sdk/hop` registration and renewal against `rly.best` succeed. The current failure is not the earlier `hop route signature is invalid` API error.

## Important Observations

When `rly.best` is the middle hop, logs show this sequence:

1. `rly.best` receives the inbound HopMux stream from `portal.thumbgo.kr`.
2. `rly.best` receives the hop token and initial TLS ClientHello from the entry side.
3. `rly.best` opens the outbound overlay HopMux stream to `s-h.day`.
4. `rly.best` forwards the token and ClientHello to `s-h.day`.
5. `rly.best` receives the TLS server response from `s-h.day`.
6. `rly.best` writes that response back to the inbound stream toward `portal.thumbgo.kr`.
7. `portal.thumbgo.kr` does not appear to send the next TLS flight back to `rly.best`.
8. The request eventually fails with EOF or timeout.

The most useful narrowed symptom is:

```text
rly.best receives data from s-h.day and writes it toward portal.thumbgo.kr,
but no further inbound data is observed from portal.thumbgo.kr afterward.
```

This suggests the failure is after the Rust relay writes the exit relay response back to the Go entry relay.

## Changes Added During Diagnostics

The local working tree currently contains diagnostic and experimental changes in the relay runtime:

- Added structured HopMux logs for inbound and outbound session lifecycle.
- Added raw HopMux I/O tracing for read, write, flush, shutdown, and parsed yamux frame headers.
- Added bridge byte counters and directional copy tracing.
- Added explicit `flush()` calls after bridge writes and replay writes.
- Added prefetch of the inbound ClientHello before opening the next hop.
- Changed token frame emission to a single write plus flush to match the Go behavior more closely.
- Changed invalid token handling so a bad inbound stream shutdown does not close the entire yamux session.
- Experimented with replacing `tokio-yamux` with the `yamux` crate plus Tokio compat.
- Experimented with splitting traced bridge writes into 1200-byte chunks.

These changes are diagnostic and should be reviewed before being kept as production code.

## Current Hypothesis

The issue is likely in one of these areas:

1. Rust relay inbound overlay TCP stream write behavior.
   The Rust relay logs show writes toward the Go entry relay, but the Go entry side behaves as if it does not receive or process the response.

2. HopMux frame compatibility on accepted inbound sessions.
   Outbound Rust-to-Go HopMux toward `s-h.day` can work, but accepted Go-to-Rust HopMux sessions may still differ in framing, flush timing, half-close behavior, or stream lifecycle.

3. `tokio-wireguard` TCP stream behavior under accepted inbound connections.
   The failure is narrowed below the HTTP API and below route signature validation. The next area to verify is whether data written to an accepted overlay TCP stream is actually delivered to the Go peer in the expected shape.

The `tokio-yamux` to `yamux` swap did not resolve the issue by itself. Large response frame splitting also did not resolve it.

## Less Likely Causes

The following causes are less likely based on the current evidence:

- `/sdk/hop` signature validation failure.
- Missing lease registration.
- Local test application failure.
- Exit relay `s-h.day` failing to return data.
- General inability for `rly.best` to open outbound overlay connections.

## Next Debugging Steps

Recommended next work:

1. Inspect `tokio-wireguard` accepted TCP stream write and flush semantics.
2. Add a minimal overlay echo diagnostic that bypasses HopMux to verify raw accepted overlay TCP bidirectional delivery.
3. Compare Go relay HopMux frame behavior against Rust frames on an accepted inbound session.
4. Decide whether to revert the experimental `yamux` crate swap and keep only the logging, flush, and prefetch changes.
5. Once the root cause is confirmed, reduce diagnostic logging to targeted structured logs that are safe for production troubleshooting.

## Operational Notes

- Do not push these diagnostic changes until the failing path is fixed or the experimental changes are split into a reviewable branch.
- Server logs intentionally avoid tokens, signatures, private keys, and other secret material.
- The deployed diagnostic image is useful for tracing, but the log volume is high and should not remain enabled indefinitely in production.
