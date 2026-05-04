//! Top-level server orchestrator that owns the three axum routers + the
//! QUIC backhaul endpoint + the lease janitor + the policy runtime.
//! Phase 5 U16 lands the `Server` struct + `Server::run`.
