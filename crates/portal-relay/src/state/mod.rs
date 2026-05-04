//! Relay runtime state — identity, lease registry, TLS material.
//!
//! Phase 5 fills in:
//! - U4 `identity.rs` — R2 `SecretBox<KeyType>` newtypes + loader.
//! - U5 `lease.rs` — papaya-backed lease registry.
//! - U12 `tls_material.rs` — rustls cert/key handoff from portal-acme.
