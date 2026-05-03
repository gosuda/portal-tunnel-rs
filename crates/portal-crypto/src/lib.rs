//! Cryptographic primitives — identity, signing, and the keyless protocol skeleton.
//!
//! Owner: cryptographic primitives (Phase 2, U3). Holds every `SecretBox<KeyType>`
//! constructor in the workspace; no other crate may load a private key from disk.
