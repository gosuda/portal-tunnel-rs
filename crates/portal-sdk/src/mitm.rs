//! RFC 5705 keying-material exporter probe for MITM detection.
//!
//! Derives 32 bytes of post-handshake keying material from a rustls
//! TLS connection using the canonical label
//! [`portal_wire::mitm::MITM_PROBE_LABEL`]
//! (`b"portal-tunnel/mitm-probe/v2"`).
//!
//! [`derive_probe_ekm`] is the building block; the cross-channel
//! echo / comparison lives in a later integration unit where the
//! relay-side echo path is wired up. Until that lands, callers
//! receive the raw bytes and may compare them against a separately
//! conveyed expected value out-of-band.
//!
//! # Why not compare here?
//!
//! Earlier drafts of the plan proposed a single `probe_mitm(conn,
//! expected_spki)` entry point. Reviewer feedback flagged that this
//! conflated two concerns — pure EKM derivation from rustls TLS
//! state, and cross-channel comparison against an expected value —
//! and that the comparison side has no value until the relay-side
//! echo over a separate authenticated channel is implemented. We
//! therefore ship only the derivation primitive in this batch and
//! defer the comparison wrapper to the integration unit that wires
//! the echo path.

use portal_wire::mitm::MITM_PROBE_LABEL;

/// Length of the derived keying material in bytes.
pub const PROBE_EKM_LEN: usize = 32;

/// Errors returned by [`derive_probe_ekm`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MitmError {
    /// The TLS connection's exporter rejected the request — typically
    /// because the handshake has not yet completed, or the negotiated
    /// cipher suite does not support keying material export.
    #[error("rustls exporter failed: {0}")]
    ExporterFailed(#[from] rustls::Error),
}

/// Derive [`PROBE_EKM_LEN`] bytes of RFC 5705 keying material from a
/// rustls connection (client or server side) using the canonical
/// portal-tunnel MITM-probe label.
///
/// Both peers calling this on the same TLS connection MUST receive
/// the same bytes. A mismatch when the bytes are exchanged over a
/// separate authenticated channel indicates a MITM has terminated TLS
/// between them.
///
/// # Errors
///
/// Returns [`MitmError::ExporterFailed`] if rustls rejects the
/// exporter call. The most common cause is calling this function
/// before the handshake has completed; check
/// [`rustls::CommonState::is_handshaking`] first when ordering is in
/// doubt.
pub fn derive_probe_ekm<Data>(
    conn: &rustls::ConnectionCommon<Data>,
) -> Result<[u8; PROBE_EKM_LEN], MitmError>
where
    Data: rustls::SideData,
{
    let mut out = [0_u8; PROBE_EKM_LEN];
    conn.export_keying_material(&mut out[..], MITM_PROBE_LABEL, None)?;
    Ok(out)
}
