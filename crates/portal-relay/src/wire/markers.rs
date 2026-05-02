/// Hop-mux keepalive frame — sent to prevent idle timeout.
pub const KEEPALIVE: u8 = 0x00;
/// Raw TCP stream activation byte — signals raw passthrough mode.
pub const RAW_TCP: u8 = 0x01;
/// TLS-over-mux activation byte — signals TLS handshake on mux stream.
pub const TLS_ACTIVATE: u8 = 0x02;
