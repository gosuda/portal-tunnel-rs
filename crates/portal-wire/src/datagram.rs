//! UDP [`DatagramFrame`](DatagramFrame) on `Channel::UdpDatagram`.

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::limits;

/// Flow id + payload for QUIC datagram relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatagramFrame {
    /// Multiplexed UDP flow id.
    pub flow_id: u32,
    /// Payload capped at [`limits::UDP_DATAGRAM_MAX`](crate::limits::UDP_DATAGRAM_MAX).
    pub payload: Bytes,
}

impl DatagramFrame {
    /// Enforce SEC-014 size cap.
    ///
    /// # Errors
    /// Returns [`Error::FrameTooLarge`] when `payload` exceeds [`limits::UDP_DATAGRAM_MAX`].
    pub const fn validate_len(&self) -> Result<(), Error> {
        if self.payload.len() > limits::UDP_DATAGRAM_MAX {
            return Err(Error::FrameTooLarge);
        }
        Ok(())
    }
}
