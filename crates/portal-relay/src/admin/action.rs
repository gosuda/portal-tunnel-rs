//! Future admin mutation actions shared by operator surfaces.

use std::net::IpAddr;

use crate::state::IdentityKey;

/// Identity approval mode selected by an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    /// Identities are approved automatically.
    Auto,
    /// Identities require explicit operator approval.
    Manual,
}

/// Admin action vocabulary for current and future operator views.
///
/// The R15 v0.1 status TUI is read-only and never invokes these actions;
/// the enum lives here so later mutable admin surfaces can share one command
/// shape without coupling to a concrete frontend.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Action {
    /// Ban an identity key.
    BanIdentity {
        /// Identity key to ban.
        key: IdentityKey,
    },
    /// Remove an identity-key ban.
    UnbanIdentity {
        /// Identity key to unban.
        key: IdentityKey,
    },
    /// Approve an identity key.
    ApproveIdentity {
        /// Identity key to approve.
        key: IdentityKey,
    },
    /// Deny an identity key.
    DenyIdentity {
        /// Identity key to deny.
        key: IdentityKey,
    },
    /// Ban an IP address.
    BanIp {
        /// IP address to ban.
        ip: IpAddr,
    },
    /// Remove an IP-address ban.
    UnbanIp {
        /// IP address to unban.
        ip: IpAddr,
    },
    /// Set a per-identity bytes-per-second cap.
    SetIdentityBps {
        /// Identity key whose cap is changing.
        key: IdentityKey,
        /// Bytes-per-second cap to apply.
        bps: u64,
    },
    /// Set the UDP forwarding policy.
    SetUdpPolicy {
        /// Whether UDP forwarding is enabled.
        enabled: bool,
        /// Maximum simultaneous UDP leases allowed by the policy.
        max_leases: usize,
    },
    /// Set the policy for a TCP port.
    SetTcpPortPolicy {
        /// Whether TCP port forwarding is enabled.
        enabled: bool,
        /// Maximum simultaneous TCP port leases allowed by the policy.
        max_leases: usize,
    },
    /// Set the identity approval mode.
    SetApprovalMode {
        /// Approval mode to apply.
        mode: ApprovalMode,
    },
}
