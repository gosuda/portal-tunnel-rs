#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("{0}")]
    InvalidRequest(String),
    #[error("feature unavailable")]
    FeatureUnavailable,
    #[error("hostname conflict")]
    HostnameConflict,
    #[error("lease not found")]
    LeaseNotFound,
    #[error("lease is not approved for routing")]
    LeaseRejected,
    #[error("request denied because source IP is banned")]
    IpBanned,
    #[error("udp disabled")]
    UdpDisabled,
    #[error("udp capacity exceeded")]
    UdpCapacityExceeded,
    #[error("no udp ports available")]
    UdpPortExhausted,
    #[error("tcp port disabled")]
    TcpPortDisabled,
    #[error("no tcp ports available")]
    TcpPortExhausted,
    #[error("tcp port capacity exceeded")]
    TcpPortCapacityExceeded,
    #[error("transport mismatch")]
    TransportMismatch,
    #[error("unauthorized")]
    Unauthorized,
}

impl LeaseError {
    pub fn status_code(&self) -> hyper::StatusCode {
        match self {
            LeaseError::FeatureUnavailable => hyper::StatusCode::SERVICE_UNAVAILABLE,
            LeaseError::HostnameConflict => hyper::StatusCode::CONFLICT,
            LeaseError::LeaseNotFound => hyper::StatusCode::NOT_FOUND,
            LeaseError::LeaseRejected => hyper::StatusCode::FORBIDDEN,
            LeaseError::IpBanned => hyper::StatusCode::FORBIDDEN,
            LeaseError::UdpDisabled => hyper::StatusCode::FORBIDDEN,
            LeaseError::UdpCapacityExceeded => hyper::StatusCode::SERVICE_UNAVAILABLE,
            LeaseError::UdpPortExhausted => hyper::StatusCode::SERVICE_UNAVAILABLE,
            LeaseError::TcpPortDisabled => hyper::StatusCode::FORBIDDEN,
            LeaseError::TcpPortExhausted => hyper::StatusCode::SERVICE_UNAVAILABLE,
            LeaseError::TcpPortCapacityExceeded => hyper::StatusCode::SERVICE_UNAVAILABLE,
            LeaseError::TransportMismatch => hyper::StatusCode::CONFLICT,
            LeaseError::Unauthorized => hyper::StatusCode::FORBIDDEN,
            LeaseError::InvalidRequest(_) => hyper::StatusCode::BAD_REQUEST,
        }
    }

    pub fn api_code(&self) -> &'static str {
        match self {
            LeaseError::FeatureUnavailable => "feature_unavailable",
            LeaseError::HostnameConflict => "hostname_conflict",
            LeaseError::LeaseNotFound => "lease_not_found",
            LeaseError::LeaseRejected => "lease_rejected",
            LeaseError::IpBanned => "ip_banned",
            LeaseError::UdpDisabled => "udp_disabled",
            LeaseError::UdpCapacityExceeded => "udp_capacity_exceeded",
            LeaseError::UdpPortExhausted => "udp_port_exhausted",
            LeaseError::TcpPortDisabled => "tcp_port_disabled",
            LeaseError::TcpPortExhausted => "tcp_port_exhausted",
            LeaseError::TcpPortCapacityExceeded => "tcp_port_capacity_exceeded",
            LeaseError::TransportMismatch => "transport_mismatch",
            LeaseError::Unauthorized => "unauthorized",
            LeaseError::InvalidRequest(_) => "invalid_request",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupStats {
    pub challenges: usize,
    pub leases: usize,
    pub hop_routes: usize,
}

impl CleanupStats {
    pub fn is_empty(self) -> bool {
        self.challenges == 0 && self.leases == 0 && self.hop_routes == 0
    }
}
