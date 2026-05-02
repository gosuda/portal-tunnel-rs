// PRE: token verified by verify_token. INVARIANT: admit_connect returns the same RelayStream Arc the lease was registered with — never a clone of the descriptor.

use std::sync::Arc;

use chrono::Utc;

use crate::auth::lease_token::{LeaseAccessTokenClaims, verify_lease_access_token};
use crate::relay::stream::RelayStream;
use crate::relay::udp_datagram::UdpDatagramRuntime;

use super::{LeaseError, LeaseRegistry};

impl LeaseRegistry {
    pub fn admit_connect(&self, token: &str) -> Result<Arc<RelayStream>, LeaseError> {
        let claims = self.verify_token(token)?;
        let now = Utc::now();
        let inner = self.inner.lock().expect("lease registry lock poisoned");
        let lease = inner
            .leases
            .get(&claims.identity.key())
            .ok_or(LeaseError::LeaseNotFound)?;
        if lease.expires_at <= now {
            return Err(LeaseError::LeaseNotFound);
        }
        if !self
            .policy
            .is_identity_routable(&claims.identity.key(), &lease.client_ip)
        {
            return Err(LeaseError::LeaseRejected);
        }
        Ok(Arc::clone(&lease.stream))
    }

    pub fn admit_datagram(&self, token: &str) -> Result<Arc<UdpDatagramRuntime>, LeaseError> {
        let claims = self.verify_token(token)?;
        let now = Utc::now();
        let inner = self.inner.lock().expect("lease registry lock poisoned");
        let lease = inner
            .leases
            .get(&claims.identity.key())
            .ok_or(LeaseError::LeaseNotFound)?;
        if lease.expires_at <= now {
            return Err(LeaseError::LeaseNotFound);
        }
        if !self
            .policy
            .is_identity_routable(&claims.identity.key(), &lease.client_ip)
        {
            return Err(LeaseError::LeaseRejected);
        }
        lease
            .udp_runtime
            .as_ref()
            .map(Arc::clone)
            .ok_or(LeaseError::TransportMismatch)
    }

    pub fn verify_token(&self, token: &str) -> Result<LeaseAccessTokenClaims, LeaseError> {
        verify_lease_access_token(token, &self.relay, &self.issuer, Utc::now())
            .map_err(|_| LeaseError::Unauthorized)
    }
}
