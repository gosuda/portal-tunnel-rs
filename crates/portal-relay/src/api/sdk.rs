use serde::Serialize;

pub const SDK_VERSION: &str = "6";
pub const RELEASE_VERSION: &str = "v2.1.8-rs.dev6";

#[derive(Debug, Serialize)]
pub struct DomainResponse {
    pub protocol_version: &'static str,
    pub release_version: &'static str,
}
