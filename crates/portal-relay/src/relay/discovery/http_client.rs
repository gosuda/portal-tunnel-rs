// INVARIANT: every response is decoded as ApiEnvelope<T>; raw bodies are rejected.

use anyhow::{Context, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

use super::{
    DiscoveryAnnounceRequest, DiscoveryAnnounceResponse, DiscoveryResponse, DiscoveryState,
};
use crate::wire::paths::{PATH_DISCOVERY, PATH_DISCOVERY_ANNOUNCE};

use super::DISCOVERY_VERSION;

#[derive(Debug, Deserialize)]
struct ApiEnvelopeResponse<T> {
    data: Option<T>,
    error: Option<ApiEnvelopeError>,
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct ApiEnvelopeError {
    code: String,
    message: String,
}

async fn decode_envelope<T>(resp: reqwest::Response) -> anyhow::Result<T>
where
    T: DeserializeOwned,
{
    let envelope = resp
        .json::<ApiEnvelopeResponse<T>>()
        .await
        .context("decode api envelope")?;
    if envelope.ok {
        return envelope.data.context("api envelope missing data");
    }
    let message = envelope.error.map_or_else(
        || "api request failed".to_string(),
        |err| format!("{}: {}", err.code, err.message),
    );
    bail!(message)
}

pub(super) fn api_url(relay_url: &str, path: &str) -> anyhow::Result<String> {
    let mut url =
        Url::parse(relay_url.trim()).with_context(|| format!("parse relay url {relay_url:?}"))?;
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

impl DiscoveryState {
    pub(super) async fn fetch_discovery(
        &self,
        relay_url: &str,
    ) -> anyhow::Result<DiscoveryResponse> {
        let url = api_url(relay_url, PATH_DISCOVERY)?;
        self.get_enveloped(&url).await
    }

    pub(super) async fn announce_self(
        &self,
        relay_url: &str,
        descriptor: &super::descriptor::RelayDescriptor,
    ) -> anyhow::Result<()> {
        let url = api_url(relay_url, PATH_DISCOVERY_ANNOUNCE)?;
        let req = DiscoveryAnnounceRequest {
            protocol_version: DISCOVERY_VERSION.to_string(),
            descriptor: descriptor.clone(),
        };
        let _: DiscoveryAnnounceResponse = self.post_enveloped(&url, &req).await?;
        Ok(())
    }

    pub(super) async fn get_enveloped<T>(&self, url: &str) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
    {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("GET {url} status"))?;
        decode_envelope(resp).await
    }

    pub(super) async fn post_enveloped<T, B>(&self, url: &str, body: &B) -> anyhow::Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let resp = self
            .client
            .post(url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?
            .error_for_status()
            .with_context(|| format!("POST {url} status"))?;
        decode_envelope(resp).await
    }
}
