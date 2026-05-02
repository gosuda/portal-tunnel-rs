use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ApiEnvelope<T>
where
    T: Serialize,
{
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
    pub ok: bool,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

pub fn api_ok<T>(data: &T) -> ApiEnvelope<&T>
where
    T: Serialize,
{
    ApiEnvelope {
        data: Some(data),
        error: None,
        ok: true,
    }
}

#[must_use]
pub fn api_error(code: &str, message: &str) -> ApiEnvelope<()> {
    ApiEnvelope {
        data: None,
        error: Some(ApiError {
            code: code.to_string(),
            message: message.to_string(),
        }),
        ok: false,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn serializes_success_like_go_api_envelope() {
        let value = serde_json::to_value(api_ok(&json!({"status": "ok"}))).unwrap();
        assert_eq!(value, json!({"data": {"status": "ok"}, "ok": true}));
    }

    #[test]
    fn serializes_error_like_go_api_envelope() {
        let value = serde_json::to_value(api_error("invalid_json", "bad json")).unwrap();
        assert_eq!(
            value,
            json!({
                "error": {
                    "code": "invalid_json",
                    "message": "bad json"
                },
                "ok": false
            })
        );
    }
}
