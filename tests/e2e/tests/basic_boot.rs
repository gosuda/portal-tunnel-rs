//! Basic boot test — verifies the e2e harness can start the relay
//! admin router and the demo target, and that both respond to
//! simple HTTP requests.

use e2e::{Harness, http_get};

#[tokio::test]
async fn admin_health_returns_200() {
    let harness = Harness::boot().await;
    let addr = harness.admin_addr().to_string();
    let result = http_get(&addr, "/v1/admin/health").await;
    harness.shutdown().await;
    let (status, body) = match result {
        Ok(v) => v,
        Err(e) => panic!("http_get admin health failed: {e}"),
    };
    assert_eq!(status, 200, "admin health status: {status}, body: {body}");
}

#[tokio::test]
async fn demo_echo_responds() {
    let harness = Harness::boot().await;
    let addr = harness.demo_addr().to_string();
    let result = http_get(&addr, "/").await;
    harness.shutdown().await;
    let (status, body) = match result {
        Ok(v) => v,
        Err(e) => panic!("http_get demo echo failed: {e}"),
    };
    assert_eq!(status, 200, "demo echo status: {status}, body: {body}");
}
