# Portal Tunnel Rust Porting Plan

이 문서는 기존 Go 릴레이 서버를 Rust로 재작성하기 위한 실행 계획이다.
목표는 새 구현이 기존 Go SDK/CLI와 완전히 호환되는 릴레이 서버가 되는
것이며, 작업 산출물은 모두 `portal-tunnel-rs` 레포 내부에 둔다.

기준 분석 문서: `docs/existing-system-analysis.md`

## 목표

1. 기존 Go SDK/CLI를 수정하지 않고 Rust 릴레이에 연결할 수 있어야 한다.
2. HTTPS 터널 경로에서 릴레이는 tenant TLS를 종료하지 않고 SNI만 읽어야 한다.
3. `/sdk/*`, `/sdk/connect`, `/v1/sign`, marker byte, JWT, SIWE 계약은 기존 Go
   구현과 호환되어야 한다.
4. 초기 구현은 최소 호환 릴레이를 먼저 완성하고, UDP/TCP port, discovery,
   multi-hop, admin, ACME는 단계적으로 붙인다.

## 비목표

초기 단계에서 아래는 바로 구현하지 않는다.

- Admin frontend 전체 이식
- Managed ACME DNS provider 자동화
- WireGuard overlay와 multi-hop
- UDP QUIC DATAGRAM
- Dedicated raw TCP port transport
- Thumbnail, installer, release asset serving

이 기능들은 core HTTPS tunnel path가 기존 클라이언트와 호환됨을 확인한 뒤
추가한다.

## 기본 원칙

- Go SDK/CLI 동작을 public contract로 본다.
- Go 내부 패키지 구조를 그대로 옮기지 않고, Rust에서 단순한 소유 경계를 둔다.
- API 응답, path, error code, marker byte, token shape은 테스트 fixture로 고정한다.
- Rust 구현이 Go 구현보다 먼저 추상화되지 않도록 한다.
- 각 단계는 기존 Go 클라이언트로 검증 가능한 완료 기준을 가진다.

## 권장 레포 구조

```text
portal-tunnel-rs/
  Cargo.toml
  crates/
    portal-relay/
      Cargo.toml
      src/
        main.rs
        config.rs
        api/
          mod.rs
          envelope.rs
          sdk.rs
          keyless.rs
        auth/
          mod.rs
          identity.rs
          siwe.rs
          lease_token.rs
        relay/
          mod.rs
          server.rs
          leases.rs
          stream.rs
          sni.rs
          bridge.rs
        state/
          mod.rs
          identity.rs
          tls_material.rs
        policy/
          mod.rs
    portal-compat-tests/
      Cargo.toml
      tests/
        fixtures.rs
        api_contract.rs
        token_contract.rs
        stream_contract.rs
  docs/
    existing-system-analysis.md
    porting-plan.md
  fixtures/
    go/
      api/
      crypto/
      wire/
```

초기에는 `portal-relay` 하나만 만들어도 된다. 다만 fixture와 통합 테스트가
커질 가능성이 높으므로 `portal-compat-tests`는 별도 crate로 분리할 수 있게
여지를 둔다.

## Phase 0: Contract Fixture 확보

목적: Rust 구현 전에 호환성 기준을 데이터로 고정한다.

작업:

- Go 구현에서 대표 JSON request/response fixture를 추출한다.
- `APIEnvelope` 성공/실패 응답 fixture를 만든다.
- `RegisterChallengeRequest`, `RegisterChallengeResponse`, `RegisterRequest`,
  `RegisterResponse`, `RenewRequest`, `RenewResponse`, `UnregisterRequest` fixture를
  만든다.
- keyless `/v1/sign` request/response fixture를 만든다.
- datagram frame encoding fixture를 만든다.
- Go에서 발급한 ES256K lease JWT를 Rust에서 검증하는 fixture를 만든다.
- Rust에서 발급할 JWT가 Go 검증 코드에서 통과하는지 확인하는 역방향 테스트를
  준비한다.
- SIWE message와 signature fixture를 만든다.

완료 기준:

- fixture가 `fixtures/go/` 아래에 저장되어 있다.
- Rust test scaffold에서 fixture를 읽을 수 있다.
- 아직 relay server가 없어도 serialization/crypto 계약 테스트를 작성할 수 있다.

리스크:

- ES256K JWT는 JWS signing input, header, raw 64-byte signature format이 조금만
  달라도 깨진다.
- SIWE는 domain, URI, nonce, issued/expiration time이 기존 SDK와 정확히 맞아야 한다.

## Phase 1: Rust Workspace와 최소 API 서버

목적: HTTPS HTTP/1.1 API listener를 띄우고 기존 SDK의 compatibility probe를 통과한다.

작업:

- Cargo workspace를 만든다.
- `portal-relay` binary crate를 만든다.
- config parser를 추가한다.
  - `PORTAL_URL`
  - `IDENTITY_PATH`
  - `API_PORT`
  - `SNI_PORT`
  - `UDP_ENABLED`
  - `TCP_ENABLED`
  - `MIN_PORT`
  - `MAX_PORT`
- relay identity 파일을 load/create한다.
- manual/local TLS material을 load/create한다.
- API TLS listener를 HTTP/1.1 only로 띄운다.
- API envelope helper를 구현한다.
- `/healthz`를 구현한다.
- `/sdk/domain`을 구현한다.
  - `protocol_version = "6"`
  - `release_version`은 기존 값 또는 Rust 릴레이 버전 정책을 명확히 정한다.
  - CORS `Access-Control-Allow-Origin: *`를 유지한다.

완료 기준:

- `cargo test`가 통과한다.
- Rust relay 실행 후 `GET /healthz`가 envelope로 응답한다.
- 기존 Go SDK의 `/sdk/domain` compatibility check가 통과한다.

권장 Rust crate:

- `tokio`
- `axum` 또는 `hyper`
- `rustls`
- `tokio-rustls`
- `serde`
- `serde_json`
- `clap`
- `tracing`
- `thiserror`

주의:

- `/sdk/connect` 때문에 HTTP/2를 기본 활성화하면 안 된다.
- high-level framework를 쓰더라도 raw connection upgrade가 가능한지 Phase 1에서
  검증해야 한다.

## Phase 2: Identity, SIWE, Lease Token

목적: lease lifecycle의 crypto contract를 맞춘다.

작업:

- Identity normalization을 구현한다.
  - DNS label normalization
  - EVM address normalization
  - `Identity.Key()` 생성
  - lease hostname 생성
- relay identity state format을 Go와 호환되게 구현한다.
  - `identity.json`
  - secp256k1 private/public key
  - EVM address
  - admin secret key
- SIWE challenge 생성을 구현한다.
  - statement: `Register a portal lease`
  - chain id: `1`
  - request id: `rch_...`
  - URI: request host + `/sdk/register`
  - TTL: 2분
- SIWE signature verification을 구현한다.
- ES256K JWT 발급과 검증을 구현한다.
  - `alg = ES256K`
  - `typ = JWT`
  - `aud = portal-sdk`
  - `iss = normalized PORTAL_URL`
  - `sub = Identity.Key()`
  - JWS `kid = relay identity address`
  - raw 64-byte secp256k1 signature

완료 기준:

- Go fixture JWT를 Rust가 검증한다.
- Rust JWT를 Go 검증 코드가 검증한다.
- Go SDK가 Rust relay의 register challenge를 서명할 수 있다.
- Rust relay가 Go SDK의 register signature를 검증한다.

권장 Rust crate 후보:

- `k256`
- `sha2`
- `sha3`
- `hex`
- `base64`
- `jsonwebtoken`은 ES256K raw format 제어가 어려울 수 있으므로 직접 JWS 처리도 검토
- SIWE는 crate 채택 전 fixture 기반 호환성 검증 필요

주의:

- Ethereum address는 secp256k1 public key의 Keccak-256 기반이다.
- Ethereum personal-sign prefix 처리를 정확히 맞춰야 한다.
- JWT library가 ES256K를 지원하더라도 signature encoding이 Go 구현과 다를 수 있다.

## Phase 3: Lease Registry와 `/sdk/*` Lifecycle

목적: 기존 Go SDK가 Rust relay에 lease를 등록, 갱신, 해제할 수 있게 한다.

작업:

- in-memory lease registry를 구현한다.
- pending register challenge 저장을 구현한다.
- pending challenge per IP limit 32를 구현한다.
- lease TTL 기본값 30초를 구현한다.
- registry janitor를 구현한다.
- hostname conflict check를 구현한다.
- `POST /sdk/register/challenge`를 구현한다.
- `POST /sdk/register`를 구현한다.
- `POST /sdk/renew`를 구현한다.
- `POST /sdk/unregister`를 구현한다.
- error code와 status code를 기존과 맞춘다.

완료 기준:

- 기존 Go SDK가 Rust relay에 register 성공한다.
- lease가 30초 뒤 만료되고 cleanup된다.
- renew가 새 access token과 expiry를 반환한다.
- unregister가 lease와 sessions를 제거한다.

초기 단순화:

- policy는 auto approval만 구현한다.
- UDP/TCP request는 feature unavailable 또는 disabled로 명확히 거절한다.
- multi-hop `hop_token`은 초기에는 unsupported path로 처리한다.

주의:

- 기존 SDK는 특정 API error code를 보고 relay를 incompatible 또는 unavailable로 판단한다.
- `feature_unavailable`, `transport_mismatch`, `hostname_conflict`,
  `unauthorized`, `lease_not_found`는 우선순위 높게 맞춘다.

## Phase 4: Reverse Session `/sdk/connect`

목적: SDK가 reverse session pool을 유지할 수 있게 한다.

작업:

- `/sdk/connect`를 HTTP/1.1 only로 제한한다.
- `X-Portal-Access-Token` 검증을 구현한다.
- 성공 시 아래 response를 쓴 뒤 raw stream으로 전환한다.

```http
HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

```

- per-lease ready queue를 구현한다.
- ready queue limit 8을 구현한다.
- idle keepalive `0x00`를 15초마다 쓴다.
- claim 시 keepalive를 중단하고 activation marker를 쓴다.
- session close와 lease cleanup을 연결한다.

완료 기준:

- Go SDK가 reverse session을 열고 idle 상태를 유지한다.
- SDK가 `0x00` keepalive를 정상 처리한다.
- queue 초과 시 새 session이 닫힌다.
- token이 틀리면 envelope error로 거절된다.

주의:

- HTTP response 이후 남은 buffered bytes가 있으면 raw stream에 보존되어야 한다.
- framework upgrade API가 HTTP/1.1 response shape을 임의로 바꾸지 않는지 확인해야 한다.

## Phase 5: SNI Listener와 TLS Passthrough

목적: public HTTPS ingress를 기존 relay와 동일하게 동작시킨다.

작업:

- SNI TCP listener를 구현한다.
- TLS ClientHello peek를 구현한다.
- peek한 bytes를 bridge 대상 stream에 replay할 수 있는 wrapper를 만든다.
- hostname normalization을 구현한다.
- lookup 순서를 구현한다.
  1. exact hostname
  2. one-level wildcard
  3. root host API fallback
  4. close
- normal lease route에서 reverse session claim을 구현한다.
- claim timeout 10초를 구현한다.
- TLS route claim 시 `0x02`를 쓴다.
- bidirectional bridge를 구현한다.
- 가능한 경우 half-close를 구현한다.

완료 기준:

- Go SDK가 등록한 hostname으로 public TLS client가 접속할 수 있다.
- Rust relay가 tenant TLS plaintext를 보지 않고 byte bridge만 수행한다.
- SNI root host는 API listener로 fallback된다.
- wildcard는 one-level만 match한다.

검증:

- Go SDK `portal expose` 또는 SDK integration으로 local HTTP app을 노출한다.
- public hostname에 HTTPS request를 보내 응답을 받는다.
- Go SDK MITM self-probe가 실패하지 않는다.

주의:

- SNI peek timeout은 기존처럼 2초 수준으로 둔다.
- ClientHello parser가 incomplete packet을 잘 처리해야 한다.
- bridge 양방향 close 순서가 잘못되면 TLS client가 hang될 수 있다.

## Phase 6: Keyless `/v1/sign`

목적: Go SDK tenant TLS handshake가 Rust relay의 keyless signing으로 완료되게 한다.

작업:

- `/v1/sign` endpoint를 API envelope 없이 구현한다.
- key id `relay-cert`를 지원한다.
- request timestamp skew 30초를 검증한다.
- digest와 algorithm에 맞게 relay certificate private key로 sign한다.
- ECDSA certificate 기준 `ECDSA_SHA256`을 우선 지원한다.
- 필요 시 ECDSA SHA-384/512, RSA PKCS#1, RSA-PSS를 추가한다.

완료 기준:

- Go SDK가 Rust relay certificate chain을 fetch한다.
- Go SDK가 `/v1/sign`을 호출한다.
- tenant TLS handshake가 성공한다.
- public HTTPS request가 end-to-end로 성공한다.

주의:

- 이 endpoint는 `APIEnvelope`를 쓰지 않는다.
- Go JSON byte slice는 base64 string으로 encode된다.
- signature 형식은 Rust TLS signer가 아니라 Go keyless client가 기대하는 형식이어야 한다.

## Phase 7: Core Compatibility Gate

목적: 최소 HTTPS tunnel 릴레이를 완료 상태로 고정한다.

필수 시나리오:

1. Rust relay를 local cert로 실행한다.
2. 기존 Go CLI 또는 SDK로 lease를 등록한다.
3. Go SDK가 reverse sessions를 유지한다.
4. public TLS client가 SNI listener로 들어온다.
5. Rust relay가 `0x02` marker를 쓰고 bridge한다.
6. SDK-side tenant TLS가 `/v1/sign`을 통해 handshake를 완료한다.
7. local service response가 public client에 도달한다.
8. renew가 정상 동작한다.
9. unregister 또는 process shutdown이 sessions를 정리한다.

이 gate를 통과하기 전에는 UDP/TCP/discovery/admin 구현을 시작하지 않는다.

## Phase 8: Raw TCP Port Transport

목적: non-TLS TCP exposure를 지원한다.

작업:

- `TCP_ENABLED`, `MIN_PORT`, `MAX_PORT` config를 활성화한다.
- port allocator와 5분 sticky reservation을 구현한다.
- register에서 `tcp_enabled=true`를 처리한다.
- lease별 TCP listener를 만든다.
- external TCP connection에서 reverse session을 claim한다.
- `0x01` marker를 쓴 뒤 raw bridge한다.

완료 기준:

- Go SDK가 `tcp_enabled` lease를 등록한다.
- register response에 `tcp_addr`가 포함된다.
- external raw TCP client가 local TCP service와 통신한다.

## Phase 9: UDP QUIC DATAGRAM Transport

목적: raw UDP exposure를 지원한다.

작업:

- QUIC listener를 SNI UDP port에 띄운다.
- ALPN `portal-tunnel`을 설정한다.
- QUIC DATAGRAM을 활성화한다.
- first stream control message `{ "access_token": "..." }`를 처리한다.
- UDP lease port를 할당하고 listener를 만든다.
- flow id table을 구현한다.
- datagram frame `[flow_id uvarint][payload]` encoding을 구현한다.
- flow idle timeout 30초를 구현한다.

완료 기준:

- Go SDK가 QUIC backhaul을 연결한다.
- public UDP client packet이 local UDP service까지 전달된다.
- local UDP response가 원래 public UDP client로 돌아간다.

## Phase 10: Admin and Policy Parity

목적: 운영 중 릴레이 제어 기능을 맞춘다.

작업:

- admin auth session을 구현한다.
- `portal_admin` cookie semantics를 맞춘다.
- approval mode를 구현한다.
- identity approve/revoke/deny/ban을 구현한다.
- IP ban을 구현한다.
- UDP/TCP admin settings를 구현한다.
- BPS throttling을 구현한다.
- `admin_settings.json` persistence를 구현한다.
- `PublicLeases`와 `AdminLeases` response를 맞춘다.

완료 기준:

- 기존 frontend 또는 API client가 admin snapshot을 정상 읽는다.
- manual approval mode에서 승인 전 routing이 막히고 승인 후 열린다.
- ban/deny/IP ban이 register/routing에 반영된다.

## Phase 11: Discovery, Relay Descriptor, Multi-Hop

목적: public relay mesh와 multi-hop을 지원한다.

작업:

- relay descriptor canonical bytes를 구현한다.
- recoverable secp256k1 descriptor signature를 구현한다.
- `/discovery`를 구현한다.
- `/discovery/announce`를 구현한다.
- relay set refresh policy를 구현한다.
- hop route canonical bytes와 DER signature verification을 구현한다.
- `/sdk/hop`을 구현한다.
- WireGuard overlay와 HopMux 대체 구현을 설계한다.

완료 기준:

- Go relay와 Rust relay가 서로 discovery descriptor를 검증한다.
- Go SDK multi-hop route sync가 Rust relay에 성공한다.
- Rust relay가 entry/middle/exit 역할 중 최소 하나를 기존 Go relay와 상호 운용한다.

주의:

- WireGuard overlay는 가장 큰 독립 리스크다. 별도 design doc을 먼저 작성한다.

## Phase 12: ACME, Frontend, Release Operations

목적: Go relay 운영 기능과 배포 경험을 맞춘다.

작업:

- manual cert path를 완성한다.
- local development cert path를 완성한다.
- Cloudflare/GCP/Route53 ACME DNS-01 자동화를 검토한다.
- frontend static serving을 구현하거나 별도 artifact serving 전략을 정한다.
- install script/bin endpoint를 구현할지 결정한다.
- Dockerfile과 docker-compose 호환성을 맞춘다.
- release packaging을 정한다.

완료 기준:

- 기존 deployment 환경에서 Go relay 대신 Rust relay를 배포할 수 있다.
- required env vars와 exposed ports가 기존 compose와 호환된다.

## Test Matrix

| 영역 | 테스트 |
| --- | --- |
| API envelope | success/error JSON fixture roundtrip |
| API paths | method mismatch, invalid JSON, status/error code |
| Identity | DNS label, EVM address, hostname generation |
| SIWE | Go signed message verification in Rust |
| JWT | Go token verify in Rust, Rust token verify in Go |
| Reverse session | connect, keepalive, queue limit, marker write |
| SNI | exact, wildcard, root fallback, no route close |
| Bridge | bidirectional copy, half-close, timeout cleanup |
| Keyless | sign request, timestamp skew, tenant TLS handshake |
| TCP port | port allocation, sticky reservation, raw marker |
| UDP | QUIC control stream, DATAGRAM codec, flow cleanup |
| Admin | auth cookie, approval, ban, snapshot |
| Discovery | descriptor canonical bytes, signature recovery |

## Milestone Definition

| Milestone | Deliverable |
| --- | --- |
| M0 | Fixture and test harness committed |
| M1 | Rust relay serves `/healthz` and `/sdk/domain` over HTTPS HTTP/1.1 |
| M2 | Register/renew/unregister with SIWE and ES256K JWT |
| M3 | `/sdk/connect` reverse session queue and keepalive |
| M4 | SNI TLS passthrough bridge with `0x02` marker |
| M5 | `/v1/sign` and successful Go SDK HTTPS tunnel |
| M6 | Raw TCP port transport |
| M7 | UDP QUIC DATAGRAM transport |
| M8 | Admin/policy parity |
| M9 | Discovery and multi-hop parity |
| M10 | ACME/frontend/deployment parity |

## Immediate Next Steps

1. Create Cargo workspace and `portal-relay` binary crate.
2. Add fixture directory and a small Go fixture generator under `fixtures/go/`.
3. Implement API envelope types and `/sdk/domain`.
4. Add identity normalization and relay identity state reader/writer.
5. Start ES256K JWT interoperability tests before building the full register API.

The first implementation PR should stop at M1 plus enough fixture scaffolding to
make M2 development measurable.
