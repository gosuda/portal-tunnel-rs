/// JWT algorithm for relay lease tokens (ES256K = secp256k1 ECDSA + SHA-256).
/// Tokens signed with any other algorithm MUST be rejected.
pub const LEASE_TOKEN_ALG: &str = "ES256K";
/// JWT claim field names — must match Go jwt.go exactly.
pub const CLAIM_SUB: &str = "sub";
pub const CLAIM_ISS: &str = "iss";
pub const CLAIM_EXP: &str = "exp";
pub const CLAIM_IAT: &str = "iat";
pub const CLAIM_JTI: &str = "jti";
