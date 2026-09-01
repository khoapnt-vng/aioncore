use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use aionui_api_types::{
    SESSION_MCP_RESOLVER_PROFILE_V1, SessionMcpServer, SessionMcpTrustClaim, SessionMcpTrustSnapshot,
    session_mcp_server_fingerprint,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

pub const SESSION_MCP_TRUST_KEY_ENV: &str = "AIONUI_SESSION_MCP_TRUST_KEY";

const TRUST_AUDIENCE: &str = "aioncore.session-mcp-trust";
const TRUST_VERSION: u8 = 1;
const MAX_CLAIMS: usize = 16;
const MAX_PAYLOAD_BYTES: usize = 4_096;
const MAX_CONSUMED_NONCES: usize = 4_096;
const NONCE_BYTES: usize = 16;
const SIGNATURE_BYTES: usize = 32;
const MAX_CLAIM_LIFETIME_MS: i64 = 120_000;
const MAX_FUTURE_SKEW_MS: i64 = 30_000;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SessionMcpTrustError {
    #[error("too many session MCP trust claims")]
    TooManyClaims,
    #[error("malformed session MCP trust claim")]
    Malformed,
    #[error("invalid session MCP trust signature")]
    InvalidSignature,
    #[error("invalid session MCP trust audience")]
    InvalidAudience,
    #[error("session MCP trust claim is not yet valid")]
    NotYetValid,
    #[error("session MCP trust claim expired")]
    Expired,
    #[error("session MCP trust claim lifetime is invalid")]
    InvalidLifetime,
    #[error("session MCP trust claim does not identify one exact server")]
    ServerMismatch,
    #[error("duplicate session MCP trust claim")]
    Duplicate,
    #[error("session MCP trust claim was already consumed")]
    Replay,
    #[error("session MCP trust authority is unavailable")]
    AuthorityUnavailable,
    #[error("session MCP trust replay ledger is at capacity")]
    ReplayLedgerAtCapacity,
}

impl SessionMcpTrustError {
    pub(crate) fn diagnostic_class(self) -> &'static str {
        match self {
            Self::TooManyClaims => "too_many_claims",
            Self::Malformed => "malformed",
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidAudience => "invalid_audience",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::InvalidLifetime => "invalid_lifetime",
            Self::ServerMismatch => "server_mismatch",
            Self::Duplicate => "duplicate",
            Self::Replay => "replay",
            Self::AuthorityUnavailable => "authority_unavailable",
            Self::ReplayLedgerAtCapacity => "replay_ledger_at_capacity",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustPayload {
    version: u8,
    audience: String,
    server_id: String,
    server_fingerprint: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
    nonce: String,
}

#[derive(Clone)]
pub struct SessionMcpTrustAuthority {
    key: [u8; 32],
    replay_ledger: Arc<Mutex<ReplayLedger>>,
}

#[derive(Default)]
struct ReplayLedger {
    consumed_nonces: HashMap<[u8; NONCE_BYTES], i64>,
    high_water_now_ms: i64,
}

/// Decode the backend-owned database column. Corrupt or non-canonical
/// snapshots never become runtime authority: callers treat an error as an
/// empty trust set.
pub(crate) fn decode_verified_session_mcp_trust(
    raw: Option<&str>,
) -> Result<Vec<SessionMcpTrustSnapshot>, SessionMcpTrustError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let snapshots: Vec<SessionMcpTrustSnapshot> =
        serde_json::from_str(raw).map_err(|_| SessionMcpTrustError::Malformed)?;
    if snapshots.len() > MAX_CLAIMS {
        return Err(SessionMcpTrustError::TooManyClaims);
    }
    let mut server_ids = HashSet::with_capacity(snapshots.len());
    for snapshot in &snapshots {
        if snapshot.server_id.is_empty()
            || !is_lower_hex_sha256(&snapshot.server_fingerprint)
            || snapshot.resolver_profile != SESSION_MCP_RESOLVER_PROFILE_V1
            || !server_ids.insert(snapshot.server_id.as_str())
        {
            return Err(SessionMcpTrustError::Malformed);
        }
    }
    Ok(snapshots)
}

impl SessionMcpTrustAuthority {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            replay_ledger: Arc::new(Mutex::new(ReplayLedger::default())),
        }
    }

    /// Verify all supplied claims first, then consume every nonce as one atomic
    /// step. A malformed member therefore cannot burn an otherwise valid claim.
    pub(crate) fn authenticate_claims(
        &self,
        claims: &[SessionMcpTrustClaim],
        servers: &[SessionMcpServer],
        now_ms: i64,
    ) -> Result<Vec<SessionMcpTrustSnapshot>, SessionMcpTrustError> {
        if claims.len() > MAX_CLAIMS {
            return Err(SessionMcpTrustError::TooManyClaims);
        }

        // Wall clock can jump forward and then roll back. Keep a monotonic
        // in-process high-water mark so cleanup never makes an old signed
        // claim valid again after its nonce has been evicted.
        let mut ledger = self
            .replay_ledger
            .lock()
            .map_err(|_| SessionMcpTrustError::AuthorityUnavailable)?;
        let effective_now_ms = ledger.high_water_now_ms.max(now_ms);
        ledger.high_water_now_ms = effective_now_ms;

        let mut pending = Vec::with_capacity(claims.len());
        let mut server_ids = HashSet::with_capacity(claims.len());
        let mut batch_nonces = HashSet::with_capacity(claims.len());
        for claim in claims {
            let verified = self.verify_claim(claim, servers, effective_now_ms)?;
            if !server_ids.insert(verified.snapshot.server_id.clone()) || !batch_nonces.insert(verified.nonce) {
                return Err(SessionMcpTrustError::Duplicate);
            }
            pending.push(verified);
        }

        ledger
            .consumed_nonces
            .retain(|_, expires_at_ms| *expires_at_ms > effective_now_ms);
        if pending
            .iter()
            .any(|verified| ledger.consumed_nonces.contains_key(&verified.nonce))
        {
            return Err(SessionMcpTrustError::Replay);
        }
        if ledger.consumed_nonces.len().saturating_add(pending.len()) > MAX_CONSUMED_NONCES {
            return Err(SessionMcpTrustError::ReplayLedgerAtCapacity);
        }
        for verified in &pending {
            ledger.consumed_nonces.insert(verified.nonce, verified.expires_at_ms);
        }

        Ok(pending.into_iter().map(|verified| verified.snapshot).collect())
    }

    fn verify_claim(
        &self,
        claim: &SessionMcpTrustClaim,
        servers: &[SessionMcpServer],
        now_ms: i64,
    ) -> Result<VerifiedClaim, SessionMcpTrustError> {
        if claim.payload.len() > max_base64url_len(MAX_PAYLOAD_BYTES) {
            return Err(SessionMcpTrustError::Malformed);
        }
        let payload_bytes = decode_canonical_base64url(&claim.payload, None)?;
        if payload_bytes.is_empty() || payload_bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(SessionMcpTrustError::Malformed);
        }
        let signature = decode_canonical_base64url(&claim.signature, Some(SIGNATURE_BYTES))?;

        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| SessionMcpTrustError::AuthorityUnavailable)?;
        mac.update(&payload_bytes);
        mac.verify_slice(&signature)
            .map_err(|_| SessionMcpTrustError::InvalidSignature)?;

        let payload: TrustPayload =
            serde_json::from_slice(&payload_bytes).map_err(|_| SessionMcpTrustError::Malformed)?;
        if payload.version != TRUST_VERSION || payload.audience != TRUST_AUDIENCE {
            return Err(SessionMcpTrustError::InvalidAudience);
        }
        if payload.server_id.is_empty()
            || !is_lower_hex_sha256(&payload.server_fingerprint)
            || !is_safe_timestamp(payload.issued_at_ms)
            || !is_safe_timestamp(payload.expires_at_ms)
        {
            return Err(SessionMcpTrustError::Malformed);
        }
        if payload.expires_at_ms <= payload.issued_at_ms
            || payload.expires_at_ms - payload.issued_at_ms > MAX_CLAIM_LIFETIME_MS
        {
            return Err(SessionMcpTrustError::InvalidLifetime);
        }
        if payload.issued_at_ms > now_ms.saturating_add(MAX_FUTURE_SKEW_MS) {
            return Err(SessionMcpTrustError::NotYetValid);
        }
        if payload.expires_at_ms <= now_ms {
            return Err(SessionMcpTrustError::Expired);
        }

        let nonce_bytes = decode_canonical_base64url(&payload.nonce, Some(NONCE_BYTES))?;
        let nonce: [u8; NONCE_BYTES] = nonce_bytes.try_into().map_err(|_| SessionMcpTrustError::Malformed)?;

        let mut matches = servers.iter().filter(|server| server.id == payload.server_id);
        let server = matches.next().ok_or(SessionMcpTrustError::ServerMismatch)?;
        if matches.next().is_some() {
            return Err(SessionMcpTrustError::ServerMismatch);
        }
        let actual_fingerprint = session_mcp_server_fingerprint(server);
        if actual_fingerprint != payload.server_fingerprint {
            return Err(SessionMcpTrustError::ServerMismatch);
        }

        Ok(VerifiedClaim {
            snapshot: SessionMcpTrustSnapshot {
                server_id: payload.server_id,
                server_fingerprint: actual_fingerprint,
                resolver_profile: SESSION_MCP_RESOLVER_PROFILE_V1.into(),
            },
            nonce,
            expires_at_ms: payload.expires_at_ms,
        })
    }
}

struct VerifiedClaim {
    snapshot: SessionMcpTrustSnapshot,
    nonce: [u8; NONCE_BYTES],
    expires_at_ms: i64,
}

fn decode_canonical_base64url(value: &str, expected_len: Option<usize>) -> Result<Vec<u8>, SessionMcpTrustError> {
    if value.is_empty()
        || value.contains('=')
        || expected_len.is_some_and(|expected| value.len() != max_base64url_len(expected))
    {
        return Err(SessionMcpTrustError::Malformed);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SessionMcpTrustError::Malformed)?;
    if expected_len.is_some_and(|expected| decoded.len() != expected) || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(SessionMcpTrustError::Malformed);
    }
    Ok(decoded)
}

fn max_base64url_len(byte_len: usize) -> usize {
    byte_len.div_ceil(3) * 4 - usize::from(!byte_len.is_multiple_of(3)) * (3 - byte_len % 3)
}

fn is_safe_timestamp(value: i64) -> bool {
    (0..=MAX_SAFE_INTEGER).contains(&value)
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aionui_api_types::SessionMcpTransport;

    const NOW: i64 = 1_800_000_000_000;
    const KEY: [u8; 32] = [0x42; 32];

    fn server() -> SessionMcpServer {
        SessionMcpServer {
            id: "studio-project-1".into(),
            name: "aionui-creative-studio".into(),
            transport: SessionMcpTransport::Stdio {
                command: "node".into(),
                args: vec!["/app/out/main/builtin-mcp-studio.js".into()],
                env: HashMap::from([
                    ("STUDIO_PROJECT_ID".into(), "project-1".into()),
                    ("UNICODE".into(), "عکس‌های".into()),
                ]),
            },
        }
    }

    fn signed_claim(server: &SessionMcpServer, nonce: [u8; NONCE_BYTES]) -> SessionMcpTrustClaim {
        let payload = serde_json::json!({
            "version": TRUST_VERSION,
            "audience": TRUST_AUDIENCE,
            "server_id": server.id,
            "server_fingerprint": session_mcp_server_fingerprint(server),
            "issued_at_ms": NOW,
            "expires_at_ms": NOW + MAX_CLAIM_LIFETIME_MS,
            "nonce": URL_SAFE_NO_PAD.encode(nonce),
        });
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut mac = HmacSha256::new_from_slice(&KEY).unwrap();
        mac.update(&payload_bytes);
        SessionMcpTrustClaim {
            payload: URL_SAFE_NO_PAD.encode(payload_bytes),
            signature: URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
        }
    }

    fn resign(payload: serde_json::Value) -> SessionMcpTrustClaim {
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut mac = HmacSha256::new_from_slice(&KEY).unwrap();
        mac.update(&payload_bytes);
        SessionMcpTrustClaim {
            payload: URL_SAFE_NO_PAD.encode(payload_bytes),
            signature: URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
        }
    }

    fn decoded_payload(claim: &SessionMcpTrustClaim) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&claim.payload).unwrap()).unwrap()
    }

    #[test]
    fn authenticates_exact_server_and_rejects_replay() {
        let authority = SessionMcpTrustAuthority::new(KEY);
        let server = server();
        let claim = signed_claim(&server, [1; NONCE_BYTES]);

        let snapshots = authority.authenticate_claims(std::slice::from_ref(&claim), std::slice::from_ref(&server), NOW);
        assert_eq!(
            snapshots.unwrap(),
            vec![SessionMcpTrustSnapshot {
                server_id: server.id.clone(),
                server_fingerprint: session_mcp_server_fingerprint(&server),
                resolver_profile: SESSION_MCP_RESOLVER_PROFILE_V1.into(),
            }]
        );
        assert_eq!(
            authority.authenticate_claims(&[claim], &[server], NOW),
            Err(SessionMcpTrustError::Replay)
        );
    }

    #[test]
    fn private_snapshot_decode_is_strict_and_defaults_absent_to_untrusted() {
        assert!(decode_verified_session_mcp_trust(None).unwrap().is_empty());
        let valid = serde_json::to_string(&[SessionMcpTrustSnapshot {
            server_id: "studio-project-1".into(),
            server_fingerprint: "a".repeat(64),
            resolver_profile: SESSION_MCP_RESOLVER_PROFILE_V1.into(),
        }])
        .unwrap();
        assert_eq!(decode_verified_session_mcp_trust(Some(&valid)).unwrap().len(), 1);

        for invalid in [
            "not-json".to_owned(),
            serde_json::json!([{
                "server_id": "studio-project-1",
                "server_fingerprint": "A".repeat(64),
                "resolver_profile": SESSION_MCP_RESOLVER_PROFILE_V1,
            }])
            .to_string(),
            serde_json::json!([
                {"server_id": "duplicate", "server_fingerprint": "a".repeat(64), "resolver_profile": SESSION_MCP_RESOLVER_PROFILE_V1},
                {"server_id": "duplicate", "server_fingerprint": "b".repeat(64), "resolver_profile": SESSION_MCP_RESOLVER_PROFILE_V1},
            ])
            .to_string(),
            serde_json::json!([{
                "server_id": "studio-project-1",
                "server_fingerprint": "a".repeat(64),
                "resolver_profile": SESSION_MCP_RESOLVER_PROFILE_V1,
                "caller_owned": true,
            }])
            .to_string(),
            serde_json::json!([{
                "server_id": "studio-project-1",
                "server_fingerprint": "a".repeat(64),
                "resolver_profile": "aioncore.session-mcp-resolver.v999",
            }])
            .to_string(),
        ] {
            assert_eq!(
                decode_verified_session_mcp_trust(Some(&invalid)),
                Err(SessionMcpTrustError::Malformed)
            );
        }
    }

    #[test]
    fn clock_rollback_never_reopens_a_consumed_claim() {
        let authority = SessionMcpTrustAuthority::new(KEY);
        let server = server();
        let claim = signed_claim(&server, [10; NONCE_BYTES]);

        assert!(
            authority
                .authenticate_claims(std::slice::from_ref(&claim), std::slice::from_ref(&server), NOW)
                .is_ok()
        );
        assert_eq!(
            authority.authenticate_claims(
                std::slice::from_ref(&claim),
                std::slice::from_ref(&server),
                NOW - 10_000
            ),
            Err(SessionMcpTrustError::Replay)
        );

        // Advance beyond expiry so cleanup may evict the nonce, then roll the
        // supplied clock back. The high-water mark keeps the claim expired.
        assert!(
            authority
                .authenticate_claims(&[], std::slice::from_ref(&server), NOW + MAX_CLAIM_LIFETIME_MS)
                .is_ok()
        );
        assert_eq!(
            authority.authenticate_claims(&[claim], &[server], NOW),
            Err(SessionMcpTrustError::Expired)
        );
    }

    #[test]
    fn rejects_forged_signature_before_trusting_payload() {
        let authority = SessionMcpTrustAuthority::new(KEY);
        let server = server();
        let mut claim = signed_claim(&server, [2; NONCE_BYTES]);
        let mut signature = URL_SAFE_NO_PAD.decode(&claim.signature).unwrap();
        signature[0] ^= 1;
        claim.signature = URL_SAFE_NO_PAD.encode(signature);

        assert_eq!(
            authority.authenticate_claims(&[claim], &[server], NOW),
            Err(SessionMcpTrustError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_malformed_and_unknown_payload_fields() {
        let authority = SessionMcpTrustAuthority::new(KEY);
        let server = server();
        let malformed = SessionMcpTrustClaim {
            payload: "not+base64".into(),
            signature: "also-bad".into(),
        };
        assert_eq!(
            authority.authenticate_claims(&[malformed], std::slice::from_ref(&server), NOW),
            Err(SessionMcpTrustError::Malformed)
        );
        let oversized = SessionMcpTrustClaim {
            payload: "A".repeat(max_base64url_len(MAX_PAYLOAD_BYTES) + 1),
            signature: "A".repeat(max_base64url_len(SIGNATURE_BYTES)),
        };
        assert_eq!(
            authority.authenticate_claims(&[oversized], std::slice::from_ref(&server), NOW),
            Err(SessionMcpTrustError::Malformed)
        );

        let claim = signed_claim(&server, [3; NONCE_BYTES]);
        let mut payload = decoded_payload(&claim);
        payload["trusted"] = serde_json::Value::Bool(true);
        assert_eq!(
            authority.authenticate_claims(&[resign(payload)], &[server], NOW),
            Err(SessionMcpTrustError::Malformed)
        );
    }

    #[test]
    fn rejects_expired_and_descriptor_mismatch() {
        let authority = SessionMcpTrustAuthority::new(KEY);
        let server = server();
        let claim = signed_claim(&server, [4; NONCE_BYTES]);
        assert_eq!(
            authority.authenticate_claims(&[claim], std::slice::from_ref(&server), NOW + MAX_CLAIM_LIFETIME_MS),
            Err(SessionMcpTrustError::Expired)
        );

        let authority = SessionMcpTrustAuthority::new(KEY);
        let claim = signed_claim(&server, [5; NONCE_BYTES]);
        let mut changed = server;
        if let SessionMcpTransport::Stdio { env, .. } = &mut changed.transport {
            env.insert("STUDIO_PROJECT_ID".into(), "other-project".into());
        }
        assert_eq!(
            authority.authenticate_claims(&[claim], &[changed], NOW),
            Err(SessionMcpTrustError::ServerMismatch)
        );
    }

    #[test]
    fn invalid_batch_does_not_consume_valid_member() {
        let authority = SessionMcpTrustAuthority::new(KEY);
        let server = server();
        let valid = signed_claim(&server, [6; NONCE_BYTES]);
        let mut forged = signed_claim(&server, [7; NONCE_BYTES]);
        let mut signature = URL_SAFE_NO_PAD.decode(&forged.signature).unwrap();
        signature[0] ^= 1;
        forged.signature = URL_SAFE_NO_PAD.encode(signature);

        assert!(
            authority
                .authenticate_claims(&[valid.clone(), forged], std::slice::from_ref(&server), NOW)
                .is_err()
        );
        assert!(authority.authenticate_claims(&[valid], &[server], NOW).is_ok());
    }

    #[test]
    fn rejects_duplicate_claims_and_invalid_lifetime() {
        let authority = SessionMcpTrustAuthority::new(KEY);
        let server = server();
        let duplicate = signed_claim(&server, [8; NONCE_BYTES]);
        assert_eq!(
            authority.authenticate_claims(&[duplicate.clone(), duplicate], std::slice::from_ref(&server), NOW),
            Err(SessionMcpTrustError::Duplicate)
        );

        let claim = signed_claim(&server, [9; NONCE_BYTES]);
        let mut payload = decoded_payload(&claim);
        payload["expires_at_ms"] = serde_json::Value::from(NOW + MAX_CLAIM_LIFETIME_MS + 1);
        assert_eq!(
            authority.authenticate_claims(&[resign(payload)], &[server], NOW),
            Err(SessionMcpTrustError::InvalidLifetime)
        );
    }

    #[test]
    fn fingerprint_is_map_order_independent_and_transport_sensitive() {
        let first = server();
        let mut second = server();
        if let SessionMcpTransport::Stdio { env, .. } = &mut second.transport {
            let values = env.clone();
            env.clear();
            env.insert("UNICODE".into(), values["UNICODE"].clone());
            env.insert("STUDIO_PROJECT_ID".into(), values["STUDIO_PROJECT_ID"].clone());
        }
        assert_eq!(
            session_mcp_server_fingerprint(&first),
            session_mcp_server_fingerprint(&second)
        );

        second.transport = SessionMcpTransport::Http {
            url: "http://127.0.0.1/studio".into(),
            headers: HashMap::new(),
        };
        assert_ne!(
            session_mcp_server_fingerprint(&first),
            session_mcp_server_fingerprint(&second)
        );
    }

    #[test]
    fn cross_language_golden_vector_is_stable() {
        let server = server();
        assert_eq!(
            session_mcp_server_fingerprint(&server),
            "f00a0b687dad20ca2e2b0de601979878bda785a7232f0a34e7f9e37b28b0cb07"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(KEY),
            "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"
        );

        let payload = concat!(
            r#"{"version":1,"audience":"aioncore.session-mcp-trust","server_id":"studio-project-1","server_fingerprint":""#,
            "f00a0b687dad20ca2e2b0de601979878bda785a7232f0a34e7f9e37b28b0cb07",
            r#"","issued_at_ms":1800000000000,"expires_at_ms":1800000120000,"nonce":"AQEBAQEBAQEBAQEBAQEBAQ"}"#
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(payload.as_bytes()),
            "eyJ2ZXJzaW9uIjoxLCJhdWRpZW5jZSI6ImFpb25jb3JlLnNlc3Npb24tbWNwLXRydXN0Iiwic2VydmVyX2lkIjoic3R1ZGlvLXByb2plY3QtMSIsInNlcnZlcl9maW5nZXJwcmludCI6ImYwMGEwYjY4N2RhZDIwY2EyZTJiMGRlNjAxOTc5ODc4YmRhNzg1YTcyMzJmMGEzNGU3ZjllMzdiMjhiMGNiMDciLCJpc3N1ZWRfYXRfbXMiOjE4MDAwMDAwMDAwMDAsImV4cGlyZXNfYXRfbXMiOjE4MDAwMDAxMjAwMDAsIm5vbmNlIjoiQVFFQkFRRUJBUUVCQVFFQkFRRUJBUSJ9"
        );
        let mut mac = HmacSha256::new_from_slice(&KEY).unwrap();
        mac.update(payload.as_bytes());
        assert_eq!(
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
            "-btA8nf8G_syCrSH2h_0bSRPXFo8NzDDJhbhTKTWOHE"
        );
    }
}
