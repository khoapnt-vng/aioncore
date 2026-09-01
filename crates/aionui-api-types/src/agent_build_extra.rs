use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::TeamMcpStdioConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionMcpTransport {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
    },
    Http {
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    Sse {
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
    StreamableHttp {
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMcpServer {
    pub id: String,
    pub name: String,
    pub transport: SessionMcpTransport,
}

const SESSION_MCP_FINGERPRINT_DOMAIN: &[u8] = b"aionui.session-mcp.identity.v1\0";
/// Bump whenever Core changes how a persisted logical session descriptor is
/// resolved into the executable/network config passed to Aionrs.
pub const SESSION_MCP_RESOLVER_PROFILE_V1: &str = "aioncore.session-mcp-resolver.v1";

/// Fingerprint the exact logical executable/network descriptor supplied by
/// the host without relying on map iteration order or cross-language JSON
/// canonicalization. A separate Core-owned resolver profile records how that
/// logical descriptor is interpreted at runtime.
pub fn session_mcp_server_fingerprint(server: &SessionMcpServer) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_MCP_FINGERPRINT_DOMAIN);
    fingerprint_string(&mut hasher, &server.id);
    fingerprint_string(&mut hasher, &server.name);
    match &server.transport {
        SessionMcpTransport::Stdio { command, args, env } => {
            fingerprint_string(&mut hasher, "stdio");
            fingerprint_string(&mut hasher, command);
            fingerprint_count(&mut hasher, args.len());
            for arg in args {
                fingerprint_string(&mut hasher, arg);
            }
            fingerprint_map(&mut hasher, env);
        }
        SessionMcpTransport::Http { url, headers } => {
            fingerprint_string(&mut hasher, "http");
            fingerprint_string(&mut hasher, url);
            fingerprint_map(&mut hasher, headers);
        }
        SessionMcpTransport::Sse { url, headers } => {
            fingerprint_string(&mut hasher, "sse");
            fingerprint_string(&mut hasher, url);
            fingerprint_map(&mut hasher, headers);
        }
        SessionMcpTransport::StreamableHttp { url, headers } => {
            fingerprint_string(&mut hasher, "streamable_http");
            fingerprint_string(&mut hasher, url);
            fingerprint_map(&mut hasher, headers);
        }
    }
    hex::encode(hasher.finalize())
}

fn fingerprint_string(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn fingerprint_count(hasher: &mut Sha256, count: usize) {
    hasher.update((count as u64).to_be_bytes());
}

fn fingerprint_map(hasher: &mut Sha256, values: &HashMap<String, String>) {
    let mut entries: Vec<_> = values.iter().collect();
    entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    fingerprint_count(hasher, entries.len());
    for (key, value) in entries {
        fingerprint_string(hasher, key);
        fingerprint_string(hasher, value);
    }
}

/// Short-lived host authentication supplied only while a session MCP snapshot
/// is created. The backend verifies and consumes this envelope before
/// persisting the conversation; it must never be stored as runtime authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionMcpTrustClaim {
    pub payload: String,
    pub signature: String,
}

/// Backend-owned record proving which logical session MCP descriptor the
/// desktop host authenticated and which exact Core resolver policy may
/// interpret it at runtime.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionMcpTrustSnapshot {
    pub server_id: String,
    pub server_fingerprint: String,
    pub resolver_profile: String,
}

/// ACP-specific fields extracted from `extra` in build task options.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AcpBuildExtra {
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub cli_path: Option<String>,
    #[serde(default)]
    pub agent_name: Option<String>,
    #[serde(default)]
    pub custom_agent_id: Option<String>,
    #[serde(default)]
    pub preset_context: Option<String>,
    #[serde(default)]
    pub skills: Vec<String>,
    #[serde(default)]
    pub preset_assistant_id: Option<String>,
    #[serde(default)]
    pub session_mode: Option<String>,
    #[serde(default)]
    pub current_model_id: Option<String>,
    #[serde(default)]
    pub thought_level: Option<String>,
    #[serde(default)]
    pub cron_job_id: Option<String>,
    #[serde(default)]
    pub team_mcp_stdio_config: Option<TeamMcpStdioConfig>,
    #[serde(default)]
    pub mcp_server_ids: Option<Vec<String>>,
    #[serde(default)]
    pub session_mcp_servers: Vec<SessionMcpServer>,
    #[serde(default)]
    pub user_id: Option<String>,
}

/// Aionrs-specific fields extracted from `extra` in build task options.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AionrsBuildExtra {
    #[serde(default)]
    pub system_prompt: Option<String>,
    #[serde(default)]
    pub preset_rules: Option<String>,
    #[serde(default)]
    pub skills: Vec<String>,
    #[serde(default)]
    pub max_turns: Option<usize>,
    #[serde(default)]
    pub max_tool_call_malformed_turns: Option<usize>,
    #[serde(default)]
    pub max_tool_call_failure_turns: Option<usize>,
    #[serde(default)]
    pub session_mode: Option<String>,
    #[serde(default)]
    pub team_mcp_stdio_config: Option<TeamMcpStdioConfig>,
    #[serde(default)]
    pub mcp_server_ids: Option<Vec<String>>,
    #[serde(default)]
    pub session_mcp_servers: Vec<SessionMcpServer>,
    /// Runtime-only projection loaded from AionCore's private verified column.
    /// Conversation assembly must overwrite any caller-shaped value, including
    /// an empty private result, before this reaches the factory.
    #[serde(default)]
    pub session_mcp_trust: Vec<SessionMcpTrustSnapshot>,
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
}

/// ACP model information returned by the ACP backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcpModelInfo {
    pub model_id: String,
    pub model_name: Option<String>,
    pub provider: Option<String>,
}

/// Controls what happens when a slash command produces an empty turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashCommandCompletionBehavior {
    Normal,
    NeutralTipOnEmpty,
}

/// A slash command item available in a conversation session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashCommandItem {
    pub command: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_behavior: Option<SlashCommandCompletionBehavior>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_turn_tip_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empty_turn_tip_params: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acp_build_extra_defaults_thought_level_to_none() {
        let parsed: AcpBuildExtra = serde_json::from_str(r#"{"backend":"codex"}"#).unwrap();
        assert!(parsed.thought_level.is_none());
    }

    #[test]
    fn acp_build_extra_parses_thought_level_seed() {
        let parsed: AcpBuildExtra = serde_json::from_str(r#"{"backend":"codex","thought_level":"high"}"#).unwrap();
        assert_eq!(parsed.thought_level.as_deref(), Some("high"));
    }

    #[test]
    fn acp_build_extra_ignores_legacy_guide_config_field() {
        let legacy_key = concat!("guide", "_mcp_config");
        let parsed: AcpBuildExtra = serde_json::from_value(serde_json::json!({
            "backend": "claude",
            legacy_key: {"port": 1234, "token": "legacy", "binary_path": "/bin/aioncore"}
        }))
        .unwrap();

        assert_eq!(parsed.backend.as_deref(), Some("claude"));
        let serialized = serde_json::to_value(&parsed).unwrap();
        assert!(
            serialized.get(legacy_key).is_none(),
            "legacy guide config must be ignored, not re-serialized"
        );
    }

    #[test]
    fn aionrs_build_extra_ignores_legacy_fields() {
        let legacy_key = concat!("guide", "_mcp_config");
        let parsed: AionrsBuildExtra = serde_json::from_value(serde_json::json!({
            "backend": "aionrs",
            "max_tokens": 8192,
            legacy_key: {"port": 1234, "token": "legacy", "binary_path": "/bin/aioncore"}
        }))
        .unwrap();

        assert_eq!(parsed.backend.as_deref(), Some("aionrs"));
        let serialized = serde_json::to_value(&parsed).unwrap();
        assert!(
            serialized.get(legacy_key).is_none(),
            "legacy guide config must be ignored, not re-serialized"
        );
        assert!(
            serialized.get("max_tokens").is_none(),
            "legacy max_tokens must be ignored, not re-serialized"
        );
    }
}
