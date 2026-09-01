//! Application configuration parsed from CLI arguments + key derivation.

use std::path::PathBuf;

/// Main-process-only key used to authenticate a transient session MCP trust
/// claim. Debug output is deliberately redacted because startup diagnostics
/// may format the surrounding application config.
#[derive(Clone)]
pub struct SessionMcpTrustKey([u8; 32]);

impl SessionMcpTrustKey {
    #[doc(hidden)]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn expose(&self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for SessionMcpTrustKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionMcpTrustKey([REDACTED])")
    }
}

/// Application configuration parsed from CLI arguments.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub data_dir: PathBuf,
    pub work_dir: PathBuf,
    pub app_version: String,
    /// Run in local embedded mode (skip authentication, use system_default_user).
    pub local: bool,
    /// SECURITY (D-01): per-session loopback token required for local-mode API/WS
    /// requests. Populated from the pre-runtime stdin bootstrap envelope. When `local`
    /// is set, the server refuses to start without it (see `init_environment`).
    pub local_token: Option<String>,
    /// Short-lived host-authentication key for built-in session MCP claims.
    /// It is read from the same synchronous stdin envelope before any runtime
    /// or spawned user MCP process exists.
    pub session_mcp_trust_key: Option<SessionMcpTrustKey>,
    /// Dump prompt diagnostics under `data_dir/prompt-dumps`.
    pub dump_prompts: bool,
    /// Explicitly authorize backup and rebuild for corruption-like local databases.
    pub recover_corrupted_database: bool,
}

impl AppConfig {
    /// Format as `host:port` for socket binding.
    pub fn socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Local URL helpers should use to call this backend from the same machine.
    pub fn local_base_url(&self) -> String {
        let host = match self.host.as_str() {
            "0.0.0.0" | "::" => "127.0.0.1",
            other => other,
        };
        format!("http://{host}:{}", self.port)
    }

    /// Path to the SQLite database file.
    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("aionui-backend.db")
    }

    /// SECURITY (D-05): path to the dedicated data-encryption key file, kept SEPARATE
    /// from the SQLite database so reading the database alone does not reveal the key.
    pub fn encryption_key_path(&self) -> PathBuf {
        self.data_dir.join(".aionui-enc-key")
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            host: aionui_common::constants::DEFAULT_HOST.to_string(),
            port: aionui_common::constants::DEFAULT_PORT,
            data_dir: PathBuf::from("data"),
            work_dir: PathBuf::from("data"),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            local: false,
            local_token: None,
            session_mcp_trust_key: None,
            dump_prompts: false,
            recover_corrupted_database: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_config_default() {
        let config = AppConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 25808);
        assert_eq!(config.data_dir, PathBuf::from("data"));
        assert_eq!(config.app_version, env!("CARGO_PKG_VERSION"));
        assert!(!config.dump_prompts);
        assert!(!config.recover_corrupted_database);
    }

    #[test]
    fn session_mcp_trust_key_debug_output_is_redacted() {
        let key = SessionMcpTrustKey::new([0x42; 32]);
        let rendered = format!("{key:?}");

        assert_eq!(rendered, "SessionMcpTrustKey([REDACTED])");
        assert!(!rendered.contains("66"));
    }

    #[test]
    fn test_app_config_socket_addr() {
        let config = AppConfig {
            host: "0.0.0.0".to_string(),
            port: 3000,
            ..Default::default()
        };
        assert_eq!(config.socket_addr(), "0.0.0.0:3000");
    }

    #[test]
    fn local_base_url_uses_loopback_for_wildcard_host() {
        let config = AppConfig {
            host: "0.0.0.0".to_string(),
            port: 49152,
            ..Default::default()
        };
        assert_eq!(config.local_base_url(), "http://127.0.0.1:49152");
    }

    #[test]
    fn test_app_config_database_path() {
        let config = AppConfig {
            data_dir: PathBuf::from("/tmp/aionui"),
            ..Default::default()
        };
        assert_eq!(config.database_path(), PathBuf::from("/tmp/aionui/aionui-backend.db"));
    }
}
