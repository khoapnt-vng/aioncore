//! Bootstrap layers shared by non-MCP subcommands.

use std::ffi::OsStr;
use std::io::Read as _;
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use tracing::info;

use aionui_app::{AppConfig, SessionMcpTrustKey};
use aionui_conversation::SESSION_MCP_TRUST_KEY_ENV;
use aionui_db::Database;

use crate::cli::Cli;

use super::builtin_skills::materialize_builtin_skills;
use super::tracing_init::{LogGuards, init_tracing};
use super::work_dir::resolve_work_dir;
use super::{BootstrapError, BootstrapErrorCode};

/// Legacy exec-time secret environment names. These are never consumed; they are
/// retained only so bootstrap can scrub stale launch configurations defensively.
const LOCAL_TOKEN_ENV: &str = "AIONUI_LOCAL_TOKEN";

/// Non-secret opt-in marker for the versioned stdin bootstrap envelope.
const BOOTSTRAP_SECRETS_STDIN_ENV: &str = "AIONUI_BOOTSTRAP_SECRETS_STDIN";
const BOOTSTRAP_SECRETS_STDIN_MARKER_V1: &str = "1";
const BOOTSTRAP_SECRETS_ENVELOPE_VERSION: u32 = 1;
/// The v1 payload is roughly 180 bytes. Keep enough headroom for representation
/// details while bounding allocation and input before serde sees it.
const MAX_BOOTSTRAP_SECRETS_ENVELOPE_BYTES: usize = 512;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapSecretsEnvelopeV1 {
    version: u32,
    #[serde(rename = "localToken")]
    local_token: String,
    #[serde(rename = "sessionMcpTrustKey")]
    session_mcp_trust_key: String,
}

/// Resolved environment needed by all non-MCP subcommands.
pub struct ServerEnvironment {
    /// Must be held alive for the process lifetime to flush log buffers.
    pub _log_guard: LogGuards,
    pub config: AppConfig,
}

/// Sensitive server-only values resolved and scrubbed synchronously before
/// Tokio or any command branch can create worker threads or child processes.
pub(crate) struct PreRuntimeServerEnvironment {
    work_dir: std::path::PathBuf,
    local_token: Option<String>,
    session_mcp_trust_key: Option<SessionMcpTrustKey>,
}

/// Scrub server-only authentication authority from the process environment
/// before runtime construction. Subcommands never consume these values or
/// mutate the work-dir environment; the server branch receives them explicitly.
pub(crate) fn prepare_pre_runtime_environment(
    cli: &Cli,
) -> Result<Option<PreRuntimeServerEnvironment>, BootstrapError> {
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    prepare_pre_runtime_environment_with(
        cli,
        &mut stdin,
        |name| std::env::var_os(name),
        |name| {
            // SAFETY: run_main calls this synchronously before constructing
            // Tokio or entering any command branch.
            unsafe { std::env::remove_var(name) };
        },
        |name, value| {
            // SAFETY: same pre-runtime boundary as the removal above.
            unsafe { std::env::set_var(name, value) };
        },
    )
}

fn prepare_pre_runtime_environment_with(
    cli: &Cli,
    bootstrap_input: &mut dyn std::io::Read,
    mut read: impl FnMut(&str) -> Option<std::ffi::OsString>,
    mut remove: impl FnMut(&str),
    mut set: impl FnMut(&str, &std::path::Path),
) -> Result<Option<PreRuntimeServerEnvironment>, BootstrapError> {
    let stdin_marker = read(BOOTSTRAP_SECRETS_STDIN_ENV);
    // Remove the non-secret mode marker and both legacy secret names before
    // parsing or selecting a command. Secrets are accepted only through stdin.
    remove(BOOTSTRAP_SECRETS_STDIN_ENV);
    remove(LOCAL_TOKEN_ENV);
    remove(SESSION_MCP_TRUST_KEY_ENV);

    let use_stdin_envelope = match stdin_marker.as_deref() {
        None => false,
        Some(marker) if marker == OsStr::new(BOOTSTRAP_SECRETS_STDIN_MARKER_V1) => true,
        Some(_) => return Err(invalid_bootstrap_secrets_envelope()),
    };

    if cli.command.is_some() {
        if use_stdin_envelope {
            // The envelope is a packaged-server launch contract. Refuse to
            // redirect a CLI/MCP helper's own stdin into bootstrap parsing.
            return Err(invalid_bootstrap_secrets_envelope());
        }
        return Ok(None);
    }

    if cli.local && !use_stdin_envelope {
        // Local packaged mode cannot authenticate safely without the stdin
        // envelope. Refuse before managed-runtime or Tokio initialization.
        return Err(invalid_bootstrap_secrets_envelope());
    }

    let (local_token, session_mcp_trust_key) = if use_stdin_envelope {
        let envelope = read_bootstrap_secrets_envelope(bootstrap_input)?;
        let trust_key = parse_session_mcp_trust_key(Some(envelope.session_mcp_trust_key))?;
        (Some(envelope.local_token), trust_key)
    } else {
        (None, None)
    };
    let work_dir = resolve_work_dir(cli.work_dir.clone(), &cli.data_dir);
    set("AIONUI_WORK_DIR", &work_dir);
    Ok(Some(PreRuntimeServerEnvironment {
        work_dir,
        local_token,
        session_mcp_trust_key,
    }))
}

fn invalid_bootstrap_secrets_envelope() -> BootstrapError {
    BootstrapError::new(
        BootstrapErrorCode::ConfigInvalid,
        "config.bootstrap_secrets_stdin",
        "stdin bootstrap secrets envelope is missing or invalid",
    )
}

fn read_bootstrap_secrets_envelope(
    input: &mut dyn std::io::Read,
) -> Result<BootstrapSecretsEnvelopeV1, BootstrapError> {
    let mut bytes = Vec::with_capacity(MAX_BOOTSTRAP_SECRETS_ENVELOPE_BYTES + 1);
    input
        .take((MAX_BOOTSTRAP_SECRETS_ENVELOPE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid_bootstrap_secrets_envelope())?;

    if bytes.len() > MAX_BOOTSTRAP_SECRETS_ENVELOPE_BYTES || bytes.last() != Some(&b'\n') {
        return Err(invalid_bootstrap_secrets_envelope());
    }

    let json = &bytes[..bytes.len() - 1];
    if json.is_empty() || json.contains(&b'\n') || json.contains(&b'\r') {
        return Err(invalid_bootstrap_secrets_envelope());
    }

    let envelope: BootstrapSecretsEnvelopeV1 =
        serde_json::from_slice(json).map_err(|_| invalid_bootstrap_secrets_envelope())?;
    if envelope.version != BOOTSTRAP_SECRETS_ENVELOPE_VERSION || !is_canonical_local_token(&envelope.local_token) {
        return Err(invalid_bootstrap_secrets_envelope());
    }
    Ok(envelope)
}

fn is_canonical_local_token(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Layer 1: Logging + config resolution.
///
/// Cheap, synchronous, no IO beyond creating the log directory.
/// All subcommands that need logging and config should call this first.
pub fn init_environment(
    cli: &Cli,
    merged_path: &str,
    pre_runtime: PreRuntimeServerEnvironment,
) -> Result<ServerEnvironment, BootstrapError> {
    let log_dir = cli.log_dir.clone().unwrap_or_else(|| cli.data_dir.join("logs"));
    let log_guard = init_tracing(&log_dir, cli.log_level.as_deref())?;

    info!(
        path_segments = merged_path.split(if cfg!(windows) { ';' } else { ':' }).count(),
        path_len = merged_path.len(),
        "startup: PATH ready"
    );

    // SECURITY (D-01): the embedded local API is protected by a per-session loopback
    // token supplied by the desktop host through the pre-runtime stdin envelope. In
    // local mode this token is MANDATORY — refuse to start without it rather than
    // silently reverting to an unauthenticated API that any local process could drive.
    let local_token = pre_runtime.local_token;
    if cli.local && local_token.is_none() {
        return Err(BootstrapError::new(
            BootstrapErrorCode::ConfigInvalid,
            "config.local_token",
            "local mode requires a loopback auth token from secure bootstrap",
        ));
    }

    let config = AppConfig {
        host: cli.host.clone(),
        port: cli.port,
        data_dir: cli.data_dir.clone(),
        work_dir: pre_runtime.work_dir,
        app_version: cli.app_version.clone(),
        local: cli.local,
        local_token,
        session_mcp_trust_key: pre_runtime.session_mcp_trust_key,
        dump_prompts: cli.dump_prompts,
        recover_corrupted_database: cli.recover_corrupted_database,
    };
    info!(
        "Running in {} mode — authentication is {}",
        if config.local { "local" } else { "remote" },
        // Local mode is no longer unauthenticated: it is gated by the loopback token.
        if config.local { "loopback-token" } else { "enabled" }
    );

    Ok(ServerEnvironment {
        _log_guard: log_guard,
        config,
    })
}

fn invalid_session_mcp_trust_key() -> BootstrapError {
    BootstrapError::new(
        BootstrapErrorCode::ConfigInvalid,
        "config.session_mcp_trust_key",
        "session MCP trust key must be canonical unpadded base64url containing exactly 32 bytes",
    )
}

fn parse_session_mcp_trust_key(raw: Option<String>) -> Result<Option<SessionMcpTrustKey>, BootstrapError> {
    let Some(value) = raw else {
        return Ok(None);
    };
    if value.is_empty() || value.contains('=') {
        return Err(invalid_session_mcp_trust_key());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(&value)
        .map_err(|_| invalid_session_mcp_trust_key())?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(invalid_session_mcp_trust_key());
    }
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| invalid_session_mcp_trust_key())?;
    Ok(Some(SessionMcpTrustKey::new(bytes)))
}

/// Layer 2: Materialize builtin skills + initialize the database.
///
/// Requires only `data_dir`. Subcommands that need persistent state
/// (database, skill files) should call this after `init_environment`.
pub async fn init_data_layer(config: &AppConfig) -> Result<Database, BootstrapError> {
    let boot = Instant::now();

    materialize_builtin_skills(&config.data_dir).await.map_err(|e| {
        BootstrapError::new(
            BootstrapErrorCode::DataInitFailed,
            "data.builtin_skills",
            "failed to initialize application data",
        )
        .with_source(e)
        .with_field("dataDir", config.data_dir.display().to_string())
    })?;
    info!(
        elapsed_ms = boot.elapsed().as_millis(),
        "startup: builtin skills materialized"
    );

    let db_path = config.database_path();
    aionui_db::maybe_copy_legacy_database(&db_path).map_err(|e| {
        BootstrapError::new(
            BootstrapErrorCode::DataInitFailed,
            "data.legacy_db",
            "failed to initialize application data",
        )
        .with_source(e)
        .with_field("databasePath", db_path.display().to_string())
    })?;
    info!("Initializing database at {}", db_path.display());
    // SECURITY (D-06): load the at-rest encryption key (D-05 key file) BEFORE opening the
    // database so the SQLite file is opened as an encrypted SQLCipher database.
    let encryption_key = aionui_common::load_or_create_encryption_key(&config.encryption_key_path()).map_err(|e| {
        BootstrapError::new(
            BootstrapErrorCode::DataInitFailed,
            "data.encryption_key",
            "failed to initialize application data",
        )
        .with_source(e)
        .with_field("keyPath", config.encryption_key_path().display().to_string())
    })?;
    let database = aionui_db::init_database_staged_with_options(
        &db_path,
        aionui_db::DatabaseInitOptions {
            recover_corrupted_database: config.recover_corrupted_database,
            encryption_key: Some(encryption_key),
        },
    )
    .await
    .map_err(|e| {
        let stage = e.stage();
        BootstrapError::new(
            BootstrapErrorCode::DataInitFailed,
            stage,
            "failed to initialize application data",
        )
        .with_source(e.into_source())
        .with_field("databasePath", db_path.display().to_string())
    })?;
    info!(elapsed_ms = boot.elapsed().as_millis(), "startup: database initialized");

    Ok(database)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::io::{Cursor, Read};

    use clap::Parser;

    use super::{
        BOOTSTRAP_SECRETS_STDIN_ENV, LOCAL_TOKEN_ENV, MAX_BOOTSTRAP_SECRETS_ENVELOPE_BYTES, SESSION_MCP_TRUST_KEY_ENV,
        parse_session_mcp_trust_key, prepare_pre_runtime_environment_with, read_bootstrap_secrets_envelope,
    };
    use crate::cli::Cli;

    const KEY: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
    const LOCAL_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const VALID_ENVELOPE: &str = concat!(
        r#"{"version":1,"localToken":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","sessionMcpTrustKey":""#,
        "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI",
        "\"}\n"
    );

    struct PanicReader;

    impl Read for PanicReader {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            panic!("stdin must remain untouched")
        }
    }

    #[test]
    fn session_mcp_trust_key_requires_canonical_32_byte_base64url() {
        assert!(parse_session_mcp_trust_key(Some(KEY.into())).unwrap().is_some());
        assert!(parse_session_mcp_trust_key(None).unwrap().is_none());
        for malformed in ["", "abc=", "not+base64", "AQ"] {
            assert!(
                parse_session_mcp_trust_key(Some(malformed.into())).is_err(),
                "{malformed}"
            );
        }
    }

    #[test]
    fn server_pre_runtime_reads_bounded_stdin_envelope_and_scrubs_all_env_names() {
        let environment = std::cell::RefCell::new(HashMap::from([
            (BOOTSTRAP_SECRETS_STDIN_ENV.to_owned(), "1".to_owned()),
            (LOCAL_TOKEN_ENV.to_owned(), "stale-local-token".to_owned()),
            (SESSION_MCP_TRUST_KEY_ENV.to_owned(), "stale-trust-key".to_owned()),
        ]));
        let cli = Cli::try_parse_from(["aioncore", "--work-dir", "/tmp/aionui-pre-runtime"]).unwrap();
        let mut input = Cursor::new(VALID_ENVELOPE.as_bytes());

        let prepared = prepare_pre_runtime_environment_with(
            &cli,
            &mut input,
            |name| {
                environment
                    .borrow()
                    .get(name)
                    .map(|value| OsString::from(value.as_str()))
            },
            |name| {
                environment.borrow_mut().remove(name);
            },
            |name, value| {
                environment
                    .borrow_mut()
                    .insert(name.to_owned(), value.to_string_lossy().into_owned());
            },
        )
        .unwrap();

        assert_eq!(
            prepared.as_ref().and_then(|value| value.local_token.as_deref()),
            Some(LOCAL_TOKEN)
        );
        assert!(prepared.unwrap().session_mcp_trust_key.is_some());
        assert!(!environment.borrow().contains_key(BOOTSTRAP_SECRETS_STDIN_ENV));
        assert!(!environment.borrow().contains_key(LOCAL_TOKEN_ENV));
        assert!(!environment.borrow().contains_key(SESSION_MCP_TRUST_KEY_ENV));
        assert_eq!(
            environment.borrow().get("AIONUI_WORK_DIR").map(String::as_str),
            Some("/tmp/aionui-pre-runtime")
        );
    }

    #[test]
    fn malformed_server_envelope_is_rejected_after_all_env_names_are_scrubbed() {
        let environment = std::cell::RefCell::new(HashMap::from([
            (BOOTSTRAP_SECRETS_STDIN_ENV.to_owned(), "1".to_owned()),
            (LOCAL_TOKEN_ENV.to_owned(), "stale-local-token".to_owned()),
            (SESSION_MCP_TRUST_KEY_ENV.to_owned(), "stale-trust-key".to_owned()),
        ]));
        let cli = Cli::try_parse_from(["aioncore"]).unwrap();
        let mut input = Cursor::new(
            br#"{"version":1,"localToken":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","sessionMcpTrustKey":"not+base64"}
"#,
        );

        let result = prepare_pre_runtime_environment_with(
            &cli,
            &mut input,
            |name| {
                environment
                    .borrow()
                    .get(name)
                    .map(|value| OsString::from(value.as_str()))
            },
            |name| {
                environment.borrow_mut().remove(name);
            },
            |_name, _value| panic!("malformed key must fail before work-dir mutation"),
        );

        assert!(result.is_err());
        assert!(!environment.borrow().contains_key(BOOTSTRAP_SECRETS_STDIN_ENV));
        assert!(!environment.borrow().contains_key(LOCAL_TOKEN_ENV));
        assert!(!environment.borrow().contains_key(SESSION_MCP_TRUST_KEY_ENV));
    }

    #[test]
    fn marker_absent_preserves_subcommand_stdin_and_discards_legacy_secret_envs() {
        let environment = std::cell::RefCell::new(HashMap::from([
            (LOCAL_TOKEN_ENV.to_owned(), "stale-local-token".to_owned()),
            (SESSION_MCP_TRUST_KEY_ENV.to_owned(), "stale-trust-key".to_owned()),
        ]));
        let cli = Cli::try_parse_from(["aioncore", "--work-dir", "/tmp/must-not-be-exported", "capabilities"]).unwrap();
        let mut input = PanicReader;

        let prepared = prepare_pre_runtime_environment_with(
            &cli,
            &mut input,
            |name| {
                environment
                    .borrow()
                    .get(name)
                    .map(|value| OsString::from(value.as_str()))
            },
            |name| {
                environment.borrow_mut().remove(name);
            },
            |_name, _value| panic!("subcommands must not mutate AIONUI_WORK_DIR"),
        )
        .unwrap();

        assert!(prepared.is_none());
        assert!(!environment.borrow().contains_key(LOCAL_TOKEN_ENV));
        assert!(!environment.borrow().contains_key(SESSION_MCP_TRUST_KEY_ENV));
        assert!(!environment.borrow().contains_key("AIONUI_WORK_DIR"));
    }

    #[test]
    fn marker_is_rejected_for_subcommands_without_consuming_stdin() {
        let environment = std::cell::RefCell::new(HashMap::from([(
            BOOTSTRAP_SECRETS_STDIN_ENV.to_owned(),
            "1".to_owned(),
        )]));
        let cli = Cli::try_parse_from(["aioncore", "capabilities"]).unwrap();
        let mut input = PanicReader;

        let result = prepare_pre_runtime_environment_with(
            &cli,
            &mut input,
            |name| {
                environment
                    .borrow()
                    .get(name)
                    .map(|value| OsString::from(value.as_str()))
            },
            |name| {
                environment.borrow_mut().remove(name);
            },
            |_name, _value| panic!("subcommands must not mutate AIONUI_WORK_DIR"),
        );

        assert!(result.is_err());
        assert!(!environment.borrow().contains_key(BOOTSTRAP_SECRETS_STDIN_ENV));
    }

    #[test]
    fn local_server_without_marker_fails_before_stdin_or_work_dir_access() {
        let environment = std::cell::RefCell::new(HashMap::<String, String>::new());
        let cli = Cli::try_parse_from(["aioncore", "--local"]).unwrap();
        let mut input = PanicReader;

        let result = prepare_pre_runtime_environment_with(
            &cli,
            &mut input,
            |name| {
                environment
                    .borrow()
                    .get(name)
                    .map(|value| OsString::from(value.as_str()))
            },
            |name| {
                environment.borrow_mut().remove(name);
            },
            |_name, _value| panic!("missing marker must fail before work-dir mutation"),
        );
        let Err(error) = result else {
            panic!("local server must reject a missing bootstrap marker")
        };

        assert_eq!(error.stage(), "config.bootstrap_secrets_stdin");
    }

    #[test]
    fn envelope_parser_fails_closed_for_wrong_shape_version_and_framing() {
        let oversized = vec![b'x'; MAX_BOOTSTRAP_SECRETS_ENVELOPE_BYTES + 1];
        let cases: Vec<&[u8]> = vec![
            b"",
            b"{}\n",
            br#"{"version":2,"localToken":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","sessionMcpTrustKey":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"}
"#,
            br#"{"version":1,"localToken":"","sessionMcpTrustKey":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"}
"#,
            br#"{"version":1,"localToken":"0123456789abcdef","sessionMcpTrustKey":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"}
"#,
            br#"{"version":1,"localToken":"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef","sessionMcpTrustKey":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"}
"#,
            br#"{"version":1,"localToken":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","sessionMcpTrustKey":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI","extra":true}
"#,
            br#"{"version":1,"localToken":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","sessionMcpTrustKey":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"}"#,
            b"{}\ntrailing",
            b"{}\r\n",
            oversized.as_slice(),
        ];

        for case in cases {
            assert!(read_bootstrap_secrets_envelope(&mut Cursor::new(case)).is_err());
        }
    }

    #[test]
    fn unknown_marker_value_fails_without_reading_stdin() {
        let environment = std::cell::RefCell::new(HashMap::from([(
            BOOTSTRAP_SECRETS_STDIN_ENV.to_owned(),
            "2".to_owned(),
        )]));
        let cli = Cli::try_parse_from(["aioncore"]).unwrap();
        let mut input = PanicReader;

        let result = prepare_pre_runtime_environment_with(
            &cli,
            &mut input,
            |name| {
                environment
                    .borrow()
                    .get(name)
                    .map(|value| OsString::from(value.as_str()))
            },
            |name| {
                environment.borrow_mut().remove(name);
            },
            |_name, _value| panic!("invalid marker must fail before work-dir mutation"),
        );

        assert!(result.is_err());
        assert!(!environment.borrow().contains_key(BOOTSTRAP_SECRETS_STDIN_ENV));
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_marker_is_present_and_fails_closed() {
        use std::os::unix::ffi::OsStringExt as _;

        let marker = OsString::from_vec(vec![0xff]);
        let removed = std::cell::RefCell::new(Vec::new());
        let cli = Cli::try_parse_from(["aioncore", "--local"]).unwrap();
        let mut input = PanicReader;

        let result = prepare_pre_runtime_environment_with(
            &cli,
            &mut input,
            |name| (name == BOOTSTRAP_SECRETS_STDIN_ENV).then(|| marker.clone()),
            |name| removed.borrow_mut().push(name.to_owned()),
            |_name, _value| panic!("invalid marker must fail before work-dir mutation"),
        );
        let Err(error) = result else {
            panic!("non-Unicode bootstrap marker must be rejected")
        };

        assert_eq!(error.stage(), "config.bootstrap_secrets_stdin");
        assert_eq!(
            removed.into_inner(),
            vec![
                BOOTSTRAP_SECRETS_STDIN_ENV.to_owned(),
                LOCAL_TOKEN_ENV.to_owned(),
                SESSION_MCP_TRUST_KEY_ENV.to_owned()
            ]
        );
    }

    #[test]
    fn database_stage_comes_from_db_boundary_error() {
        let err = aionui_db::DatabaseInitError::new(
            "database.migration",
            aionui_db::DbError::Migration(sqlx::migrate::MigrateError::VersionMismatch(42)),
        );

        assert_eq!(err.stage(), "database.migration");
    }

    #[test]
    fn database_schema_repair_stage_comes_from_db_boundary_error() {
        let err = aionui_db::DatabaseInitError::new(
            "database.schema_repair",
            aionui_db::DbError::Init("repair failed".into()),
        );

        assert_eq!(err.stage(), "database.schema_repair");
    }

    #[test]
    fn database_recoverable_corruption_stage_comes_from_db_boundary_error() {
        let err = aionui_db::DatabaseInitError::new(
            "database.recoverable_corruption",
            aionui_db::DbError::Migration(sqlx::migrate::MigrateError::ExecuteMigration(
                sqlx::Error::Protocol("database disk image is malformed".into()),
                13,
            )),
        );

        assert_eq!(err.stage(), "database.recoverable_corruption");
    }
}
