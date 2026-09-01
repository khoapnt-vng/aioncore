//! Bootstrap layers shared by non-MCP subcommands.

use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tracing::info;

use aionui_app::{AppConfig, SessionMcpTrustKey};
use aionui_conversation::SESSION_MCP_TRUST_KEY_ENV;
use aionui_db::Database;

use crate::cli::Cli;

use super::builtin_skills::materialize_builtin_skills;
use super::tracing_init::{LogGuards, init_tracing};
use super::work_dir::resolve_work_dir;
use super::{BootstrapError, BootstrapErrorCode};

/// Env var carrying the per-session loopback auth token (SECURITY D-01). The desktop
/// host (Electron / WePrompt backend launcher) generates a fresh random token each run
/// and passes it here at spawn time; the same value must be sent by every API/WS client.
const LOCAL_TOKEN_ENV: &str = "AIONUI_LOCAL_TOKEN";

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
    prepare_pre_runtime_environment_with(
        cli,
        |name| std::env::var(name).ok(),
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
    mut read: impl FnMut(&str) -> Option<String>,
    mut remove: impl FnMut(&str),
    mut set: impl FnMut(&str, &std::path::Path),
) -> Result<Option<PreRuntimeServerEnvironment>, BootstrapError> {
    let local_token = read(LOCAL_TOKEN_ENV).filter(|value| !value.is_empty());
    let raw_trust_key = read(SESSION_MCP_TRUST_KEY_ENV);
    // Remove both server-only authorities before parsing or selecting a command
    // so valid and malformed values can never reach a later child process.
    remove(LOCAL_TOKEN_ENV);
    remove(SESSION_MCP_TRUST_KEY_ENV);

    if cli.command.is_some() {
        return Ok(None);
    }

    let session_mcp_trust_key = parse_session_mcp_trust_key(raw_trust_key)?;
    let work_dir = resolve_work_dir(cli.work_dir.clone(), &cli.data_dir);
    set("AIONUI_WORK_DIR", &work_dir);
    Ok(Some(PreRuntimeServerEnvironment {
        work_dir,
        local_token,
        session_mcp_trust_key,
    }))
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
    // token supplied by the desktop host via the `AIONUI_LOCAL_TOKEN` env var. In local
    // mode this token is MANDATORY — refuse to start without it rather than silently
    // reverting to an unauthenticated API that any local process could drive.
    let local_token = pre_runtime.local_token;
    if cli.local && local_token.is_none() {
        return Err(BootstrapError::new(
            BootstrapErrorCode::ConfigInvalid,
            "config.local_token",
            "local mode requires a loopback auth token but AIONUI_LOCAL_TOKEN is unset or empty",
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

    use clap::Parser;

    use super::{
        LOCAL_TOKEN_ENV, SESSION_MCP_TRUST_KEY_ENV, parse_session_mcp_trust_key, prepare_pre_runtime_environment_with,
    };
    use crate::cli::Cli;

    #[test]
    fn session_mcp_trust_key_requires_canonical_32_byte_base64url() {
        let key = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
        assert!(parse_session_mcp_trust_key(Some(key.into())).unwrap().is_some());
        assert!(parse_session_mcp_trust_key(None).unwrap().is_none());
        for malformed in ["", "abc=", "not+base64", "AQ"] {
            assert!(
                parse_session_mcp_trust_key(Some(malformed.into())).is_err(),
                "{malformed}"
            );
        }
    }

    #[test]
    fn server_pre_runtime_scrubs_key_and_sets_work_dir_before_later_environment_reads() {
        let key = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
        let local_token = "local-token-1";
        let environment = std::cell::RefCell::new(HashMap::from([
            (LOCAL_TOKEN_ENV.to_owned(), local_token.to_owned()),
            (SESSION_MCP_TRUST_KEY_ENV.to_owned(), key.to_owned()),
        ]));
        let cli = Cli::try_parse_from(["aioncore", "--work-dir", "/tmp/aionui-pre-runtime"]).unwrap();

        let prepared = prepare_pre_runtime_environment_with(
            &cli,
            |name| environment.borrow().get(name).cloned(),
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
            Some(local_token)
        );
        assert!(!environment.borrow().contains_key(LOCAL_TOKEN_ENV));
        assert!(!environment.borrow().contains_key(SESSION_MCP_TRUST_KEY_ENV));
        assert_eq!(
            environment.borrow().get("AIONUI_WORK_DIR").map(String::as_str),
            Some("/tmp/aionui-pre-runtime")
        );
    }

    #[test]
    fn malformed_server_key_is_removed_before_error() {
        let environment = std::cell::RefCell::new(HashMap::from([
            (LOCAL_TOKEN_ENV.to_owned(), "local-token-1".to_owned()),
            (SESSION_MCP_TRUST_KEY_ENV.to_owned(), "not+base64".to_owned()),
        ]));
        let cli = Cli::try_parse_from(["aioncore"]).unwrap();

        let result = prepare_pre_runtime_environment_with(
            &cli,
            |name| environment.borrow().get(name).cloned(),
            |name| {
                environment.borrow_mut().remove(name);
            },
            |_name, _value| panic!("malformed key must fail before work-dir mutation"),
        );

        assert!(result.is_err());
        assert!(!environment.borrow().contains_key(LOCAL_TOKEN_ENV));
        assert!(!environment.borrow().contains_key(SESSION_MCP_TRUST_KEY_ENV));
    }

    #[test]
    fn subcommands_scrub_and_discard_valid_or_malformed_key_without_setting_work_dir() {
        for raw in ["QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI", "not+base64"] {
            let environment = std::cell::RefCell::new(HashMap::from([
                (LOCAL_TOKEN_ENV.to_owned(), "local-token-1".to_owned()),
                (SESSION_MCP_TRUST_KEY_ENV.to_owned(), raw.to_owned()),
            ]));
            let cli =
                Cli::try_parse_from(["aioncore", "--work-dir", "/tmp/must-not-be-exported", "capabilities"]).unwrap();

            let prepared = prepare_pre_runtime_environment_with(
                &cli,
                |name| environment.borrow().get(name).cloned(),
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
