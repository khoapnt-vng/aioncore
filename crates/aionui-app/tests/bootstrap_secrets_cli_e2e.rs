//! Process-boundary coverage for the packaged-launch stdin bootstrap contract.

use std::io::Write as _;
use std::process::{Command, Stdio};

const BOOTSTRAP_MARKER: &str = "AIONUI_BOOTSTRAP_SECRETS_STDIN";
const LOCAL_TOKEN_ENV: &str = "AIONUI_LOCAL_TOKEN";
const TRUST_KEY_ENV: &str = "AIONUI_SESSION_MCP_TRUST_KEY";

fn aioncore_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_aioncore"));
    command
        .env_remove(BOOTSTRAP_MARKER)
        .env_remove(LOCAL_TOKEN_ENV)
        .env_remove(TRUST_KEY_ENV);
    command
}

#[test]
fn marker_absent_preserves_subcommand_stdin() {
    let mut child = aioncore_command()
        .args(["team", "send-message"])
        .env("AIONUI_BASE_URL", "http://127.0.0.1:9")
        .env("AIONUI_CONVERSATION_ID", "conv-1")
        .env("AIONUI_USER_ID", "user-1")
        .env("AIONUI_RUNTIME_TOKEN", "token-1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"to":"worker-1","message":"hi","team_id":"forged"}"#)
        .unwrap();

    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("TEAM_CLI_SCHEMA_VALIDATION_FAILED"),
        "subcommand did not receive its original stdin\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn malformed_packaged_server_envelope_fails_at_bootstrap_boundary() {
    let mut child = aioncore_command()
        .arg("--local")
        .env(BOOTSTRAP_MARKER, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"{}\ntrailing").unwrap();

    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("BOOTSTRAP_CONFIG_INVALID"), "stderr:\n{stderr}");
    assert!(
        stderr.contains("stage=config.bootstrap_secrets_stdin"),
        "stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("trailing"),
        "bootstrap must not echo secret input: {stderr}"
    );
}

#[test]
fn local_server_missing_marker_fails_at_pre_runtime_boundary() {
    let output = aioncore_command().arg("--local").stdin(Stdio::null()).output().unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("BOOTSTRAP_CONFIG_INVALID"), "stderr:\n{stderr}");
    assert!(
        stderr.contains("stage=config.bootstrap_secrets_stdin"),
        "stderr:\n{stderr}"
    );
}

#[test]
fn bootstrap_marker_is_refused_for_subcommands_without_consuming_their_stdin() {
    let output = aioncore_command()
        .arg("capabilities")
        .env(BOOTSTRAP_MARKER, "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("BOOTSTRAP_CONFIG_INVALID"), "stderr:\n{stderr}");
    assert!(
        stderr.contains("stage=config.bootstrap_secrets_stdin"),
        "stderr:\n{stderr}"
    );
}
