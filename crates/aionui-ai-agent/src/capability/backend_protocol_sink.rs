use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

use aion_protocol::events::{ProtocolEvent, ToolCategory, ToolInfo};
use aion_protocol::writer::ProtocolEmitter;
use aionui_common::{Confirmation, ConfirmationMcpIdentity, ConfirmationOption, generate_id};
use serde_json::json;
use tokio::sync::broadcast;
use tracing::debug;

use crate::protocol::events::{AcpPermissionEventData, AgentStreamEvent, ToolCallEventData, ToolCallStatus};

/// Implements `ProtocolEmitter` for the aioncore context.
///
/// Bridges aionrs `ProtocolEvent` emissions to `AgentStreamEvent` on a
/// broadcast channel. Only handles events relevant to the approval flow;
/// other events (text, thinking, tool results) are already handled by
/// `BackendOutputSink` via the `OutputSink` trait.
pub struct BackendProtocolSink {
    event_tx: broadcast::Sender<AgentStreamEvent>,
    confirmations: Arc<RwLock<Vec<Confirmation>>>,
}

impl BackendProtocolSink {
    pub fn new(event_tx: broadcast::Sender<AgentStreamEvent>, confirmations: Arc<RwLock<Vec<Confirmation>>>) -> Self {
        Self {
            event_tx,
            confirmations,
        }
    }

    fn build_confirmation(call_id: &str, tool: &ToolInfo) -> Confirmation {
        let mcp_identity = match (&tool.category, &tool.mcp) {
            (ToolCategory::Mcp, Some(mcp)) => Some(ConfirmationMcpIdentity {
                server_name: mcp.server_name.clone(),
                tool_name: mcp.tool_name.clone(),
            }),
            _ => None,
        };
        let title = match &mcp_identity {
            Some(identity) => format!(
                "mcp wants to use: {}/{}",
                escape_untrusted_identity(&identity.server_name),
                escape_untrusted_identity(&identity.tool_name)
            ),
            None => format!("{} wants to use: {}", tool.category, tool.name),
        };
        let command_type = Some(tool.category.to_string());
        let mut options = vec![ConfirmationOption {
            label: "messages.confirmation.yesAllowOnce".to_string(),
            value: json!("proceed_once"),
            params: None,
        }];

        if let Some(identity) = &mcp_identity {
            options.push(ConfirmationOption {
                label: "messages.confirmation.yesAlwaysAllowTool".to_string(),
                value: json!("proceed_always"),
                params: Some(HashMap::from([
                    ("toolName".to_string(), escape_untrusted_identity(&identity.tool_name)),
                    (
                        "serverName".to_string(),
                        escape_untrusted_identity(&identity.server_name),
                    ),
                ])),
            });
        } else if tool.category != ToolCategory::Mcp {
            options.push(ConfirmationOption {
                label: "messages.confirmation.yesAllowAlways".to_string(),
                value: json!("proceed_always"),
                params: None,
            });
        }

        options.push(ConfirmationOption {
            label: "messages.confirmation.no".to_string(),
            value: json!("cancel"),
            params: None,
        });

        Confirmation {
            id: generate_id(),
            call_id: call_id.to_string(),
            title: Some(title),
            action: Some(tool.name.clone()),
            description: if mcp_identity.is_some() {
                escape_untrusted_identity(&tool.description)
            } else {
                tool.description.clone()
            },
            command_type,
            mcp_identity,
            options,
        }
    }
}

/// Make untrusted identity text visibly unambiguous without changing the raw
/// identity used by the approval authority.
fn escape_untrusted_identity(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for character in input.chars() {
        let code_point = character as u32;
        let is_bidi_control = matches!(
            code_point,
            0x061c | 0x200e | 0x200f | 0x202a..=0x202e | 0x2066..=0x2069
        );
        if character.is_control() || is_bidi_control {
            write!(&mut escaped, "\\u{{{code_point:04X}}}").expect("writing to String cannot fail");
        } else {
            escaped.push(character);
        }
    }
    escaped
}

impl ProtocolEmitter for BackendProtocolSink {
    fn emit(&self, event: &ProtocolEvent) -> std::io::Result<()> {
        match event {
            ProtocolEvent::ToolRequest { call_id, tool, .. } => {
                let confirmation = Self::build_confirmation(call_id, tool);

                if let Ok(mut confs) = self.confirmations.write() {
                    confs.push(confirmation.clone());
                }

                let _ = self
                    .event_tx
                    .send(AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(
                        confirmation.clone(),
                    )));

                debug!(
                    call_id,
                    tool_name = %tool.name,
                    "BackendProtocolSink: emitted AcpPermission(Confirmation) event"
                );
            }

            ProtocolEvent::ToolCancelled { call_id, reason, .. } => {
                if let Ok(mut confs) = self.confirmations.write() {
                    confs.retain(|c| c.call_id != *call_id);
                }

                let _ = self.event_tx.send(AgentStreamEvent::ToolCall(ToolCallEventData {
                    call_id: call_id.clone(),
                    name: format!("cancelled: {reason}"),
                    args: serde_json::Value::Null,
                    status: ToolCallStatus::Error,
                    input: None,
                    output: None,
                    description: None,
                }));
            }

            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aion_protocol::events::{McpToolInfo, ToolInfo};

    fn make_sink() -> (
        BackendProtocolSink,
        broadcast::Receiver<AgentStreamEvent>,
        Arc<RwLock<Vec<Confirmation>>>,
    ) {
        let (tx, rx) = broadcast::channel(16);
        let confs = Arc::new(RwLock::new(Vec::new()));
        let sink = BackendProtocolSink::new(tx, confs.clone());
        (sink, rx, confs)
    }

    #[test]
    fn tool_request_emits_permission_event() {
        let (sink, mut rx, confs) = make_sink();
        let event = ProtocolEvent::ToolRequest {
            msg_id: "m1".into(),
            call_id: "c1".into(),
            tool: ToolInfo {
                name: "Write".into(),
                category: ToolCategory::Edit,
                args: json!({"path": "/tmp/test.txt"}),
                description: "Write file /tmp/test.txt".into(),
                mcp: None,
            },
        };

        sink.emit(&event).unwrap();

        let received = rx.try_recv().unwrap();
        match received {
            AgentStreamEvent::AcpPermission(AcpPermissionEventData::Confirmation(conf)) => {
                assert_eq!(conf.call_id, "c1");
                assert!(conf.options.len() >= 3);
            }
            other => panic!("Expected AcpPermission(Confirmation), got {:?}", other),
        }

        let stored = confs.read().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].call_id, "c1");
    }

    #[test]
    fn tool_running_is_ignored() {
        let (sink, mut rx, _) = make_sink();
        let event = ProtocolEvent::ToolRunning {
            msg_id: "m1".into(),
            call_id: "c1".into(),
            tool_name: "Write".into(),
        };

        sink.emit(&event).unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn tool_cancelled_removes_confirmation_and_emits_error() {
        let (sink, mut rx, confs) = make_sink();

        let req = ProtocolEvent::ToolRequest {
            msg_id: "m1".into(),
            call_id: "c1".into(),
            tool: ToolInfo {
                name: "Bash".into(),
                category: ToolCategory::Exec,
                args: json!({"command": "rm -rf /"}),
                description: "Execute: rm -rf /".into(),
                mcp: None,
            },
        };
        sink.emit(&req).unwrap();
        let _ = rx.try_recv().unwrap();

        assert_eq!(confs.read().unwrap().len(), 1);

        let cancel = ProtocolEvent::ToolCancelled {
            msg_id: "m1".into(),
            call_id: "c1".into(),
            reason: "User denied".into(),
        };
        sink.emit(&cancel).unwrap();

        let received = rx.try_recv().unwrap();
        match received {
            AgentStreamEvent::ToolCall(data) => {
                assert_eq!(data.call_id, "c1");
                assert_eq!(data.status, ToolCallStatus::Error);
            }
            other => panic!("Expected ToolCall error, got {:?}", other),
        }

        assert_eq!(confs.read().unwrap().len(), 0);
    }

    #[test]
    fn other_events_are_ignored() {
        let (sink, mut rx, _) = make_sink();
        let event = ProtocolEvent::StreamStart { msg_id: "m1".into() };

        sink.emit(&event).unwrap();

        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn no_panic_when_no_receivers() {
        let (tx, _) = broadcast::channel(16);
        let confs = Arc::new(RwLock::new(Vec::new()));
        let sink = BackendProtocolSink::new(tx, confs);
        let event = ProtocolEvent::ToolRequest {
            msg_id: "m1".into(),
            call_id: "c1".into(),
            tool: ToolInfo {
                name: "Read".into(),
                category: ToolCategory::Info,
                args: json!({}),
                description: "Read file".into(),
                mcp: None,
            },
        };
        sink.emit(&event).unwrap();
    }

    #[test]
    fn confirmation_has_three_options() {
        let conf = BackendProtocolSink::build_confirmation(
            "c1",
            &ToolInfo {
                name: "Write".into(),
                category: ToolCategory::Edit,
                args: json!({"path": "/tmp/test.txt"}),
                description: "Write file /tmp/test.txt".into(),
                mcp: None,
            },
        );
        assert_eq!(conf.options.len(), 3);
        assert_eq!(conf.options[0].value, json!("proceed_once"));
        assert_eq!(conf.options[1].value, json!("proceed_always"));
        assert_eq!(conf.options[2].value, json!("cancel"));
        assert!(conf.mcp_identity.is_none());
    }

    #[test]
    fn mcp_confirmation_carries_raw_identity_but_escapes_visible_text() {
        let server_name = "studio\u{202e}res\nver";
        let tool_name = "raw\0tool";
        let conf = BackendProtocolSink::build_confirmation(
            "c1",
            &ToolInfo {
                name: "mcp__studio__raw_tool".into(),
                category: ToolCategory::Mcp,
                args: json!({}),
                description: "MCP request\u{202e}\n".into(),
                mcp: Some(McpToolInfo {
                    server_name: server_name.into(),
                    tool_name: tool_name.into(),
                    annotations: Default::default(),
                }),
            },
        );

        assert_eq!(
            conf.mcp_identity,
            Some(ConfirmationMcpIdentity {
                server_name: server_name.into(),
                tool_name: tool_name.into(),
            })
        );
        assert_eq!(
            conf.title.as_deref(),
            Some("mcp wants to use: studio\\u{202E}res\\u{000A}ver/raw\\u{0000}tool")
        );
        assert_eq!(conf.description, "MCP request\\u{202E}\\u{000A}");
        let always = &conf.options[1];
        assert_eq!(always.label, "messages.confirmation.yesAlwaysAllowTool");
        assert_eq!(always.value, json!("proceed_always"));
        assert_eq!(
            always.params.as_ref().and_then(|params| params.get("serverName")),
            Some(&"studio\\u{202E}res\\u{000A}ver".to_string())
        );
        assert_eq!(
            always.params.as_ref().and_then(|params| params.get("toolName")),
            Some(&"raw\\u{0000}tool".to_string())
        );
        assert!(
            conf.options
                .iter()
                .all(|option| option.label != "messages.confirmation.yesAlwaysAllowServer")
        );
    }

    #[test]
    fn mcp_without_structured_identity_does_not_offer_ambiguous_always_allow() {
        let conf = BackendProtocolSink::build_confirmation(
            "c1",
            &ToolInfo {
                name: "legacy_proxy_name".into(),
                category: ToolCategory::Mcp,
                args: json!({}),
                description: "MCP request".into(),
                mcp: None,
            },
        );

        assert!(conf.mcp_identity.is_none());
        assert_eq!(
            conf.options
                .iter()
                .map(|option| option.value.clone())
                .collect::<Vec<_>>(),
            vec![json!("proceed_once"), json!("cancel")]
        );
    }
}
