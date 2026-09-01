-- Core-authenticated trust snapshots are stored outside the
-- caller-shaped conversation.extra document. Existing rows remain NULL and
-- therefore untrusted after upgrade.
ALTER TABLE conversations
ADD COLUMN verified_session_mcp_trust TEXT NULL;
