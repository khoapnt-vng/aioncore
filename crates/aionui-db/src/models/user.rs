use aionui_common::TimestampMs;
use serde::{Deserialize, Serialize};

/// Row mapping for the `users` table.
///
/// All fields match the SQLite column names and types exactly.
/// Optional fields correspond to nullable columns.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    // SECURITY (D-02): never serialize secret material out over HTTP. `skip_serializing`
    // only affects JSON *output*; `sqlx::FromRow`, `Deserialize`, and direct field access
    // (password verification, JWT-secret resolution) are unaffected, so internal use keeps
    // working while the internal `/api/auth/internal/users*` handlers stop leaking these.
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub avatar_path: Option<String>,
    #[serde(skip_serializing)]
    pub jwt_secret: Option<String>,
    pub created_at: TimestampMs,
    pub updated_at: TimestampMs,
    pub last_login: Option<TimestampMs>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SECURITY (D-02): serializing a `User` must never expose secret material.
    /// Guards the `skip_serializing` attributes on `password_hash` / `jwt_secret`.
    #[test]
    fn user_serialization_omits_secret_fields() {
        let user = User {
            id: "u1".to_string(),
            username: "alice".to_string(),
            email: Some("alice@example.com".to_string()),
            password_hash: "argon2$super-secret-hash".to_string(),
            avatar_path: None,
            jwt_secret: Some("top-secret-jwt-key".to_string()),
            created_at: 0,
            updated_at: 0,
            last_login: None,
        };

        let value = serde_json::to_value(&user).expect("serialize user");
        let obj = value.as_object().expect("user serializes to an object");

        assert!(
            !obj.contains_key("password_hash"),
            "password_hash must not be serialized"
        );
        assert!(!obj.contains_key("jwt_secret"), "jwt_secret must not be serialized");
        // Non-secret fields still serialize.
        assert_eq!(obj.get("id").and_then(|v| v.as_str()), Some("u1"));
        assert_eq!(obj.get("username").and_then(|v| v.as_str()), Some("alice"));

        // The raw JSON string must not contain the secret values anywhere.
        let json = serde_json::to_string(&user).expect("serialize user to string");
        assert!(!json.contains("super-secret-hash"), "hash value leaked into JSON");
        assert!(!json.contains("top-secret-jwt-key"), "jwt secret leaked into JSON");
    }
}
