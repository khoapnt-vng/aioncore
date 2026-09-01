use std::borrow::Cow;
use std::path::Path;

use sqlx::migrate::Migrator;
use sqlx::sqlite::SqlitePoolOptions;

async fn run_migrations_through(pool: &sqlx::SqlitePool, max_version: i64) {
    let full = Migrator::new(Path::new("migrations")).await.unwrap();
    let migrations = full
        .migrations
        .iter()
        .filter(|migration| migration.version <= max_version)
        .cloned()
        .collect::<Vec<_>>();
    Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
    .run(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn migration_028_adds_nullable_client_id_without_changing_legacy_token_bytes() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    run_migrations_through(&pool, 27).await;

    sqlx::query(
        "INSERT INTO oauth_tokens (
            server_url, access_token, refresh_token, token_type, expires_at, created_at, updated_at
         ) VALUES (?, ?, ?, 'bearer', 1700000000000, 1, 1)",
    )
    .bind("https://legacy.example.com")
    .bind("enc_access_exact_bytes")
    .bind("enc_refresh_exact_bytes")
    .execute(&pool)
    .await
    .unwrap();

    run_migrations_through(&pool, 28).await;

    let row: (String, String, Option<String>) = sqlx::query_as(
        "SELECT access_token, refresh_token, client_id
         FROM oauth_tokens
         WHERE server_url = 'https://legacy.example.com'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.0, "enc_access_exact_bytes");
    assert_eq!(row.1, "enc_refresh_exact_bytes");
    assert_eq!(row.2, None);
}
