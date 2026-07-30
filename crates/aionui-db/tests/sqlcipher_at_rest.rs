//! SECURITY (D-06): proves the conversation database is encrypted at rest with SQLCipher.
//!
//! These tests are the definitive check that `PRAGMA key` is actually honoured by the
//! sqlx connection (i.e. the shared libsqlite3-sys was built with SQLCipher): the raw
//! file must not carry the plaintext SQLite header, and the wrong/absent key must fail.

use aionui_db::{DatabaseInitOptions, init_database_with_options};

const TEST_KEY: [u8; 32] = [7u8; 32];

fn opts(key: Option<[u8; 32]>) -> DatabaseInitOptions {
    DatabaseInitOptions {
        recover_corrupted_database: false,
        encryption_key: key,
    }
}

#[tokio::test]
async fn encrypted_db_file_has_no_plaintext_sqlite_header() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("enc.db");

    {
        let db = init_database_with_options(&db_path, opts(Some(TEST_KEY)))
            .await
            .unwrap();
        db.close().await;
    }

    let bytes = std::fs::read(&db_path).unwrap();
    assert!(
        bytes.len() >= 16,
        "database file should contain the (encrypted) first page"
    );
    // A plain SQLite file begins with the magic string "SQLite format 3\0". A SQLCipher
    // database encrypts page 1 (including that header), so it must NOT be present.
    assert_ne!(
        &bytes[..16],
        b"SQLite format 3\0",
        "database file is NOT encrypted at rest — SQLCipher key was not applied"
    );
}

#[tokio::test]
async fn encrypted_db_requires_the_correct_key() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("enc.db");

    {
        let db = init_database_with_options(&db_path, opts(Some(TEST_KEY)))
            .await
            .unwrap();
        db.close().await;
    }

    // Wrong key must not open the encrypted database.
    let wrong_key = init_database_with_options(&db_path, opts(Some([9u8; 32]))).await;
    assert!(wrong_key.is_err(), "opening with the wrong key must fail");

    // No key at all (plain SQLite) must also fail on an encrypted file.
    let no_key = init_database_with_options(&db_path, opts(None)).await;
    assert!(no_key.is_err(), "opening an encrypted database without a key must fail");

    // The correct key reopens the database successfully.
    let correct = init_database_with_options(&db_path, opts(Some(TEST_KEY))).await;
    assert!(correct.is_ok(), "opening with the correct key must succeed");
}

/// Guards that the sqlx-linked SQLite is actually SQLCipher. `PRAGMA cipher_version`
/// returns a value only on SQLCipher builds; plain SQLite returns nothing. If this
/// regresses, at-rest encryption silently degrades to plaintext.
#[tokio::test]
async fn sqlx_sqlite_is_sqlcipher() {
    let db = aionui_db::init_database_memory().await.unwrap();
    let row: Option<(String,)> = sqlx::query_as("PRAGMA cipher_version")
        .fetch_optional(db.pool())
        .await
        .unwrap();
    assert!(
        row.is_some(),
        "sqlx must link SQLCipher (PRAGMA cipher_version returned nothing → plain SQLite)"
    );
}
