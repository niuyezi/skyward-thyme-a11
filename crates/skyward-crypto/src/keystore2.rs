//! Reading what the phone's key service was asked to keep. The service
//! holds each key under a name, and what it holds is the handle the secure
//! world knows the key by.

use anyhow::{Context, Result};
use std::path::Path;

/// Where the key service keeps what it was asked to keep.
pub const DATABASE: &str = "/data/misc/keystore/persistent.sqlite";

/// Where it kept the same thing before it kept a database of its own, as
/// Android 11 does: one file per key.
pub const STORE: &str = crate::keystore1::STORE;

/// The kind of thing a row holds: the key itself rather than a certificate.
const KEY_BLOB: i64 = 0;

/// The handle the secure world knows the key named `alias` by, for `user`.
/// The key service keeps its latest writes in a log beside the database
/// until it folds them in, and a file read as an immutable file is read
/// without that log, so the database is read through its log where there
/// is one. A phone whose key service kept no database, as Android 11's
/// did not, keeps the key in a file of its own instead.
pub fn key_blob(database: &Path, alias: &str) -> Result<Vec<u8>> {
    let store = database.parent().unwrap_or(Path::new(STORE));
    match database.is_file() {
        true => from_database(database, alias),
        false => crate::keystore1::key_blob(store, 0, alias),
    }
}

/// The handle the secure world knows the key named `alias` by, from the
/// key service's database. It is opened read-only, without being written
/// to or waiting on anyone, since the phone it belongs to is not running.
fn from_database(database: &Path, alias: &str) -> Result<Vec<u8>> {
    let db = crate::sqlite::read_only(database)?;
    let mut query = db
        .prepare(
            "SELECT b.blob FROM blobentry b JOIN keyentry k ON b.keyentryid = k.id
             WHERE k.alias = ?1 AND b.subcomponent_type = ?2 ORDER BY b.id DESC LIMIT 1",
        )
        .context("ask the key service's store for a key")?;
    let mut rows = query.query((alias, KEY_BLOB)).context("ask the key service's store for a key")?;
    let row = rows
        .next()
        .with_context(|| format!("read what {} says about {alias}", database.display()))?
        .with_context(|| format!("{} holds no key named {alias}", database.display()))?;
    row.get(0).with_context(|| format!("read the key named {alias}"))
}
