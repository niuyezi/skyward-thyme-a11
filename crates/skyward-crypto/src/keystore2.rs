//! Reading what the phone's key service was asked to keep. The service
//! holds each key under a name, and what it holds is the handle the secure
//! world knows the key by.

use anyhow::{Context, Result};
use std::path::Path;

/// Where the key service keeps what it was asked to keep.
pub const DATABASE: &str = "/data/misc/keystore/persistent.sqlite";

/// The kind of thing a row holds: the key itself rather than a certificate.
const KEY_BLOB: i64 = 0;

/// The handle the secure world knows the key named `alias` by. The
/// database is opened read-only, without being written to or waiting on
/// anyone, since the phone it belongs to is not running. It is not opened
/// as an immutable file: the key service keeps its latest writes in a log
/// beside the database until it folds them in, and a file read as
/// immutable is read without that log.
pub fn key_blob(database: &Path, alias: &str) -> Result<Vec<u8>> {
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
