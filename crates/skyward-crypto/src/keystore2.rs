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
/// database is opened as it lies, without being written to or waiting on
/// anyone, since the phone it belongs to is not running.
pub fn key_blob(database: &Path, alias: &str) -> Result<Vec<u8>> {
    let at = format!("file:{}?immutable=1", database.display());
    let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI;
    let db = rusqlite::Connection::open_with_flags(&at, flags)
        .with_context(|| format!("open {}", database.display()))?;
    let mut query = db
        .prepare(
            "SELECT b.blob FROM blobentry b JOIN keyentry k ON b.keyentryid = k.id
             WHERE k.alias = ?1 AND b.subcomponent_type = ?2 ORDER BY b.id DESC LIMIT 1",
        )
        .context("ask the key service's store for a key")?;
    let mut rows = query
        .query((alias, KEY_BLOB))
        .context("ask the key service's store for a key")?;
    let row = rows
        .next()
        .with_context(|| format!("read what {} says about {alias}", database.display()))?
        .with_context(|| format!("{} holds no key named {alias}", database.display()))?;
    row.get(0)
        .with_context(|| format!("read the key named {alias}"))
        // **The store writes a word in front of the blob the hardware made.**
        // What it keeps is that word and then the blob, which is what a key
        // directory on the data partition holds too; the hardware wants the
        // blob alone, and answers "invalid key blob" to the wrapper.
        .map(crate::keystore::bare_blob)
}
