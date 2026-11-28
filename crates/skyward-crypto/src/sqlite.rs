//! Opening one of the phone's own stores to read, and leaving it as it
//! lies.
//!
//! The phone writes its stores as sqlite databases with a log beside them
//! (`-wal`), and keeps its latest writes in that log until it folds them
//! in. A store opened read-only is read through its log, so what it answers
//! is what the phone last wrote. A store opened as an immutable file is
//! read without its log, and answers with a value the phone has already
//! replaced; that is the wrong answer, so it is not how these are opened
//! while the log is there to be read.
//!
//! Reading through the log needs the shared-memory file beside it
//! (`-shm`), which the phone leaves there. Where a phone has been started
//! in a way that took that file and left the log, the log cannot be read;
//! then, and only then, the store is read as it lies without it, which at
//! least answers what was folded in.

use anyhow::{Context, Result};
use std::path::Path;

/// The flags every store is opened with: read-only, and naming the file as
/// a URI so it can be asked for read-only in the name too.
fn flags() -> rusqlite::OpenFlags {
    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI
}

/// Open the store at `path` to read, seeing what its log holds.
pub fn read_only(path: &Path) -> Result<rusqlite::Connection> {
    let at = format!("file:{}?mode=ro", path.display());
    match rusqlite::Connection::open_with_flags(&at, flags()) {
        Ok(db) => Ok(db),
        Err(e) => {
            // The log is there but its shared-memory file is not, so the
            // log cannot be read. Read the store as it lies instead of
            // failing outright.
            let immutable = format!("file:{}?immutable=1", path.display());
            rusqlite::Connection::open_with_flags(&immutable, flags())
                .with_context(|| format!("open {} (read-only failed first: {e})", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_store_is_read_through_its_log() {
        let at = std::env::temp_dir().join(format!("skyward-sqlite-{}-{}.db", std::process::id(), line!()));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", at.display()));
        }
        // The writer stays open, so what it writes stays in the log rather
        // than being folded in.
        let writer = rusqlite::Connection::open(&at).unwrap();
        writer.pragma_update(None, "journal_mode", "wal").unwrap();
        writer.execute("CREATE TABLE t (k TEXT, v TEXT)", ()).unwrap();
        writer.execute("INSERT INTO t VALUES ('a', 'old')", ()).unwrap();
        writer.execute("UPDATE t SET v = 'new' WHERE k = 'a'", ()).unwrap();

        let db = read_only(&at).unwrap();
        let v: String = db.query_row("SELECT v FROM t WHERE k = 'a'", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "new", "the value the phone last wrote, from the log");

        drop(db);
        drop(writer);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", at.display()));
        }
    }
}
