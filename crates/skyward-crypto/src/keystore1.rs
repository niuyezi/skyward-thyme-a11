//! Reading what the phone's key service was asked to keep, where it keeps
//! it as one file per key rather than in a database of its own.
//!
//! Android 11's key service keeps each key in a file of its own, named
//! after the user's own number, the kind of thing held, and the key's
//! name. The file holds a header and then the key: a key the phone counts
//! as part of its own encryption lies there as the secure world wrote it,
//! with nothing over it, since it has to be read before any user answers
//! their screen lock.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Where the key service keeps what it was asked to keep, for each user.
pub const STORE: &str = "/data/misc/keystore";

/// The kind of file that holds a key the secure world unwraps, rather than
/// a certificate or the phone's own master key.
const KEYMASTER_KEY: u8 = 4;

/// The flag that marks a key the phone counts as part of its own
/// encryption: it lies in the file as the secure world wrote it, with
/// nothing over it, and it is kept under the user's own number rather than
/// the number of an app.
const CRITICAL_TO_DEVICE_ENCRYPTION: u8 = 1 << 3;

/// The bytes of the header before the key: the version, the kind of thing
/// held, the flags, how long the description after the key is, the
/// encryption's starting point, its check, and how long the key is.
const HEADER: usize = 40;

/// The handle the secure world knows the key named `alias` by, for `user`.
/// The key service keeps the keys of the phone itself under the system's
/// own number, and the file holds the key as the secure world wrote it.
pub fn key_blob(store: &Path, user: u32, alias: &str) -> Result<Vec<u8>> {
    let at = PathBuf::from(store).join(format!("user_{user}")).join(format!("1000_USRPKEY_{alias}"));
    let raw = std::fs::read(&at).with_context(|| format!("read {}", at.display()))?;
    let (version, kind, flags, described) = (raw[0], raw[1], raw[2], raw[3]);
    anyhow::ensure!(version == 3, "{} is written in version {version}, and Skyward reads version 3", at.display());
    anyhow::ensure!(kind == KEYMASTER_KEY, "{} holds kind {kind}, and Skyward reads kind {KEYMASTER_KEY}", at.display());
    anyhow::ensure!(
        flags & (CRITICAL_TO_DEVICE_ENCRYPTION) != 0 && flags & 0b11 == 0,
        "{} is held under something over it, which Skyward does not read",
        at.display()
    );
    let length = u32::from_be_bytes(
        raw[36..40].try_into().expect("four bytes of the key's length"),
    ) as usize;
    anyhow::ensure!(
        raw.len() == HEADER + length + described as usize,
        "{} is {} bytes, and its own numbers say {}",
        at.display(),
        raw.len(),
        HEADER + length + described as usize
    );
    Ok(raw[HEADER..HEADER + length].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file as the key service writes one for a key of the phone's own
    /// encryption: the header, then the key, then the description.
    fn written(key: &[u8], description: &[u8]) -> Vec<u8> {
        let mut raw = vec![0; HEADER];
        raw[0] = 3;
        raw[1] = KEYMASTER_KEY;
        raw[2] = CRITICAL_TO_DEVICE_ENCRYPTION;
        raw[3] = description.len() as u8;
        raw[36..40].copy_from_slice(&(key.len() as u32).to_be_bytes());
        raw.extend_from_slice(key);
        raw.extend_from_slice(description);
        raw
    }

    #[test]
    fn a_key_of_the_phones_own_encryption_is_read_as_it_lies() {
        let at = std::env::temp_dir().join(format!("skyward-keystore1-{}-{}.blob", std::process::id(), line!()));
        std::fs::write(&at, written(&[0x85, 0x1a, 0x4b, 0x4d], b"")).unwrap();
        let key = key_blob(at.parent().unwrap(), 0, "synthetic_password_2f6a49a84bc74855").unwrap();
        assert_eq!(key, vec![0x85, 0x1a, 0x4b, 0x4d]);
        let _ = std::fs::remove_file(&at);
    }

    #[test]
    fn a_key_held_under_something_over_it_is_refused() {
        let at = std::env::temp_dir().join(format!("skyward-keystore1-{}-{}.blob", std::process::id(), line!()));
        let mut over = written(&[1, 2, 3], b"");
        over[2] |= 0b1;
        std::fs::write(&at, over).unwrap();
        let refused = key_blob(at.parent().unwrap(), 0, "synthetic_password_2f6a49a84bc74855");
        assert!(refused.is_err(), "a key held under the master key is not read as it lies");
        let _ = std::fs::remove_file(&at);
    }
}
