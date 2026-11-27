//! The phone's key service of the older kind, a hardware service: the
//! Keymaster that Android 11 and earlier carry, where Android 12 and later
//! carry KeyMint. The two do the same work for this program — unwrap a key
//! the storage hardware holds and undo an AES-GCM encryption it made — but
//! they are reached and laid out differently: KeyMint registers with the
//! service directory and speaks the newer parcel, while Keymaster is a
//! hardware service reached over hwbinder, and every call to it carries its
//! version in the interface name and lays its values out in the older HIDL
//! message.
//!
//! Only the parts this program uses are here: what the phone says about its
//! key hardware, what a key may be used for, opening a decryption and
//! feeding it, renewing a key the running firmware has outgrown, and the
//! note a screen lock leaves for a key it guards.

use crate::keymint::{Hardware, NONCE_BYTES};
use crate::token::Token;
use anyhow::{bail, Context, Result};
use skyward_binder::driver::{Binder, Handle};
use skyward_binder::hidl::{self, Answer, Message};

/// The interface, by the version that also carries the methods the others
/// added. Each call is made under the name of the version that introduced
/// the method, which the service checks.
pub const HARDWARE_SERVICE: &str = "android.hardware.keymaster@4.0::IKeymasterDevice";
const INSTANCE: &str = "default";

/// The methods, numbered in the order the interface declares them. The
/// later versions append to this, so these numbers hold for every one.
const GET_HARDWARE_INFO: u32 = 1;
const GET_KEY_CHARACTERISTICS: u32 = 9;
const UPGRADE_KEY: u32 = 12;
const BEGIN: u32 = 16;
const UPDATE: u32 = 17;
const FINISH: u32 = 18;
const ABORT: u32 = 19;

/// The key service's way of saying the key was made under an older build of
/// the phone's own firmware and has to be renewed before it will be used.
const KEY_REQUIRES_UPGRADE: i32 = -62;

/// What a key is used for, and how, in the values the tags carry.
const PURPOSE_DECRYPT: i32 = 1;
const BLOCK_MODE_GCM: i32 = 32;
const PADDING_NONE: i32 = 1;

/// What a key parameter is tagged with. The high bits say which kind of
/// value follows. These are the same tags KeyMint uses, by the same
/// numbers, because both were carried over from Keymaster 3 unchanged.
const TAG_PURPOSE: i32 = 536_870_913;
const TAG_BLOCK_MODE: i32 = 536_870_916;
const TAG_PADDING: i32 = 536_870_918;
const TAG_MAC_LENGTH: i32 = 805_307_371;
const TAG_APPLICATION_ID: i32 = -1_879_047_591;
const TAG_NONCE: i32 = -1_879_047_191;

/// The tag's value: a number, or bytes carried beside the union. The tag
/// alone says which of the two follows, so no arm is named.
enum Value<'a> {
    Integer(i32),
    Blob(&'a [u8]),
}

/// Write one key parameter the way HIDL lays out a `KeyParameter`: the
/// tag, then the union of the older kind, which names no arm of its own —
/// the tag alone says which value follows — then a blob carried beside
/// the union. The union is as wide as its widest arm, a `u64`, so a
/// narrower value is written in the low bytes and the rest left at
/// nothing.
fn parameter(m: &mut Message, tag: i32, value: Value<'_>) {
    m.i32(tag);
    // The union is 8 bytes wide, as wide as its widest arm; the value is
    // written in the low bytes and the rest left at nothing.
    match &value {
        Value::Integer(v) => {
            m.i32(*v);
            m.i32(0);
        }
        // A blob is not in the union at all: the union is left at nothing
        // and the bytes follow as a vector of their own.
        Value::Blob(_) => {
            m.i32(0);
            m.i32(0);
        }
    }
    match &value {
        Value::Blob(v) => m.bytes(v),
        _ => m.bytes(&[]),
    }
}

/// Write a run of key parameters: how many, then each.
fn parameters(m: &mut Message, list: &[(i32, Value<'_>)]) {
    m.i32(list.len() as i32);
    for (tag, value) in list {
        // `Value` is not `Copy`; each is rebuilt from what the list holds.
        match value {
            Value::Integer(v) => parameter(m, *tag, Value::Integer(*v)),
            Value::Blob(v) => parameter(m, *tag, Value::Blob(v)),
        }
    }
}

/// Hand over the note the secure world wrote when the user answered their
/// screen lock. A key guarded by the screen lock is refused without it. An
/// empty note is written as an empty token, which a key that is not guarded
/// takes and is refused nothing for carrying.
fn vouched(m: &mut Message, note: Option<&Token>) {
    let Some(note) = note else {
        // An empty token: every field at nothing, and no mac.
        m.u64(0);
        m.u64(0);
        m.u64(0);
        m.i32(0);
        m.i32(0);
        m.u64(0);
        m.bytes(&[]);
        return;
    };
    m.u64(note.challenge as u64);
    m.u64(note.user as u64);
    m.u64(note.authenticator as u64);
    m.i32(note.kind);
    // The type is a word of its own, and the timestamp that follows is
    // eight wide, so a word of padding comes between them.
    m.i32(0);
    m.u64(note.when as u64);
    m.bytes(&note.mac);
}

/// The phone's key service of the older kind, as this program talks to it.
pub struct Keymaster<'a> {
    device: Handle<'a>,
}

impl<'a> Keymaster<'a> {
    /// Reach the running key service, or say that none is.
    pub fn open(hardware: &'a Binder) -> Result<Keymaster<'a>> {
        let device = hidl::find(hardware, HARDWARE_SERVICE, INSTANCE)?
            .with_context(|| format!("{HARDWARE_SERVICE} is not running; the phone's key service has to be started first"))?;
        Ok(Keymaster { device })
    }

    pub fn hardware(&self) -> Result<Hardware> {
        let call = Message::call(HARDWARE_SERVICE);
        let reply = self.device.transact(GET_HARDWARE_INFO, &call).context("ask the key service about itself")?;
        let mut read = Answer::new(reply.bytes());
        let level = read.i32().context("read the security level")?;
        let name = read.text().context("read the key service's name")?;
        let author = read.text().context("read the key service's author")?;
        Ok(Hardware { version: 4, security_level: level, name, author })
    }

    /// Android 11 stores a key blob the hardware holds whole, and hands it
    /// straight back to begin() or upgradeKey(); there is no
    /// convertStorageKey as KeyMint has. So a storage key is already in the
    /// form this start of the phone takes, and is given back as it is.
    pub fn ephemeral_storage_key(&self, key: &[u8]) -> Result<Vec<u8>> {
        Ok(key.to_vec())
    }

    /// What the key service says a key may be used for: each entry is a tag
    /// and the number or length that came with it.
    pub fn authorizations(&self, key_blob: &[u8], app_id: &[u8]) -> Result<Vec<(i32, i64)>> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.bytes(key_blob);
        call.bytes(app_id);
        call.bytes(&[]);
        let reply = self.device.transact(GET_KEY_CHARACTERISTICS, &call).context("ask what the key may be used for")?;
        let mut read = Answer::new(reply.bytes());
        let code = read.i32().context("read how the key service took the call")?;
        if code != 0 {
            bail!("{}", fault(code));
        }
        // The answer is a KeyCharacteristics: two vectors, the software's
        // and the hardware's.
        let mut out = Vec::new();
        for _ in 0..2 {
            for _ in 0..read.i32().context("read how many parameters a key has")?.max(0) {
                out.push(read.parameter()?);
            }
        }
        Ok(out)
    }

    /// Undo an AES-GCM encryption the key service did with `key_blob`.
    pub fn gcm_decrypt(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], body: &[u8], note: Option<&Token>) -> Result<Vec<u8>> {
        let operation = match self.begin(key_blob, app_id, nonce, note) {
            Ok(operation) => operation,
            Err(e) if refused_with(&e) == Some(KEY_REQUIRES_UPGRADE) => {
                let renewed = self.upgrade(key_blob, app_id, nonce).context("renew the key for the firmware running now")?;
                self.begin(&renewed, app_id, nonce, note)?
            }
            Err(e) => return Err(e),
        };
        let mut out = self.update(&operation, body)?;
        out.extend_from_slice(&self.finish(&operation)?);
        Ok(out)
    }

    /// What the key service has to be told to use an AES-GCM key.
    fn gcm_params(m: &mut Message, app_id: &[u8], nonce: &[u8]) {
        let mut list = vec![
            (TAG_BLOCK_MODE, Value::Integer(BLOCK_MODE_GCM)),
            (TAG_PADDING, Value::Integer(PADDING_NONE)),
            (TAG_MAC_LENGTH, Value::Integer(128)),
        ];
        if !app_id.is_empty() {
            list.push((TAG_APPLICATION_ID, Value::Blob(app_id)));
        }
        list.push((TAG_NONCE, Value::Blob(nonce)));
        list.push((TAG_PURPOSE, Value::Integer(PURPOSE_DECRYPT)));
        parameters(m, &list);
    }

    /// Open a decryption with the key service and keep hold of it. The
    /// operation is a separate object, reached by a handle the reply names.
    fn begin(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], note: Option<&Token>) -> Result<Handle<'a>> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.i32(PURPOSE_DECRYPT);
        call.bytes(key_blob);
        Self::gcm_params(&mut call, app_id, nonce);
        vouched(&mut call, note);
        let reply = self.device.transact(BEGIN, &call).context("start a decryption")?;
        let mut read = Answer::new(reply.bytes());
        let code = read.i32().context("read how the key service took the start")?;
        if code != 0 {
            bail!("{}", fault(code));
        }
        // The answer is the out-parameters, then the handle of the
        // operation. Step over the parameters; the handle is what is kept.
        for _ in 0..read.i32().context("read how many parameters the start answered")?.max(0) {
            read.parameter()?;
        }
        match read.object().context("read the decryption the key service opened")? {
            Some(h) => Handle::hold(reply.binder(), h),
            None => bail!("the key service opened no decryption"),
        }
    }

    /// A key for the firmware running now, from one made under an older
    /// build.
    fn upgrade(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.bytes(key_blob);
        Self::gcm_params(&mut call, app_id, nonce);
        let reply = self.device.transact(UPGRADE_KEY, &call).context("renew the key")?;
        let mut read = Answer::new(reply.bytes());
        let code = read.i32().context("read how the key service took the renewal")?;
        if code != 0 {
            bail!("{}", fault(code));
        }
        Ok(read.pointed().context("read the renewed key")?.to_vec())
    }

    fn update(&self, operation: &Handle, input: &[u8]) -> Result<Vec<u8>> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.u64(operation.number());
        parameters(&mut call, &[]);
        call.bytes(input);
        vouched(&mut call, None);
        // The verification token: none.
        call.bytes(&[]);
        let reply = operation.transact(UPDATE, &call).context("feed the decryption")?;
        let mut read = Answer::new(reply.bytes());
        let code = read.i32().context("read how the decryption took the input")?;
        if code != 0 {
            bail!("{}", fault(code));
        }
        // The input consumed, the out-parameters, then the output.
        read.i32().context("read how much input was taken")?;
        for _ in 0..read.i32().context("read how many parameters the decryption answered")?.max(0) {
            read.parameter()?;
        }
        Ok(read.pointed().context("read what the decryption gave back")?.to_vec())
    }

    fn finish(&self, operation: &Handle) -> Result<Vec<u8>> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.u64(operation.number());
        parameters(&mut call, &[]);
        call.bytes(&[]);
        call.bytes(&[]);
        vouched(&mut call, None);
        call.bytes(&[]);
        let reply = operation.transact(FINISH, &call).context("close the decryption")?;
        let mut read = Answer::new(reply.bytes());
        let code = read.i32().context("read how the decryption ended")?;
        if code != 0 {
            bail!("{}", fault(code));
        }
        for _ in 0..read.i32().context("read how many parameters the end answered")?.max(0) {
            read.parameter()?;
        }
        Ok(read.pointed().context("read what the decryption ended with")?.to_vec())
    }

    /// Whether the secure world will unwrap the key at all: a decryption is
    /// opened on it under a nonce of nothing and dropped again, which reads
    /// nothing and changes nothing.
    pub fn usable(&self, key_blob: &[u8], app_id: &[u8]) -> Result<()> {
        let operation = self.begin(key_blob, app_id, &[0; NONCE_BYTES], None)?;
        let mut call = Message::call(HARDWARE_SERVICE);
        call.u64(operation.number());
        operation.transact(ABORT, &call)?;
        Ok(())
    }
}

/// What the key service's error number means, in this program's words.
fn fault(code: i32) -> String {
    match code {
        KEY_REQUIRES_UPGRADE => "the key was made under an older build of the phone's firmware and has to be renewed".into(),
        other => format!("the key service refused the call with its error {other}"),
    }
}

/// The key service's own number for why it refused, where the failure came
/// from the service rather than from this program.
fn refused_with(e: &anyhow::Error) -> Option<i32> {
    for cause in e.chain() {
        let said = cause.to_string();
        if let Some(rest) = said.strip_prefix("the key service refused the call with its error ") {
            if let Ok(code) = rest.trim().parse::<i32>() {
                return Some(code);
            }
        }
        if said.contains("has to be renewed") {
            return Some(KEY_REQUIRES_UPGRADE);
        }
    }
    None
}
