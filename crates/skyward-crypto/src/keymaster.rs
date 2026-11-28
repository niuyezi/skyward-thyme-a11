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

/// How a `KeyParameter` lies in memory, the way HIDL lays the structure
/// out: the tag, then padding to the eight-byte boundary the union sits
/// on, the union of the older kind, then a `vec<uint8_t>` blob with its
/// pointer first. Where the blob points lives apart, as an object of its
/// own inside this one.
const TAG_POS: usize = 0;
const UNION_POS: usize = 8;
const BLOB_VEC_POS: usize = 16;
const KEY_PARAMETER_BYTES: usize = 32;

/// How a `KeyCharacteristics` lies in memory: two `vec<KeyParameter>`, each
/// as wide as a vec is — where its elements lie, how many there are, and
/// whether whoever holds it frees them.
const SOFTWARE_VEC_BYTES: usize = 16;
const KEY_CHARACTERISTICS_BYTES: usize = 2 * SOFTWARE_VEC_BYTES;

/// A key parameter's cell and the bytes its blob points at. The blob's
/// pointer field is left at nothing; whoever writes the parameters apart
/// points it at the object that holds the blob.
fn parameter_blob(tag: i32, value: &Value<'_>) -> ([u8; KEY_PARAMETER_BYTES], Vec<u8>) {
    let mut cell = [0u8; KEY_PARAMETER_BYTES];
    cell[TAG_POS..TAG_POS + 4].copy_from_slice(&tag.to_le_bytes());
    let blob = match value {
        Value::Integer(v) => {
            cell[UNION_POS..UNION_POS + 4].copy_from_slice(&v.to_le_bytes());
            Vec::new()
        }
        Value::Blob(v) => v.to_vec(),
    };
    (cell, blob)
}

/// Write a run of key parameters as a `vec<KeyParameter>`: the vector's
/// frame, the array of its elements, then one object per element for the
/// blob that element carries. The blob is written for every element, empty
/// or not, because the far side reads one for every element.
fn parameters(m: &mut Message, list: &[(i32, Value<'_>)]) {
    let count = list.len() as u32;
    let mut data = Vec::with_capacity(count as usize * KEY_PARAMETER_BYTES);
    let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(count as usize);
    for (tag, value) in list {
        let (cell, blob) = parameter_blob(*tag, value);
        data.extend_from_slice(&cell);
        blobs.push(blob);
    }
    let children: Vec<(usize, &[u8])> = blobs
        .iter()
        .enumerate()
        .map(|(i, blob)| (i * KEY_PARAMETER_BYTES + BLOB_VEC_POS, blob.as_slice()))
        .collect();
    m.vec_with(count, &mut data, &children);
}

/// Read the elements of a `vec<KeyParameter>` whose array has just been
/// taken, along with the blob each element carries. The blob is written for
/// every element, empty or not, so one address follows per element.
///
/// What is answered is each element's tag and the number it carries, or,
/// for a blob, how long it is, which is all this program reads of a key's
/// authorizations.
fn elements(read: &mut Answer, count: usize, cells: &[u8]) -> Result<Vec<(i32, i64)>> {
    if cells.len() < count * KEY_PARAMETER_BYTES {
        bail!("the key service said it answered {count} parameters in {} bytes", cells.len());
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let cell = &cells[i * KEY_PARAMETER_BYTES..(i + 1) * KEY_PARAMETER_BYTES];
        let tag = i32::from_le_bytes(cell[TAG_POS..TAG_POS + 4].try_into().expect("four bytes"));
        let number = i32::from_le_bytes(cell[UNION_POS..UNION_POS + 4].try_into().expect("four bytes")) as i64;
        let blob = read.pointed().context("read the blob a parameter carries")?;
        out.push((tag, if blob.is_empty() { number } else { blob.len() as i64 }));
    }
    Ok(out)
}

/// Read a `vec<KeyParameter>` the key service answered with as a value of
/// its own: the frame saying where the elements lie and how many there are,
/// then the elements' array.
fn answered_parameters(read: &mut Answer) -> Result<Vec<(i32, i64)>> {
    let (count, cells) = read.run().context("read the parameters a key answered with")?;
    elements(read, count, cells)
}

/// Read a `vec<KeyParameter>` that lies inside a structure the key service
/// answered with. A vec inside a structure is written as its elements' array
/// alone — the count travels in the structure, where the vec's own size
/// field lies — so what has already been read is the array and the count.
fn embedded_parameters(read: &mut Answer, count: usize) -> Result<Vec<(i32, i64)>> {
    let cells = read.pointed().context("read the parameters a key answered with")?;
    elements(read, count, cells)
}

/// How a `HardwareAuthToken` lies in memory: three eight-byte numbers, the
/// authenticator type in a word of its own, padding to the eight the
/// timestamp sits on, then a `vec<uint8_t>` mac with its pointer first.
const HAT_CHALLENGE_POS: usize = 0;
const HAT_USER_POS: usize = 8;
const HAT_AUTHENTICATOR_POS: usize = 16;
const HAT_KIND_POS: usize = 24;
const HAT_TIMESTAMP_POS: usize = 32;
const HAT_MAC_VEC_POS: usize = 40;
const HAT_BYTES: usize = 56;

/// Hand over the note the secure world wrote when the user answered their
/// screen lock. A key guarded by the screen lock is refused without it. An
/// empty note is written as an empty token, which a key that is not guarded
/// takes and is refused nothing for carrying.
///
/// The mac is a vec whether it holds anything or not, and the far side
/// reads one for it either way: a token written without one leaves the far
/// side reading past the end of the call. So an empty mac is written as a
/// vec of nothing rather than left out.
fn vouched(m: &mut Message, note: Option<&Token>) {
    let mut cell = [0u8; HAT_BYTES];
    let mac: Vec<u8>;
    if let Some(note) = note {
        cell[HAT_CHALLENGE_POS..HAT_CHALLENGE_POS + 8].copy_from_slice(&(note.challenge as u64).to_le_bytes());
        cell[HAT_USER_POS..HAT_USER_POS + 8].copy_from_slice(&(note.user as u64).to_le_bytes());
        cell[HAT_AUTHENTICATOR_POS..HAT_AUTHENTICATOR_POS + 8].copy_from_slice(&(note.authenticator as u64).to_le_bytes());
        cell[HAT_KIND_POS..HAT_KIND_POS + 4].copy_from_slice(&note.kind.to_le_bytes());
        cell[HAT_TIMESTAMP_POS..HAT_TIMESTAMP_POS + 8].copy_from_slice(&(note.when as u64).to_le_bytes());
        mac = note.mac.to_vec();
    } else {
        mac = Vec::new();
    }
    let children = [(HAT_MAC_VEC_POS, mac.as_slice())];
    m.object_with(&mut cell, &children);
}

/// How a `VerificationToken` lies in memory: the operation handle, the
/// secure world's own time, a `vec<KeyParameter>` of what it verified, the
/// security level in a word of its own, padding, then a `vec<uint8_t>` mac.
const VT_CHALLENGE_POS: usize = 0;
const VT_TIMESTAMP_POS: usize = 8;
const VT_PARAMETERS_POS: usize = 16;
const VT_LEVEL_POS: usize = 32;
const VT_MAC_VEC_POS: usize = 40;
const VT_BYTES: usize = 56;

/// Hand over the token that proves another key service verified something.
/// None of it is asked for here, and a token of nothing is written as one of
/// nothing: every number at nothing and both of its vectors empty. The far
/// side reads both vectors whether they hold anything or not.
fn verified(m: &mut Message) {
    let mut cell = [0u8; VT_BYTES];
    let empty: &[u8] = &[];
    let children = [(VT_PARAMETERS_POS, empty), (VT_MAC_VEC_POS, empty)];
    m.object_with(&mut cell, &children);
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

    /// Ask the key service about itself. This call answers no error code of
    /// its own: the level, the name and the author are the whole of it.
    pub fn hardware(&self) -> Result<Hardware> {
        let call = Message::call(HARDWARE_SERVICE);
        let reply = self.device.transact(GET_HARDWARE_INFO, &call).context("ask the key service about itself")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("ask the key service about itself")?;
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
        read.status().context("ask what the key may be used for")?;
        let code = read.i32().context("read how the key service took the call")?;
        if code != 0 {
            bail!("{}", fault(code));
        }
        // The answer is a KeyCharacteristics: a structure of two vecs, the
        // software's and the hardware's. The structure is written as one
        // value; each vec inside it is written as its elements' array alone,
        // with the count kept in the structure where that vec's size lies.
        let cells = read.pointed().context("read the lists a key's parameters lie in")?;
        if cells.len() < KEY_CHARACTERISTICS_BYTES {
            bail!("a key's parameter lists came in {} bytes", cells.len());
        }
        let count_at = |at: usize| u32::from_le_bytes(cells[at + 8..at + 12].try_into().expect("four bytes")) as usize;
        let (software, hardware) = (count_at(0), count_at(SOFTWARE_VEC_BYTES));
        let mut out = embedded_parameters(&mut read, software)?;
        out.extend(embedded_parameters(&mut read, hardware)?);
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
        let mut out = self.update(operation, body)?;
        out.extend_from_slice(&self.finish(operation)?);
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

    /// Open a decryption with the key service. The operation is a number the
    /// key service names, not an object of its own: every later call on it
    /// goes to the same service and carries the number as a plain value.
    fn begin(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8], note: Option<&Token>) -> Result<u64> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.i32(PURPOSE_DECRYPT);
        call.bytes(key_blob);
        Self::gcm_params(&mut call, app_id, nonce);
        vouched(&mut call, note);
        let reply = self.device.transact(BEGIN, &call).context("start a decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("start a decryption")?;
        let code = read.i32().context("read how the key service took the start")?;
        if code != 0 {
            bail!("{}", fault(code));
        }
        // The answer is the out-parameters, then the number of the
        // operation. Step over the parameters; the number is what is kept.
        answered_parameters(&mut read).context("read what the start answered with")?;
        read.u64().context("read the decryption the key service opened")
    }

    /// A key for the firmware running now, from one made under an older
    /// build.
    fn upgrade(&self, key_blob: &[u8], app_id: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.bytes(key_blob);
        Self::gcm_params(&mut call, app_id, nonce);
        let reply = self.device.transact(UPGRADE_KEY, &call).context("renew the key")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("renew the key")?;
        let code = read.i32().context("read how the key service took the renewal")?;
        if code != 0 {
            bail!("{}", fault(code));
        }
        Ok(read.blob().context("read the renewed key")?.to_vec())
    }

    fn update(&self, operation: u64, input: &[u8]) -> Result<Vec<u8>> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.u64(operation);
        parameters(&mut call, &[]);
        call.bytes(input);
        vouched(&mut call, None);
        verified(&mut call);
        let reply = self.device.transact(UPDATE, &call).context("feed the decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("feed the decryption")?;
        let code = read.i32().context("read how the decryption took the input")?;
        if code != 0 {
            bail!("{}", fault(code));
        }
        // The input consumed, the out-parameters, then the output.
        read.i32().context("read how much input was taken")?;
        answered_parameters(&mut read).context("read what the decryption answered with")?;
        Ok(read.blob().context("read what the decryption gave back")?.to_vec())
    }

    fn finish(&self, operation: u64) -> Result<Vec<u8>> {
        let mut call = Message::call(HARDWARE_SERVICE);
        call.u64(operation);
        parameters(&mut call, &[]);
        call.bytes(&[]);
        call.bytes(&[]);
        vouched(&mut call, None);
        verified(&mut call);
        let reply = self.device.transact(FINISH, &call).context("close the decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("close the decryption")?;
        let code = read.i32().context("read how the decryption ended")?;
        if code != 0 {
            bail!("{}", fault(code));
        }
        answered_parameters(&mut read).context("read what the end answered with")?;
        Ok(read.blob().context("read what the decryption ended with")?.to_vec())
    }

    /// Whether the secure world will unwrap the key at all: a decryption is
    /// opened on it under a nonce of nothing and dropped again, which reads
    /// nothing and changes nothing.
    pub fn usable(&self, key_blob: &[u8], app_id: &[u8]) -> Result<()> {
        let operation = self.begin(key_blob, app_id, &[0; NONCE_BYTES], None)?;
        let mut call = Message::call(HARDWARE_SERVICE);
        call.u64(operation);
        let reply = self.device.transact(ABORT, &call).context("drop the decryption")?;
        let mut read = Answer::new(reply.bytes());
        read.status().context("drop the decryption")?;
        let code = read.i32().context("read how the decryption was dropped")?;
        if code != 0 {
            bail!("{}", fault(code));
        }
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
