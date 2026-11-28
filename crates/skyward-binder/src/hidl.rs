//! The older layout, which the phone's hardware services still speak. A
//! call in it carries plain numbers the way the newer one does, but hands
//! anything longer over as an address: the driver copies what the address
//! points at into the far side's own room and rewrites the address to
//! match. Where the newer layout writes a length and then the bytes, this
//! one writes a frame saying where the bytes are, and then an address for
//! the bytes themselves pointing back at that frame.

use crate::parcel::Payload;
use anyhow::{bail, Context, Result};

/// An address a call hands over, as the driver carries it.
const ADDRESS: u32 = u32::from_be_bytes([b'p', b't', b'*', 0x85]);

/// An object in the sending process, as the driver carries it.
const OBJECT: u32 = u32::from_be_bytes([b's', b'h', b'*', 0x85]);

/// The bytes this address points at sit inside what another address of the
/// same call points at.
const INSIDE_ANOTHER: u32 = 1;

/// How much room an address takes among the values.
const ADDRESS_BYTES: usize = 40;

/// How much room an object takes among the values. The newer layout adds a
/// word saying how far the object's interface travels; this one does not.
const OBJECT_BYTES: usize = 24;

/// A frame as the phone's own libraries hold one in memory: where the bytes
/// are, how many there are, and whether whoever holds it frees them. A
/// string and a vec of the older kind both open with one.
pub const FRAME_BYTES: usize = 16;

/// What the driver copies for an address is rounded up to a whole word.
const WORD: u64 = 8;

/// A call being written. What the addresses point at is kept here too, so
/// it stays where it is until the driver has read it.
#[derive(Default)]
pub struct Message {
    data: Vec<u8>,
    addresses: Vec<u64>,
    held: Vec<Box<[u8]>>,
    pointed: u64,
}

impl Message {
    /// A call to `interface`, opened with the name the far side checks
    /// before it looks at anything the method itself takes.
    pub fn call(interface: &str) -> Message {
        let mut m = Message::default();
        m.data.extend_from_slice(interface.as_bytes());
        m.data.push(0);
        while !m.data.len().is_multiple_of(4) {
            m.data.push(0);
        }
        m
    }

    pub fn u32(&mut self, v: u32) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    pub fn i32(&mut self, v: i32) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    /// A run of bytes: the frame that says where they are, then an address
    /// for the bytes themselves.
    pub fn bytes(&mut self, value: &[u8]) {
        let at = self.keep(value.to_vec());
        self.framed(at, value.len(), value.len());
    }

    /// Text, which is a run of bytes with a terminator the count leaves
    /// out.
    pub fn text(&mut self, value: &str) {
        let mut raw = value.as_bytes().to_vec();
        raw.push(0);
        let at = self.keep(raw);
        self.framed(at, value.len(), value.len() + 1);
    }

    /// One structure by itself, holding `content` as it lies in memory: how
    /// a structure with nothing of its own to point at is handed over.
    /// Answer which object it is, for any child objects it carries to name
    /// it as their holder.
    pub fn object(&mut self, content: &[u8]) -> usize {
        let at = self.keep(content.to_vec());
        self.buffer(at, content.len(), None)
    }

    /// A structure holding `content`, with `children` objects the driver
    /// copies in and whose addresses it writes into `content` at the named
    /// offsets: how a structure with a vec or a string inside it is handed
    /// over. Each child's address and length are written where the phone's
    /// own library keeps a `hidl_vec`'s buffer and size, and each child is
    /// then registered as an object sitting inside this one, so the driver
    /// copies it and writes its address into `content` where that field
    /// lies.
    ///
    /// A child that is empty is still registered: the phone's own library
    /// writes one for every vec, and the far side reads one for every vec
    /// whether it holds anything or not.
    pub fn object_with(&mut self, content: &mut [u8], children: &[(usize, &[u8])]) {
        // Keep every child first, so its address is stable while `content`
        // is being filled and copied.
        let mut ats = Vec::with_capacity(children.len());
        for (off, child) in children {
            let at = self.keep(child.to_vec());
            content[*off..*off + 8].copy_from_slice(&at.to_le_bytes());
            content[*off + 8..*off + 12].copy_from_slice(&(child.len() as u32).to_le_bytes());
            ats.push(at);
        }
        let at = self.keep(content.to_vec());
        let which = self.buffer(at, content.len(), None);
        for (i, (off, child)) in children.iter().enumerate() {
            self.buffer(ats[i], child.len(), Some((which, *off)));
        }
    }

    /// A vec handed over at the top level, written as the phone's own
    /// library writes one: a frame holding where the elements lie and how
    /// many there are, then the elements themselves as an object inside
    /// that frame. `children` are further objects pointed at from inside
    /// the elements — each element's own blobs — at their offsets, each
    /// registered as sitting inside the elements' object.
    pub fn vec_with(&mut self, count: u32, data: &mut [u8], children: &[(usize, &[u8])]) {
        let mut ats = Vec::with_capacity(children.len());
        for (off, child) in children {
            let at = self.keep(child.to_vec());
            data[*off..*off + 8].copy_from_slice(&at.to_le_bytes());
            data[*off + 8..*off + 12].copy_from_slice(&(child.len() as u32).to_le_bytes());
            ats.push(at);
        }
        let data_at = self.keep(data.to_vec());
        // The frame the phone's own library keeps in memory for a vec:
        // where its elements lie — rewritten to the elements' object
        // below —, how many there are, and that whoever holds it does not
        // free them.
        let mut frame = vec![0u8; FRAME_BYTES];
        frame[0..8].copy_from_slice(&data_at.to_le_bytes());
        frame[8..12].copy_from_slice(&count.to_le_bytes());
        let frame_at = self.keep(frame);
        let frame_object = self.buffer(frame_at, FRAME_BYTES, None);
        let data_object = self.buffer(data_at, data.len(), Some((frame_object, 0)));
        for (i, (off, child)) in children.iter().enumerate() {
            self.buffer(ats[i], child.len(), Some((data_object, *off)));
        }
    }

    /// Write one object among the values and say where it sits: an address
    /// the driver finds, pointing at bytes it copies into the far side's
    /// own room. `inside` names the object this one is written into and
    /// where inside it, which is how the driver writes an embedded
    /// object's address into its holder. The object is as long as the
    /// driver's own layout of it, no more.
    fn buffer(&mut self, at: u64, length: usize, inside: Option<(usize, usize)>) -> usize {
        let which = self.addresses.len();
        self.addresses.push(self.data.len() as u64);
        self.data.extend_from_slice(&ADDRESS.to_le_bytes());
        self.data.extend_from_slice(&inside.map_or(0, |_| INSIDE_ANOTHER).to_le_bytes());
        self.data.extend_from_slice(&at.to_le_bytes());
        self.data.extend_from_slice(&(length as u64).to_le_bytes());
        self.data.extend_from_slice(&(inside.map_or(0, |p| p.0) as u64).to_le_bytes());
        self.data.extend_from_slice(&(inside.map_or(0, |p| p.1) as u64).to_le_bytes());
        self.pointed += (length as u64).next_multiple_of(WORD);
        which
    }

    /// Hold on to bytes the driver will read, and say where they are. A run
    /// of nothing still gets one byte to point at: the driver is told to
    /// copy from the address whether the run holds anything or not, and it
    /// checks the address before it copies.
    fn keep(&mut self, bytes: Vec<u8>) -> u64 {
        let mut bytes = bytes;
        if bytes.is_empty() {
            bytes.push(0);
        }
        let bytes = bytes.into_boxed_slice();
        let at = bytes.as_ptr() as u64;
        self.held.push(bytes);
        at
    }

    /// The pair of addresses a run of bytes is written as: the frame, and
    /// then the bytes it points at.
    fn framed(&mut self, at: u64, count: usize, length: usize) {
        let mut frame = Vec::with_capacity(FRAME_BYTES);
        frame.extend_from_slice(&at.to_le_bytes());
        frame.extend_from_slice(&(count as u32).to_le_bytes());
        // Whoever reads the frame does not free what it points at.
        frame.extend_from_slice(&[0; 4]);
        let frame_at = self.keep(frame);
        let parent = self.buffer(frame_at, FRAME_BYTES, None);
        self.buffer(at, length, Some((parent, 0)));
    }
}

impl Payload for Message {
    fn values(&self) -> &[u8] {
        &self.data
    }

    fn addresses(&self) -> &[u64] {
        &self.addresses
    }

    fn pointed(&self) -> u64 {
        self.pointed
    }
}

/// Reads back what a hardware service answered.
pub struct Answer<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Answer<'a> {
    pub fn new(data: &'a [u8]) -> Answer<'a> {
        Answer { data, at: 0 }
    }

    /// Whether the call went through. A service that refused says so first,
    /// and says why in a plain string of the driver's own — not a HIDL one:
    /// how many characters, then the characters two bytes each, then a
    /// terminator — that follows.
    pub fn status(&mut self) -> Result<()> {
        let code = self.i32().context("read whether the service took the call")?;
        if code == 0 {
            return Ok(());
        }
        match self.plain_text() {
            Ok(why) if !why.is_empty() => bail!("the service refused the call: {why}"),
            _ => bail!("the service refused the call with its code {code}"),
        }
    }

    /// A string the driver writes itself rather than a HIDL one: how many
    /// characters, then the characters two bytes each, then a terminator,
    /// padded to four.
    fn plain_text(&mut self) -> Result<String> {
        let units = self.i32()?;
        if units < 0 {
            bail!("text of length {units} was read where some was expected");
        }
        let raw = self.take((units as usize + 1) * 2)?;
        let utf16: Vec<u16> = raw[..units as usize * 2].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        Ok(String::from_utf16_lossy(&utf16))
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().expect("four bytes")))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes")))
    }

    /// A truth value: a byte, padded to four as everything is.
    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.take(4)?[0] != 0)
    }

    /// The bytes an address in the reply points at. The driver has already
    /// moved them into this program's own room and rewritten the address,
    /// so they are read where they lie. An address that points at nothing
    /// and holds nothing is an empty run of bytes.
    pub fn pointed(&mut self) -> Result<&'a [u8]> {
        let raw = self.take(ADDRESS_BYTES)?;
        let kind = u32::from_le_bytes(raw[0..4].try_into().expect("four bytes"));
        if kind != ADDRESS {
            bail!("the reply holds {kind:#x} where an address was expected");
        }
        let at = u64::from_le_bytes(raw[8..16].try_into().expect("eight bytes"));
        let length = u64::from_le_bytes(raw[16..24].try_into().expect("eight bytes"));
        if length == 0 {
            return Ok(&[]);
        }
        if at == 0 {
            bail!("the service left out something the call asked for");
        }
        Ok(unsafe { std::slice::from_raw_parts(at as *const u8, length as usize) })
    }

    /// A vec or a string in the reply, as the phone's own library writes
    /// one: a frame saying how many there are and where they lie, then the
    /// things themselves. Both addresses have already been moved into this
    /// program's own room, so what is answered is how many the frame says
    /// and the bytes that were carried. A vec of nothing carries nothing,
    /// and answers a count of nothing.
    pub fn run(&mut self) -> Result<(usize, &'a [u8])> {
        let frame = self.pointed().context("read the frame of a run")?;
        if frame.len() < FRAME_BYTES {
            bail!("a run's frame holds {} bytes", frame.len());
        }
        let count = u32::from_le_bytes(frame[8..12].try_into().expect("four bytes")) as usize;
        let data = self.pointed().context("read a run")?;
        Ok((count, data))
    }

    /// The bytes a `vec<uint8_t>` in the reply carries.
    pub fn blob(&mut self) -> Result<&'a [u8]> {
        let (count, data) = self.run().context("read a run of bytes")?;
        if data.len() < count {
            bail!("a run of bytes said it held {count} but carried {}", data.len());
        }
        Ok(&data[..count])
    }

    /// Text the far side wrote as its own value, carried as UTF-8 and
    /// counted without the terminator that follows it.
    pub fn text(&mut self) -> Result<String> {
        let (units, characters) = self.run().context("read a string")?;
        if characters.len() < units {
            bail!("a string said it holds {units} characters but carried {}", characters.len());
        }
        Ok(String::from_utf8_lossy(&characters[..units]).into_owned())
    }

    /// The handle of an object in the answering process.
    pub fn object(&mut self) -> Result<Option<u32>> {
        let raw = self.take(OBJECT_BYTES)?;
        let kind = u32::from_le_bytes(raw[0..4].try_into().expect("four bytes"));
        let handle = u32::from_le_bytes(raw[8..12].try_into().expect("four bytes"));
        Ok((kind == OBJECT).then_some(handle))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at + n;
        if end > self.data.len() {
            bail!("the reply holds {} bytes, {n} more were read at {}", self.data.len(), self.at);
        }
        let out = &self.data[self.at..end];
        self.at = end;
        Ok(out)
    }
}

/// The hardware service serving `interface` as `instance`, or `None` while
/// nothing has registered it.
#[cfg(target_os = "android")]
pub fn find<'a>(binder: &'a crate::driver::Binder, interface: &str, instance: &str) -> Result<Option<crate::driver::Handle<'a>>> {
    use crate::driver::Handle;
    // The directory the phone's hardware services register with, which is
    // a second one beside the directory the rest of the phone uses, and
    // the call that asks it for a service.
    const DIRECTORY: &str = "android.hidl.manager@1.0::IServiceManager";
    const GET: u32 = 1;
    let directory = binder.directory()?;
    let mut call = Message::call(DIRECTORY);
    call.text(interface);
    call.text(instance);
    let reply = directory.transact(GET, &call).with_context(|| format!("look up {interface}/{instance}"))?;
    let mut read = Answer::new(reply.bytes());
    read.status().with_context(|| format!("look up {interface}/{instance}"))?;
    match read.object().with_context(|| format!("read what the directory answered for {interface}"))? {
        Some(handle) => Ok(Some(Handle::hold(reply.binder(), handle)?)),
        None => Ok(None),
    }
}

/// The name a hardware service gives for the interface it was reached by,
/// which is what a call that changes nothing answers.
#[cfg(target_os = "android")]
pub fn describes(service: &crate::driver::Handle) -> Result<String> {
    // Every hardware service serves this interface besides its own, and a
    // call on it is named as being on it whatever else the service serves.
    const BASE: &str = "android.hidl.base@1.0::IBase";
    const DESCRIBE: u32 = 256_136_003;
    let reply = service.transact(DESCRIBE, &Message::call(BASE)).context("ask the service what it serves")?;
    let mut read = Answer::new(reply.bytes());
    read.status().context("ask the service what it serves")?;
    let frame = read.pointed().context("read the frame of what the service serves")?;
    if frame.len() < FRAME_BYTES {
        bail!("the service answered a frame of {} bytes", frame.len());
    }
    let name = read.pointed().context("read the name of what the service serves")?;
    Ok(String::from_utf8_lossy(name.trim_suffix(&[0])).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads the parts of a written call back out of its own memory, the
    /// way the driver does: the values, and each address among them.
    fn written(m: &Message) -> Vec<(u32, u64, Vec<u8>)> {
        m.addresses
            .iter()
            .map(|at| {
                let raw = &m.data[*at as usize..*at as usize + ADDRESS_BYTES];
                let flags = u32::from_le_bytes(raw[4..8].try_into().unwrap());
                let points = u64::from_le_bytes(raw[8..16].try_into().unwrap());
                let length = u64::from_le_bytes(raw[16..24].try_into().unwrap()) as usize;
                let inside = u64::from_le_bytes(raw[24..32].try_into().unwrap());
                let bytes = unsafe { std::slice::from_raw_parts(points as *const u8, length) }.to_vec();
                assert_eq!(u32::from_le_bytes(raw[0..4].try_into().unwrap()), ADDRESS);
                assert_eq!(u64::from_le_bytes(raw[32..40].try_into().unwrap()), 0);
                (flags, inside, bytes)
            })
            .collect()
    }

    #[test]
    fn a_call_opens_with_the_interface_name_and_a_terminator() {
        let m = Message::call("a.b@1.0::IC");
        assert_eq!(&m.data[..11], b"a.b@1.0::IC");
        assert_eq!(m.data.len(), 12, "the name, its terminator, and padding to four");
        assert_eq!(m.data[11], 0);
        assert!(m.addresses.is_empty());
    }

    #[test]
    fn numbers_are_written_where_they_fall() {
        let mut m = Message::call("a.b@1.0::IC");
        m.u32(7);
        m.u64(1 << 40);
        assert_eq!(m.data.len(), 12 + 4 + 8, "a word is not moved to a boundary of its own");
        assert_eq!(u32::from_le_bytes(m.data[12..16].try_into().unwrap()), 7);
        assert_eq!(u64::from_le_bytes(m.data[16..24].try_into().unwrap()), 1 << 40);
    }

    #[test]
    fn bytes_are_written_as_a_frame_and_the_bytes_it_points_at() {
        let mut m = Message::call("a.b@1.0::IC");
        m.bytes(&[1, 2, 3]);
        let parts = written(&m);
        assert_eq!(parts.len(), 2, "the frame, then the bytes");
        assert_eq!(parts[0].0, 0, "the frame points inside nothing");
        assert_eq!(parts[0].2.len(), FRAME_BYTES);
        assert_eq!(u32::from_le_bytes(parts[0].2[8..12].try_into().unwrap()), 3, "how many bytes there are");
        assert_eq!(parts[1].0, INSIDE_ANOTHER, "the bytes sit inside the frame");
        assert_eq!(parts[1].1, 0, "inside the first address of the call");
        assert_eq!(parts[1].2, vec![1, 2, 3]);
        assert_eq!(m.pointed, FRAME_BYTES as u64 + WORD, "both rounded up to a word");
    }

    #[test]
    fn text_counts_its_characters_and_carries_a_terminator() {
        let mut m = Message::call("a.b@1.0::IC");
        m.text("default");
        let parts = written(&m);
        assert_eq!(u32::from_le_bytes(parts[0].2[8..12].try_into().unwrap()), 7, "the terminator is not counted");
        assert_eq!(parts[1].2, b"default\0", "but it is carried");
    }

    #[test]
    fn the_frame_points_at_the_bytes_that_follow_it() {
        let mut m = Message::call("a.b@1.0::IC");
        m.bytes(&[9; 5]);
        let parts = written(&m);
        let in_frame = u64::from_le_bytes(parts[0].2[0..8].try_into().unwrap());
        let raw = &m.data[m.addresses[1] as usize..];
        assert_eq!(in_frame, u64::from_le_bytes(raw[8..16].try_into().unwrap()));
    }

    #[test]
    fn a_service_that_refused_the_call_is_an_error() {
        let mut reply = 3i32.to_le_bytes().to_vec();
        reply.extend_from_slice(&(-1i32).to_le_bytes());
        assert!(Answer::new(&reply).status().is_err());
        assert!(Answer::new(&0i32.to_le_bytes()).status().is_ok());
    }

    #[test]
    fn reading_past_the_end_of_a_reply_is_an_error() {
        assert!(Answer::new(&[]).i32().is_err());
        assert!(Answer::new(&[0; 8]).pointed().is_err());
    }

    #[test]
    fn a_truth_value_is_a_byte_padded_to_four() {
        let mut read = Answer::new(&[1, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0]);
        assert!(read.bool().unwrap());
        assert!(!read.bool().unwrap());
        assert_eq!(read.i32().unwrap(), 7, "what follows it starts four bytes on");
        assert!(Answer::new(&[1, 0]).bool().is_err());
    }
}
