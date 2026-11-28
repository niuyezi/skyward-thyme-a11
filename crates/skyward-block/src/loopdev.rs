//! Making a block device out of part of a file, which is how the bundles a
//! phone keeps its shared libraries in are opened.

#[cfg(target_os = "android")]
pub use android::*;

#[cfg(target_os = "android")]
mod android {
    use anyhow::{Context, Result};
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};

    const CONTROL: &str = "/dev/loop-control";

    const GET_FREE: u32 = 0x4C82;
    const CONFIGURE: u32 = 0x4C0A;
    /// LOOP_SET_STATUS64, which a kernel older than 5.9 is told the offset
    /// and the length of what is read by.
    const SET_STATUS: u32 = 0x4C04;
    /// LOOP_SET_FD, which points the device at the file whole.
    const SET_FILE: u32 = 0x4C00;

    /// The device only ever reads. It stays pointed at the file until the
    /// recovery ends, which is as long as anything mounted from it lasts.
    const READ_ONLY: u32 = 1;

    /// Every field is a plain number or a run of bytes, so the request is
    /// made by zeroing it and filling in what matters.
    #[repr(C)]
    struct Info {
        device: u64,
        inode: u64,
        rdevice: u64,
        offset: u64,
        size_limit: u64,
        number: u32,
        encrypt_type: u32,
        encrypt_key_size: u32,
        flags: u32,
        file_name: [u8; 64],
        crypt_name: [u8; 64],
        encrypt_key: [u8; 32],
        init: [u64; 2],
    }

    #[repr(C)]
    struct Config {
        fd: u32,
        block_size: u32,
        info: Info,
        reserved: [u64; 8],
    }

    /// loop_info64, which a kernel older than 5.9 is told where what the
    /// device reads of the file begins and ends by. Its first field is a
    /// device number the kernel writes, not one to hand it, and the rest
    /// after the flags are for encryption the device does none of.
    #[repr(C)]
    struct Status {
        device: u64,
        inode: u64,
        rdevice: u64,
        offset: u64,
        size_limit: u64,
        number: u32,
        encrypt_type: u32,
        encrypt_key_size: u32,
        flags: u32,
        file_name: [u8; 64],
        crypt_name: [u8; 64],
        encrypt_key: [u8; 32],
        init: [u64; 2],
    }

    /// Open `file` from `offset` for `length` bytes as a block device, and
    /// give its path. The device goes away once whatever is mounted from it
    /// is unmounted.
    pub fn attach(file: &Path, offset: u64, length: u64) -> Result<PathBuf> {
        let backing = File::open(file).with_context(|| format!("open {}", file.display()))?;
        let control = File::open(CONTROL).with_context(|| format!("open {CONTROL}"))?;
        let number = unsafe { libc::ioctl(control.as_raw_fd(), GET_FREE as libc::Ioctl) };
        if number < 0 {
            return Err(std::io::Error::last_os_error()).context("ask for a free loop device");
        }
        let path = free_device(number as u32)?;
        let device = File::options()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        let mut config: Config = unsafe { std::mem::zeroed() };
        config.fd = backing.as_raw_fd() as u32;
        config.info.offset = offset;
        config.info.size_limit = length;
        config.info.flags = READ_ONLY;
        if unsafe { libc::ioctl(device.as_raw_fd(), CONFIGURE as libc::Ioctl, &mut config) } < 0 {
            // LOOP_CONFIGURE came with kernel 5.9; a kernel older than
            // that answers it with EINVAL, and the device is set up by
            // the two calls that kernel knows instead.
            let refused = std::io::Error::last_os_error();
            if refused.raw_os_error() != Some(libc::EINVAL) {
                return Err(refused).with_context(|| format!("point {} at {}", path.display(), file.display()));
            }
            drop(device);
            return attach_older(backing, &path, offset, length);
        }
        Ok(path)
    }

    /// Set the device up the way a kernel older than 5.9 knows: the file
    /// is pointed at whole first, then the device is told where what is
    /// read of it begins and ends. The file lies on a partition mounted
    /// read-only, which the kernel refuses to point a writable device at:
    /// the device is opened read-only, which the kernel marks it as.
    fn attach_older(backing: File, path: &Path, offset: u64, length: u64) -> Result<PathBuf> {
        let device = File::options()
            .read(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        if unsafe { libc::ioctl(device.as_raw_fd(), SET_FILE as libc::Ioctl, backing.as_raw_fd()) } < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("point {} at the bundle", path.display()));
        }
        let mut status: Status = unsafe { std::mem::zeroed() };
        status.offset = offset;
        status.size_limit = length;
        // No AUTOCLEAR: the device is let go of here, and a device marked
        // with it goes away as the last of whoever holds it lets go, which
        // is this, before anything is mounted from it.
        status.flags = READ_ONLY;
        if unsafe { libc::ioctl(device.as_raw_fd(), SET_STATUS as libc::Ioctl, &mut status) } < 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("tell {} where to read", path.display()));
        }
        Ok(path.to_path_buf())
    }

    /// Where the kernel put the loop device it just handed out: Android
    /// keeps its block devices in their own directory.
    fn free_device(number: u32) -> Result<PathBuf> {
        for dir in ["/dev/block", "/dev"] {
            let path = Path::new(dir).join(format!("loop{number}"));
            if path.exists() {
                return Ok(path);
            }
        }
        anyhow::bail!("the kernel handed out loop device {number}, which is in neither /dev/block nor /dev")
    }
}
