//! Opening the data partition and its users' own files on a thread of its
//! own, so the screen keeps up: the keys come from the secure world, and
//! what a user enters at their screen lock is checked slowly on purpose.

use anyhow::Result;
use skyward_binder::driver::Binder;
use skyward_crypto::data::{self, Closed, Opening};
use skyward_crypto::keymint::KeyMint;
use skyward_sys::worker::Worker;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

pub enum Job {
    /// Open the partition as far as it opens with nothing a user knows.
    Open,
    /// Open the own files of `user` with what they entered at their screen
    /// lock; `closed` are the users whose own files are still closed.
    Unlock { closed: Vec<Closed>, user: u32, credential: Vec<u8> },
}

/// How a job ended: what it opened, or why it did not.
pub enum Ended {
    Opened(Result<Opening, String>),
    Unlocked(Result<Vec<Closed>, String>),
}

/// A job done on a thread of its own, which the screen lets go once the
/// job has ended.
pub struct Decryptor {
    /// Tells how the job ended, once.
    worker: Worker<Ended>,
}

impl Decryptor {
    pub fn start(job: Job) -> Result<Decryptor> {
        let worker = Worker::start("decrypt", move |tell| {
            tell.tell(match job {
                Job::Open => Ended::Opened(with_data_keys(data::open_without_credential)),
                Job::Unlock { closed, user, credential } => {
                    Ended::Unlocked(with_key_service(|service| data::unlock(service, &closed, user, &credential)))
                }
            });
        })?;
        Ok(Decryptor { worker })
    }

    /// Readable once the job has ended.
    pub fn fd(&self) -> RawFd {
        self.worker.fd()
    }

    /// How the job ended, once it has.
    pub fn ended(&self) -> Option<Ended> {
        self.worker.events().pop()
    }
}

/// How long to keep asking for the key service, and how often. The
/// hardware service directory starts the key service itself, and takes its
/// records away and restarts the services whenever it restarts, so a lookup
/// that lands while that is happening is answered by a directory with
/// nothing in it, or comes back saying the other side is gone.
const KEY_SERVICE_TIMEOUT: Duration = Duration::from_secs(20);
const KEY_SERVICE_POLL: Duration = Duration::from_millis(200);

/// Reach the key service, asking again while it is not there to answer.
fn key_service<'a>(binder: &'a Binder, hardware: &'a Binder) -> Result<KeyMint<'a>> {
    let until = Instant::now() + KEY_SERVICE_TIMEOUT;
    loop {
        match KeyMint::open(binder, hardware) {
            Ok(service) => return Ok(service),
            Err(e) => {
                if Instant::now() >= until {
                    return Err(e);
                }
                std::thread::sleep(KEY_SERVICE_POLL);
            }
        }
    }
}

/// Do `work` with the phone's key service, reached afresh for it, and say
/// why it failed in words for the page.
pub fn with_key_service<T>(work: impl FnOnce(&KeyMint) -> Result<T>) -> Result<T, String> {
    let done = (|| {
        let binder = Binder::open()?;
        let hardware = Binder::hardware()?;
        let service = key_service(&binder, &hardware)?;
        work(&service)
    })();
    done.map_err(|e| format!("{e:#}"))
}

/// Do `work` with what reaching the data partition takes: the phone's key
/// service, reached afresh for it, where the phone's own table has the
/// partition encrypted, and nothing where it has not, so that a partition
/// kept as the plain filesystem it is opens on a phone whose key service
/// does not start. Says why it failed in words for the page.
pub fn with_data_keys<T>(work: impl FnOnce(Option<&KeyMint>) -> Result<T>) -> Result<T, String> {
    let done = (|| {
        if !data::keyed()? {
            return work(None);
        }
        let binder = Binder::open()?;
        let hardware = Binder::hardware()?;
        let service = key_service(&binder, &hardware)?;
        work(Some(&service))
    })();
    done.map_err(|e| format!("{e:#}"))
}
