//! Opening the data partition and its users' own files on a thread of its
//! own, so the screen keeps up: the keys come from the secure world, and
//! what a user enters at their screen lock is checked slowly on purpose.

use anyhow::{Context, Result};
use skyward_binder::driver::Binder;
use skyward_crypto::data::{self, Closed, Opening};
use skyward_crypto::keymint::KeyMint;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};

pub enum Job {
    /// Open the partition as far as it opens with nothing a user knows.
    Open,
    /// Open the own files of `user` with what they entered at their screen
    /// lock; `closed` are the users whose own files are still closed.
    Unlock {
        closed: Vec<Closed>,
        user: u32,
        credential: Vec<u8>,
    },
}

/// How a job ended: what it opened, or why it did not.
pub enum Ended {
    Opened(Result<Opening, String>),
    Unlocked(Result<Vec<Closed>, String>),
}

pub struct Decryptor {
    ended: Receiver<Ended>,
    /// Readable once the job has ended.
    wake: OwnedFd,
    thread: Option<JoinHandle<()>>,
}

impl Decryptor {
    pub fn start(job: Job) -> Result<Decryptor> {
        let mut fds = [0; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("make the decrypting thread's wake pipe");
        }
        let (wake, signal) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let (tx, ended) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("decrypt".into())
            .spawn(move || {
                let ended_as = match job {
                    Job::Open => Ended::Opened(open_data()),
                    Job::Unlock {
                        closed,
                        user,
                        credential,
                    } => Ended::Unlocked(with_key_service(|service| {
                        data::unlock(service, &closed, user, &credential)
                    })),
                };
                // The screen only stops listening once it has let the
                // thread go.
                let _ = tx.send(ended_as);
                unsafe { libc::write(signal.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
            })
            .context("start the decrypting thread")?;
        Ok(Decryptor {
            ended,
            wake,
            thread: Some(thread),
        })
    }

    pub fn fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }

    /// How the job ended, once it has.
    pub fn ended(&self) -> Option<Ended> {
        let mut drain = [0u8; 8];
        while unsafe {
            libc::read(
                self.wake.as_raw_fd(),
                drain.as_mut_ptr().cast(),
                drain.len(),
            )
        } > 0
        {}
        self.ended.try_recv().ok()
    }
}

impl Drop for Decryptor {
    /// The screen lets the thread go once its job has ended.
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the decrypting thread does not panic");
        }
    }
}

/// Open the data partition: where it is reached without a key, that is done
/// and nothing of the phone's key services is asked for; where it is not,
/// the same work goes through the key service as it always did. Why the
/// first way was left off goes into the kernel log, so a phone that ends up
/// waiting on a service it does not have can be told from one that does.
fn open_data() -> Result<Opening, String> {
    match data::open_without_keys() {
        Ok(opening) => {
            let _ = skyward_sys::kmsg("data opened without keys: its table names no encryption");
            Ok(opening)
        }
        Err(plain) => {
            let _ = skyward_sys::kmsg(&format!("data is not reachable without keys: {plain:#}"));
            with_key_service(data::open_without_credential)
                .map_err(|why| format!("key service: {why}; and as it lies: {plain:#}"))
        }
    }
}

/// Do `work` with the phone's key service, reached afresh for it, and say
/// why it failed in words for the page.
pub fn with_key_service<T>(work: impl FnOnce(&KeyMint) -> Result<T>) -> Result<T, String> {
    let done = (|| {
        // Whatever kind of key hardware the phone has, it is reached the same
        // way from here: the secure world's daemon is started first, and the
        // service is asked for afterwards. What bringing it up came to goes
        // into the kernel log, because a step that fails here is what the
        // next error is really about.
        let _chain = match crate::keyhal::start() {
            Ok(chain) => chain,
            Err(e) => {
                let _ = skyward_sys::kmsg(&format!("key hardware did not come up: {e:#}"));
                return Err(e);
            }
        };
        let binder = Binder::open()?;
        let service = open_when_ready(&binder)?;
        work(&service)
    })();
    done.map_err(|e| format!("{e:#}"))
}

/// Ask for the phone's key service until it answers. The daemon that speaks
/// to the secure world is started a moment before this, and a phone asked
/// before it is ready answers as though it had no key hardware at all — so
/// that answer is not believed until it has been given a few times.
fn open_when_ready(binder: &Binder) -> Result<KeyMint<'_>> {
    /// How long to keep asking: three seconds, which is longer than the
    /// daemon has ever taken and shorter than a page that waits feels.
    const TRIES: usize = 4;
    const BETWEEN_MS: u64 = 750;
    let mut last = None;
    for attempt in 0..TRIES {
        match KeyMint::open(binder) {
            Ok(service) => return Ok(service),
            Err(e) => {
                last = Some(e);
                if attempt + 1 < TRIES {
                    std::thread::sleep(std::time::Duration::from_millis(BETWEEN_MS));
                }
            }
        }
    }
    Err(last.expect("the service was asked at least once"))
}
