//! Starting the phone's key hardware service, which is what a phone of this
//! age has to be able to unwrap a key at all.
//!
//! Nothing starts it for us. The base's own `init.recovery.qcom.rc` has
//! `#import /init.recovery.qcom_decrypt.rc` commented out, and TWRP does not
//! use that chain either: it sets the crypto properties and starts the
//! services from its own C++. So the chain is started here, in the order the
//! commented-out file would have started it:
//!
//! 1. the vendor files, because the service's own binary and libraries are
//!    on them — `/vendor/bin/hw/android.hardware.keymaster@3.0-service`,
//!    which is the only keymaster this phone has (measured: the vendor
//!    partition carries that and a gatekeeper, and nothing newer);
//! 2. `/dev/qseecom`, which the secure world's driver is reached through;
//! 3. `qseecomd`, the daemon that talks to the secure world;
//! 4. the keymaster service itself, which registers with the hardware
//!    service directory as it starts.
//!
//! The secure world is only reached once all four are up, so the last step
//! waits for the service to answer rather than for the program to start.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::{Child, Command, Stdio};

/// The secure world's driver, and the daemon that speaks to it.
const QSEECOM: &str = "/dev/qseecom";

/// What was started, kept so the programs stay as long as the recovery does.
pub struct Started {
    children: Vec<Child>,
}

impl Started {
    /// Whether every program started is still running, and which stopped.
    pub fn still_up(&mut self) -> Vec<(String, Option<i32>)> {
        let mut gone = Vec::new();
        for child in &mut self.children {
            if let Ok(Some(status)) = child.try_wait() {
                gone.push((format!("{:?}", child.id()), status.code()));
            }
        }
        gone
    }
}

/// Bring the key hardware up, and say what happened at each step in the
/// kernel log, since this is the part that fails without a picture to show.
pub fn start() -> Result<Started> {
    // The trusted app the key service runs in the secure world is a file on
    // the firmware partition, which the phone's own table mounts as vfat at
    // /vendor/firmware_mnt. Without it QSEE has nothing to load.
    let firmware = firmware();
    let _ = skyward_sys::kmsg(&format!("key hardware: firmware at {firmware}"));
    open_qseecom()?;
    let mut children = Vec::new();
    children.push(spawn("qseecomd", Path::new("/system/bin/qseecomd"))?);
    // Nothing starts a *service*: this phone's key hardware is a passthrough
    // module that is loaded into this process by whoever uses it, not a
    // hardware service that registers with the directory. What it needs is
    // the secure world's daemon, and the library it is in.
    std::thread::sleep(std::time::Duration::from_millis(400));
    Ok(Started { children })
}

/// Mount the firmware partition where the phone's table puts it, and say
/// where that is. A phone that has none is not a failure here: the service
/// is asked for either way, and what it answers is the answer.
fn firmware() -> String {
    for name in ["modem", "firmware"] {
        if let Ok(at) = skyward_block::fstab::mount(name) {
            return at.display().to_string();
        }
    }
    "not mounted".to_string()
}

/// Let the secure world's driver be opened by the daemon that speaks to it,
/// as the commented-out decrypt rules did.
fn open_qseecom() -> Result<()> {
    let path = Path::new(QSEECOM);
    if !path.exists() {
        bail!("{QSEECOM} is not there, so the secure world cannot be reached");
    }
    let at = std::ffi::CString::new(QSEECOM).expect("no NUL");
    unsafe {
        // 0660: the daemon's group may open it, and nobody else.
        libc::chmod(at.as_ptr(), 0o660);
        // system:drmrpc, which is whose it is on a phone of this age. A
        // recovery runs as root and could open it either way; this is so the
        // daemon, which may not, can.
        libc::chown(at.as_ptr(), 1000, 1016);
    }
    Ok(())
}

/// Start a program that has to keep running, with the libraries it loads
/// found where the recovery keeps them: its own vendor folder first, which
/// is where the Qualcomm pieces are, then its system one.
fn spawn(what: &str, program: &Path) -> Result<Child> {
    if !program.exists() {
        bail!("{what} is not at {}", program.display());
    }
    Command::new(program)
        .env("LD_LIBRARY_PATH", "/vendor/lib64:/vendor/lib:/system/lib64:/system/lib")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("start {}", program.display()))
}
