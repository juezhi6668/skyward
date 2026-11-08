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
use std::time::{Duration, Instant};

/// The secure world's driver, and the daemon that speaks to it.
const QSEECOM: &str = "/dev/qseecom";

/// How long the service is given to register itself.
const WAIT: Duration = Duration::from_secs(6);
const EVERY: Duration = Duration::from_millis(100);

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
    // /vendor/firmware_mnt. Without it QSEE has nothing to load and the
    // service never announces itself.
    let firmware = firmware();
    let _ = skyward_sys::kmsg(&format!("key hardware: firmware at {firmware}"));
    open_qseecom()?;
    let mut children = Vec::new();
    children.push(spawn("qseecomd", Path::new("/system/bin/qseecomd"))?);
    // The service itself is **not** started here: it is a lazy hardware
    // service, and the only thing that starts it is init answering the
    // hardware directory's ctl.interface_start. Asking the directory for it
    // is therefore what starts it, which is what the wait below does — and
    // it only works because the image carries a rule that defines the
    // service (system/etc/init/skyward-keymaster.rc).
    // The service is started by init, not spawned here: a property is set
    // and the image's own rule answers it. Spawning it by hand was tried and
    // it runs and never announces itself; the difference is the environment
    // init gives it, which is why TWRP sets properties too.
    skyward_sys::set_prop("skyward.keymaster", "1")
        .context("ask init to start the key service")?;
    let started = Started { children };
    wait_for_service()?;
    let _ = skyward_sys::kmsg("key hardware: the key service is up");
    Ok(started)
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

/// Wait for the keymaster service to answer the hardware directory, which is
/// the only proof that the whole chain came up.
fn wait_for_service() -> Result<()> {
    use skyward_binder::hidl;
    use skyward_crypto::keymaster;
    let began = Instant::now();
    let mut last = None;
    while began.elapsed() < WAIT {
        match skyward_binder::driver::Binder::hardware() {
            Ok(hardware) => {
                match hidl::find(&hardware, keymaster::HARDWARE_SERVICE, keymaster::INSTANCE) {
                    Ok(Some(_)) => return Ok(()),
                    Ok(None) => last = Some(format!("{} has not registered", keymaster::HARDWARE_SERVICE)),
                    Err(e) => last = Some(format!("{e:#}")),
                }
            }
            Err(e) => last = Some(format!("{e:#}")),
        }
        std::thread::sleep(EVERY);
    }
    Err(anyhow::anyhow!(
        "the key service did not come up within {:?}: {}",
        WAIT,
        last.unwrap_or_else(|| "nothing was said".into())
    ))
}
