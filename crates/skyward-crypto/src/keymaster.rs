//! The phone's key service of the older kind: a hardware service reached
//! over the other driver, which is what a phone of this age has. The newer
//! kind — KeyMint, registered with the service directory — is what
//! [`crate::keymint`] speaks; a phone has one or the other, and this is the
//! one whose interface name carries its version.
//!
//! What a key is unwrapped with is the same either way: the service is
//! handed the key blob the phone stored, the parameters that say how to use
//! it, and — where the key is guarded — the note the secure world wrote when
//! the credential was answered. What differs is only how those are written
//! down and how the answer is read back.
//!
//! **Nothing here has been run against a phone yet.** It is written from the
//! interface the phone's own service binary serves
//! (`/vendor/bin/hw/android.hardware.keymaster@3.0-service`), the same way
//! [`crate::gatekeeper`] was written from its own, and the first thing to
//! check on a phone is `getHardwareInfo`: it takes nothing and answers the
//! service's version and name, so it proves the transport before anything
//! that matters is asked of it.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use anyhow::{bail, Context, Result};
use skyward_binder::hidl::{Answer, Message};

/// The hardware service, as it registers with the hardware directory.
pub const HARDWARE_SERVICE: &str = "android.hardware.keymaster@3.0::IKeymasterDevice";
pub const INSTANCE: &str = "default";

/// The method numbers, as the interface declares them: the order the
/// phone's own service is generated from.
#[allow(dead_code)]
const GET_HARDWARE_INFO: u32 = 1;
#[allow(dead_code)]
const GET_KEY_CHARACTERISTICS: u32 = 5;
#[allow(dead_code)]
const BEGIN: u32 = 6;
#[allow(dead_code)]
const UPDATE: u32 = 7;
#[allow(dead_code)]
const FINISH: u32 = 8;
#[allow(dead_code)]
const ABORT: u32 = 9;
#[allow(dead_code)]
const UPGRADE_KEY: u32 = 13;

/// What a key is used for, as the service numbers it.
pub const PURPOSE_DECRYPT: i32 = 1;

/// What the service says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardware {
    pub version: u32,
    pub security_level: i32,
    pub name: String,
    pub author: String,
}

/// The phone's key service of the older kind, as this program talks to it.
#[cfg(target_os = "android")]
pub struct Keymaster<'a> {
    device: skyward_binder::driver::Handle<'a>,
}

#[cfg(target_os = "android")]
impl<'a> Keymaster<'a> {
    /// Reach the running service, or say that none is.
    pub fn open(hardware: &'a skyward_binder::driver::Binder) -> Result<Keymaster<'a>> {
        let device = skyward_binder::hidl::find(hardware, HARDWARE_SERVICE, INSTANCE)?
            .with_context(|| {
                format!(
                    "{HARDWARE_SERVICE} is not running; the phone's key service has to be started first"
                )
            })?;
        Ok(Keymaster { device })
    }

    /// Ask the service what it is. It takes nothing and changes nothing,
    /// so it is what to call to see that the service answers at all.
    pub fn hardware(&self) -> Result<Hardware> {
        let what = "ask the key service about itself";
        let reply = self
            .device
            .transact(GET_HARDWARE_INFO, &Message::call(HARDWARE_SERVICE))
            .context(what)?;
        let mut read = Answer::new(reply.bytes());
        read.status().context(what)?;
        // The two notes the service keeps come first, each handed over as
        // the address of a structure of its own, and what is worth reading
        // comes after them.
        read.pointed()
            .context("read the note the key service keeps")?;
        read.pointed()
            .context("read the second note the key service keeps")?;
        let version = read.u32().context("read the key service's version")?;
        let security_level = read.i32().context("read where the keys are kept")?;
        let name = read.string().context("read the key service's name")?;
        let author = read.string().context("read who wrote the key service")?;
        Ok(Hardware {
            version,
            security_level,
            name,
            author,
        })
    }
}

/// What the service says a key may be used for, as the older kind hands it
/// over: a structure per level the key was made at, each with its own list
/// of tags.
///
/// Written here rather than read from a phone yet; the shape is the one
/// `getKeyCharacteristics` answers with in the interface this phone serves.
#[cfg(target_os = "android")]
#[allow(dead_code)]
pub fn authorizations(read: &mut Answer) -> Result<Vec<(i32, i64)>> {
    let what = "read what the key may be used for";
    read.status().context(what)?;
    let mut out = Vec::new();
    for _ in 0..read.i32().context(what)?.max(0) {
        // Each level is a structure of its own, and inside it the tags are
        // written as a run the service frames.
        let tags = read.pointed().context(what)?;
        let mut at = 0;
        while at + 4 <= tags.len() {
            let tag = i32::from_le_bytes(tags[at..at + 4].try_into().expect("four bytes"));
            at += 4;
            // A tag's value is written after it: the arm, then the value.
            if at + 8 > tags.len() {
                break;
            }
            let arm = i32::from_le_bytes(tags[at..at + 4].try_into().expect("four bytes"));
            at += 4;
            let number = match arm {
                0 => 0,
                _ => {
                    let v = i32::from_le_bytes(tags[at..at + 4].try_into().expect("four bytes"));
                    at += 4;
                    v as i64
                }
            };
            out.push((tag, number));
        }
    }
    if out.is_empty() {
        bail!("the key service named nothing the key may be used for");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_method_numbers_are_the_order_the_interface_declares() {
        // The phone's own service is generated from the interface, so a
        // method number that is off by one asks a different question
        // entirely: `begin` is the sixth, not the fifth.
        assert_eq!(GET_HARDWARE_INFO, 1);
        assert_eq!(GET_KEY_CHARACTERISTICS, 5);
        assert_eq!(BEGIN, 6);
        assert_eq!(UPDATE, 7);
        assert_eq!(FINISH, 8);
        assert_eq!(ABORT, 9);
        assert_eq!(UPGRADE_KEY, 13);
    }
}
