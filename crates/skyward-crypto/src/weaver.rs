//! The phone's weaver: slots in a secure element, each keeping a value
//! behind a key and giving the value back only for that key. A phone that
//! has one keeps there a part of what opens each user's secret, so the
//! secure element counts the wrong tries and holds off further ones, and
//! erasing the slot makes the secret unopenable for good.

// The calls and answers serve the phone's own driver and the host tests.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use anyhow::{bail, Context, Result};
use skyward_binder::parcel::{Parcel, Reader};
use skyward_binder::status;

/// The weaver, as it registers with the service directory.
pub const SERVICE: &str = "android.hardware.weaver.IWeaver/default";
const INTERFACE: &str = "android.hardware.weaver.IWeaver";

const GET_CONFIG: u32 = 1;
const READ: u32 = 2;

/// How a read went, as the weaver's second version says it in its answer.
const READ_OK: i32 = 0;
const READ_INCORRECT_KEY: i32 = 2;
const READ_THROTTLE: i32 = 3;

/// How the first version refuses a read: in its own errors, with nothing
/// said of how long it holds off.
const STATUS_INCORRECT_KEY: i32 = 2;
const STATUS_THROTTLE: i32 = 3;

/// What the weaver says of itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    pub slots: u32,
    /// How long the keys it keeps values behind are.
    pub key_bytes: usize,
    pub value_bytes: usize,
}

/// The call that asks the weaver about itself.
fn ask_config() -> Parcel {
    Parcel::call(INTERFACE)
}

/// What the weaver answered about itself.
fn config(read: &mut Reader) -> Result<Config> {
    status::ok(read).context("ask the weaver about itself")?;
    let end = read
        .structure()
        .context("read what the weaver says of itself")?;
    let (slots, key, value) = (read.i32()?, read.i32()?, read.i32()?);
    read.go(end)?;
    let size = |n: i32, what: &str| {
        usize::try_from(n).with_context(|| format!("the weaver says its {what} are {n} bytes long"))
    };
    Ok(Config {
        slots: u32::try_from(slots)
            .with_context(|| format!("the weaver says it has {slots} slots"))?,
        key_bytes: size(key, "keys")?,
        value_bytes: size(value, "values")?,
    })
}

/// The call that asks `slot` for its value behind `key`.
fn ask_value(slot: u32, key: &[u8]) -> Parcel {
    let mut call = Parcel::call(INTERFACE);
    call.i32(slot as i32);
    call.blob(key);
    call
}

/// What the weaver answered a read with: the value the slot keeps, or why
/// it kept it back.
fn value(read: &mut Reader) -> Result<Vec<u8>> {
    if let Err(e) = status::ok(read) {
        return Err(match status::refused_with(&e) {
            Some(STATUS_INCORRECT_KEY) => {
                e.context("the secure element does not recognise that credential")
            }
            Some(STATUS_THROTTLE) => e.context("the secure element is holding off further tries"),
            _ => e.context("read the slot of the weaver"),
        });
    }
    let end = read.structure().context("read what the weaver answered")?;
    let wait = read.i64().context("read how long the weaver holds off")?;
    let value = read.blob().context("read the value the slot keeps")?;
    // The first version stops here, and answers at all only when the read
    // went through.
    let said = match read.here() < end {
        true => read.i32().context("read how the read went")?,
        false => READ_OK,
    };
    read.go(end)?;
    let seconds = (wait.max(0) as u64).div_ceil(1000);
    match said {
        READ_OK => Ok(value),
        READ_THROTTLE => {
            bail!("the secure element is holding off further tries for another {seconds} seconds")
        }
        READ_INCORRECT_KEY if wait > 0 => {
            bail!("the secure element does not recognise that credential, and holds off further tries for another {seconds} seconds")
        }
        READ_INCORRECT_KEY => bail!("the secure element does not recognise that credential"),
        _ => bail!("the weaver failed to read the slot"),
    }
}

/// The phone's weaver, as this program talks to it.
#[cfg(target_os = "android")]
pub struct Weaver<'a> {
    device: skyward_binder::driver::Handle<'a>,
}

#[cfg(target_os = "android")]
impl<'a> Weaver<'a> {
    /// Reach the running weaver, or say that none is.
    pub fn open(binder: &'a skyward_binder::driver::Binder) -> Result<Weaver<'a>> {
        let device = skyward_binder::service::find(binder, SERVICE)?.with_context(|| {
            format!("{SERVICE} is not running; the phone's weaver has to be started first")
        })?;
        Ok(Weaver { device })
    }

    pub fn config(&self) -> Result<Config> {
        let reply = self
            .device
            .transact(GET_CONFIG, &ask_config())
            .context("ask the weaver about itself")?;
        config(&mut reply.read())
    }

    /// The value `slot` keeps behind `key`. A wrong key is counted against
    /// the slot by the secure element, so this is not something to call
    /// twice over on a guess.
    pub fn read(&self, slot: u32, key: &[u8]) -> Result<Vec<u8>> {
        let reply = self
            .device
            .transact(READ, &ask_value(slot, key))
            .with_context(|| format!("read slot {slot} of the weaver"))?;
        value(&mut reply.read())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply that went through, carrying one structure: that it is there,
    /// how long it is, then its fields.
    fn answered(fields: impl FnOnce(&mut Parcel)) -> Vec<u8> {
        let mut p = Parcel::default();
        p.i32(0);
        p.i32(1);
        let at = p.here();
        p.i32(0);
        fields(&mut p);
        let size = (p.here() - at) as i32;
        p.fill(at, size);
        p.bytes().to_vec()
    }

    fn refused(code: i32) -> Vec<u8> {
        let mut p = Parcel::default();
        p.i32(-8);
        p.string("");
        p.i32(0);
        p.i32(code);
        p.bytes().to_vec()
    }

    #[test]
    fn the_weaver_says_how_many_slots_it_has_and_how_long_its_keys_are() {
        let reply = answered(|p| {
            p.i32(64);
            p.i32(16);
            p.i32(16);
        });
        let c = config(&mut Reader::new(&reply)).unwrap();
        assert_eq!(
            c,
            Config {
                slots: 64,
                key_bytes: 16,
                value_bytes: 16
            }
        );
    }

    #[test]
    fn a_read_asks_the_slot_by_number_with_the_key() {
        let call = ask_value(3, &[7; 16]);
        let mut r = Reader::new(call.bytes());
        r.i32().unwrap();
        r.i32().unwrap();
        r.i32().unwrap();
        assert_eq!(r.string().unwrap(), INTERFACE);
        assert_eq!(r.i32().unwrap(), 3);
        assert_eq!(r.blob().unwrap(), vec![7; 16]);
        assert_eq!(r.here(), call.bytes().len());
    }

    #[test]
    fn the_value_comes_back_for_the_right_key() {
        let second = answered(|p| {
            p.i64(0);
            p.blob(&[0xAB; 16]);
            p.i32(READ_OK);
        });
        assert_eq!(value(&mut Reader::new(&second)).unwrap(), vec![0xAB; 16]);
        let first = answered(|p| {
            p.i64(0);
            p.blob(&[0xCD; 16]);
        });
        assert_eq!(
            value(&mut Reader::new(&first)).unwrap(),
            vec![0xCD; 16],
            "the first version says nothing of how it went"
        );
    }

    #[test]
    fn a_wrong_key_or_a_wait_is_said_as_the_weaver_says_it() {
        let wrong = answered(|p| {
            p.i64(0);
            p.blob(&[]);
            p.i32(READ_INCORRECT_KEY);
        });
        assert_eq!(
            value(&mut Reader::new(&wrong)).unwrap_err().to_string(),
            "the secure element does not recognise that credential"
        );
        let wrong_and_wait = answered(|p| {
            p.i64(29_001);
            p.blob(&[]);
            p.i32(READ_INCORRECT_KEY);
        });
        assert!(value(&mut Reader::new(&wrong_and_wait))
            .unwrap_err()
            .to_string()
            .ends_with("for another 30 seconds"));
        let waiting = answered(|p| {
            p.i64(5_000);
            p.blob(&[]);
            p.i32(READ_THROTTLE);
        });
        assert_eq!(
            value(&mut Reader::new(&waiting)).unwrap_err().to_string(),
            "the secure element is holding off further tries for another 5 seconds"
        );
        let failed = answered(|p| {
            p.i64(0);
            p.blob(&[]);
            p.i32(1);
        });
        assert!(value(&mut Reader::new(&failed)).is_err());
    }

    #[test]
    fn the_first_versions_refusals_are_its_own_errors() {
        let wrong = value(&mut Reader::new(&refused(STATUS_INCORRECT_KEY))).unwrap_err();
        assert_eq!(status::refused_with(&wrong), Some(STATUS_INCORRECT_KEY));
        assert!(format!("{wrong:#}")
            .starts_with("the secure element does not recognise that credential"));
        let waiting = value(&mut Reader::new(&refused(STATUS_THROTTLE))).unwrap_err();
        assert!(
            format!("{waiting:#}").starts_with("the secure element is holding off further tries")
        );
    }
}
