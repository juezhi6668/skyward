//! The package the system leaves in misc when the phone is to be erased
//! for good: it is signed with the keys the phone takes its updates signed
//! with, says it is for this phone, and lists the partitions to discard.

use crate::package::{Metadata, Phone};
use crate::signature::{self, Verdict};
use crate::Refusal;
use anyhow::{Context, Result};
use std::io::{Cursor, Read};
use zip::ZipArchive;

const METADATA: &str = "META-INF/com/android/metadata";

/// The entry that lists the partitions, and the file the phone's own
/// partitions keep for a package that holds no list.
const LIST: &str = "recovery.wipe";
const ON_PHONE: &str = "/etc/recovery.wipe";

/// What a build signed with the keys its maker keeps says of itself: a
/// package that erases such a phone for good has to name the phone.
const RELEASE_KEYS: &str = "release-keys";

/// The kind of package this is: the one that erases a phone for good.
const BRICK: &str = "BRICK";

/// What a wipe package asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wipe {
    /// Discard these partitions, in this order.
    Partitions(Vec<String>),
    /// The phone is not to be erased by this package.
    Refused(Refusal),
}

/// Read the wipe package in `bytes`: check it was signed with one of the
/// phone's update keys and that it is for this phone, and give the
/// partitions it has discarded. `tags` is what the phone says its build is
/// signed with.
pub fn read(bytes: Vec<u8>, phone: &Phone, tags: &str) -> Result<Wipe> {
    let certificates = std::fs::File::open(signature::CERTIFICATES)
        .with_context(|| format!("open {}", signature::CERTIFICATES))?;
    let keys = signature::keys(std::io::BufReader::new(certificates))
        .with_context(|| format!("read {}", signature::CERTIFICATES))?;
    let size = bytes.len() as u64;
    let verdict = signature::verify(Cursor::new(&bytes), size, &keys, |_, _| true)
        .context("check the wipe package's signature")?;
    match verdict {
        Verdict::Signed => {}
        Verdict::Unsigned => return Ok(Wipe::Refused(Refusal::Unsigned)),
        Verdict::Unverified => return Ok(Wipe::Refused(Refusal::Unverified)),
        Verdict::Stopped => {
            unreachable!("the check of a package already in memory is never stopped")
        }
    }
    let mut zip =
        ZipArchive::new(Cursor::new(&bytes)).context("read the wipe package's zip directory")?;
    let metadata = Metadata::parse(&text(&mut zip, METADATA)?);
    if let Err(refusal) = check(&metadata, phone, tags) {
        return Ok(Wipe::Refused(refusal));
    }
    let listed = match zip.index_for_name(LIST) {
        Some(_) => text(&mut zip, LIST)?,
        // A package that lists nothing erases what the phone's own
        // partitions list, as Android's recovery has it.
        None => std::fs::read_to_string(ON_PHONE).with_context(|| format!("read {ON_PHONE}"))?,
    };
    Ok(Wipe::Partitions(partitions(&listed)))
}

/// Whether the package says it may erase `phone` for good, checked the way
/// Android's recovery checks it: the kind of package, the devices it names,
/// and the serial numbers, which only a phone built with its maker's own
/// keys has to be among.
fn check(metadata: &Metadata, phone: &Phone, tags: &str) -> Result<(), Refusal> {
    let kind = metadata.get("ota-type").unwrap_or_default();
    if kind != BRICK {
        return Err(Refusal::NotBrick(kind.to_string()));
    }
    let devices = metadata.get("pre-device").unwrap_or_default();
    if !devices.split('|').any(|name| name.trim() == phone.device) {
        return Err(Refusal::OtherDevice(devices.to_string()));
    }
    match metadata.get("serialno") {
        Some(serials) => {
            if !serials
                .split('|')
                .any(|serial| serial.trim() == phone.serial)
            {
                return Err(Refusal::OtherSerial);
            }
        }
        None if tags.trim() == RELEASE_KEYS => return Err(Refusal::NoSerial),
        None => {}
    }
    Ok(())
}

/// The partitions a list names, one a line, past the comments and the empty
/// lines.
fn partitions(listed: &str) -> Vec<String> {
    listed
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

fn text<R: Read + std::io::Seek>(zip: &mut ZipArchive<R>, name: &str) -> Result<String> {
    let mut entry = zip.by_name(name).with_context(|| format!("open {name}"))?;
    let mut s = String::new();
    entry
        .read_to_string(&mut s)
        .with_context(|| format!("read {name}"))?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phone() -> Phone {
        Phone {
            device: "ishtar".into(),
            serial: "2674dc3e".into(),
            installed: None,
        }
    }

    fn metadata(lines: &[&str]) -> Metadata {
        Metadata::parse(&lines.join("\n"))
    }

    #[test]
    fn a_package_for_this_phone_erases_it() {
        let m = metadata(&[
            "ota-type=BRICK",
            "pre-device=ishtar",
            "serialno=2674dc3e|1234abcd",
        ]);
        assert_eq!(check(&m, &phone(), "release-keys"), Ok(()));
    }

    #[test]
    fn a_package_of_another_kind_or_for_another_phone_is_refused() {
        let update = metadata(&["ota-type=AB", "pre-device=ishtar"]);
        assert_eq!(
            check(&update, &phone(), "release-keys"),
            Err(Refusal::NotBrick("AB".into()))
        );
        let other = metadata(&["ota-type=BRICK", "pre-device=aurora|dagger"]);
        assert_eq!(
            check(&other, &phone(), "test-keys"),
            Err(Refusal::OtherDevice("aurora|dagger".into()))
        );
        let serials = metadata(&["ota-type=BRICK", "pre-device=ishtar", "serialno=1234abcd"]);
        assert_eq!(
            check(&serials, &phone(), "test-keys"),
            Err(Refusal::OtherSerial)
        );
    }

    #[test]
    fn a_package_that_names_no_phone_erases_only_one_off_its_makers_keys() {
        let m = metadata(&["ota-type=BRICK", "pre-device=ishtar"]);
        assert_eq!(check(&m, &phone(), "release-keys"), Err(Refusal::NoSerial));
        assert_eq!(check(&m, &phone(), "dev-keys"), Ok(()));
    }

    #[test]
    fn the_partitions_are_read_a_line_each() {
        let listed =
            "# the ones to erase\n/dev/block/by-name/userdata\n\n  /dev/block/by-name/metadata  \n";
        assert_eq!(
            partitions(listed),
            ["/dev/block/by-name/userdata", "/dev/block/by-name/metadata"]
        );
        assert!(partitions("# nothing\n\n").is_empty());
    }
}
