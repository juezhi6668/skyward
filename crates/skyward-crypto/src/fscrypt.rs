//! Letting a key into a filesystem, so the files it was used on can be
//! read. The kernel keeps the key for the filesystem, not for any one
//! file, and names it by a hash it works out itself.

use anyhow::{bail, Context, Result};
use std::path::Path;

/// How long the name the kernel gives a key is.
pub const NAME_BYTES: usize = 16;

/// Let `raw` into the filesystem mounted at `mount`, and give the name the
/// kernel knows it by. Every file whose directory names that key can be
/// read from then on.
#[cfg(target_os = "android")]
pub fn add_key(mount: &Path, raw: &[u8], wrapped: bool, recorded: Option<&[u8]>) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let dir = std::fs::File::open(mount).with_context(|| format!("open {}", mount.display()))?;
    let name = match name_by_identifier(dir.as_raw_fd(), raw, wrapped) {
        Ok(name) => Ok(name),
        // A kernel too old for that call is one that knows none of the calls
        // that name a key: on it the key is kept in the kernel's own ring of
        // them, under a name the filesystem looks up, which is the first
        // eight bytes of the key's own hash. That is the way Android 9 did
        // it, and the phone says so itself: the name it recorded beside the
        // key is eight bytes, where the newer way records sixteen.
        Err(e) if e.raw_os_error() == Some(libc::ENOTTY) => keep_in_keyring(raw, recorded),
        Err(e) => Err(e),
    };
    name.with_context(|| format!("let a key into {}", mount.display()))
}

/// The request's fixed part, before the key itself, for the newer way of
/// naming one: sixteen bytes of name and eighty of header.
const NEW_HEADER_BYTES: usize = 80;

/// How long a key for the storage hardware is, the key and the word after it.
const WRAPPED_KEY_BYTES: usize = 72;

/// How each way numbers itself, and where it keeps the length of the key.
const BY_IDENTIFIER: u32 = 2;
const NEW_KEY_BYTES_AT: usize = 40;
/// Where the older way keeps the name it was given.
const NEW_NAME_BYTES: usize = 16;
const OLD_NAME_BYTES: usize = 8;

/// The two calls, whose numbers carry the size of the request they take.
const ADD_BY_IDENTIFIER: u32 = 0xc050_6617;

/// The key is one only the storage hardware can unwrap.
const HARDWARE_WRAPPED: u32 = 1;

/// Hand the kernel a key it names by a hash it works out itself.
fn name_by_identifier(fd: std::os::fd::RawFd, raw: &[u8], wrapped: bool) -> std::io::Result<Vec<u8>> {
    let mut arg = vec![0u8; NEW_HEADER_BYTES + raw.len()];
    arg[0..4].copy_from_slice(&BY_IDENTIFIER.to_ne_bytes());
    arg[NEW_KEY_BYTES_AT..NEW_KEY_BYTES_AT + 4].copy_from_slice(&(raw.len() as u32).to_ne_bytes());
    if wrapped {
        arg[76..80].copy_from_slice(&HARDWARE_WRAPPED.to_ne_bytes());
    }
    arg[NEW_HEADER_BYTES..].copy_from_slice(raw);
    if unsafe { libc::ioctl(fd, ADD_BY_IDENTIFIER as libc::Ioctl, arg.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(arg[8..8 + NEW_NAME_BYTES].to_vec())
}

/// Keep the key in the kernel's own ring of them, under the name the
/// filesystem looks a key up by: `ext4:` and the first eight bytes of the
/// key's own hash, written out in hex.
fn keep_in_keyring(raw: &[u8], recorded: Option<&[u8]>) -> std::io::Result<Vec<u8>> {
    use sha2::{Digest, Sha256};
    /// The ring a recovery's own lookups are answered from.
    const SESSION_KEYRING: libc::c_long = -3;
    // The name is the phone's own, where it recorded one: on this way of
    // naming a key it is a word the phone chose when it made the key, not
    // one worked out from the key, and nothing can work it out again.
    let computed;
    let name = match recorded.filter(|name| name.len() == OLD_NAME_BYTES) {
        Some(name) => name,
        None => {
            computed = Sha256::digest(raw);
            &computed[..OLD_NAME_BYTES]
        }
    };
    // **Eight bytes more than the key.** A phone whose recovery had decrypted
    // kept its keys in the ring at seventy-two bytes where the hardware had
    // handed over sixty-four, and with sixty-four the folders stay shut while
    // with seventy-two they open: the storage hardware's own keys carry a
    // word of their own after the key, and the filesystem will not take one
    // without it. What the eight bytes say is not needed to read anything —
    // nothing on the end works as well as anything else.
    let mut payload = raw.to_vec();
    while payload.len() < WRAPPED_KEY_BYTES {
        payload.push(0);
    }
    let raw = &payload[..];
    let mut hex = String::new();
    for byte in name {
        hex.push_str(&format!("{byte:02x}"));
    }
    // **The same key under every name the filesystems look one up by, and in
    // both places they look.** A kernel of one age asks its own ring for
    // `ext4:` or `f2fs:`; the one after it keeps a ring named `fscrypt` and
    // asks that one for `fscrypt:<name>` — a phone whose recovery had
    // decrypted showed all of them at once, the same word after each, and a
    // ring of its own called `fscrypt` holding them.
    let kind = std::ffi::CString::new("logon").expect("no NUL");
    let keyring = std::ffi::CString::new("keyring").expect("no NUL");
    let named = std::ffi::CString::new("fscrypt").expect("no NUL");
    let ring = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            keyring.as_ptr(),
            named.as_ptr(),
            std::ptr::null::<u8>(),
            0 as libc::c_long,
            SESSION_KEYRING,
        )
    };
    for (prefix, where_) in [
        ("ext4:", SESSION_KEYRING),
        ("f2fs:", SESSION_KEYRING),
        ("fscrypt:", match ring {
            serial if serial > 0 => serial,
            _ => SESSION_KEYRING,
        }),
    ] {
        let said = std::ffi::CString::new(format!("{prefix}{hex}")).expect("no NUL");
        let kept = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                kind.as_ptr(),
                said.as_ptr(),
                raw.as_ptr(),
                raw.len(),
                where_,
            )
        };
        if kept < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(name.to_vec())
}

/// The name of the key a folder is kept by, read off the folder itself.
///
/// A folder's policy carries the name of the key that opens it, and that
/// name is a word the phone chose when it made the key — not one worked out
/// from it, so it can be read here and nowhere else. The policy has two
/// shapes and this phone keeps the first: a version, two ways of encrypting,
/// flags, and eight bytes of name.
pub fn policy_name(dir: &Path) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd;
    const POLICY_V1_BYTES: usize = 12;
    const NAME_AT: usize = 4;
    const GET_POLICY: u32 = 0x400c_6615;
    let folder = std::fs::File::open(dir).with_context(|| format!("open {}", dir.display()))?;
    let mut policy = [0u8; POLICY_V1_BYTES];
    if unsafe { libc::ioctl(folder.as_raw_fd(), GET_POLICY as libc::Ioctl, policy.as_mut_ptr()) }
        != 0
    {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("ask what key {} is kept by", dir.display()));
    }
    Ok(policy[NAME_AT..NAME_AT + OLD_NAME_BYTES].to_vec())
}

/// Whether the names and contents under `dir` read as they are: it is not
/// encrypted, or the key it is encrypted with is in the kernel. A user's
/// own files read only once that user's key is let in.
#[cfg(target_os = "android")]
pub fn unlocked(dir: &Path) -> Result<bool> {
    use std::os::fd::AsRawFd;
    const GET_POLICY: u32 = 0xc009_6616;
    const GET_KEY_STATUS: u32 = 0xc080_661a;
    /// How the first kind of policy names its key, and how the second does.
    const BY_DESCRIPTOR: u32 = 1;
    const BY_IDENTIFIER: u32 = 2;
    /// The second kind of policy is the largest: its version, three bytes
    /// of how it encrypts, four reserved, and the key's name.
    const POLICY_BYTES: usize = 24;
    const PRESENT: u32 = 2;

    let folder = std::fs::File::open(dir).with_context(|| format!("open {}", dir.display()))?;
    let mut policy = [0u8; 8 + POLICY_BYTES];
    policy[..8].copy_from_slice(&(POLICY_BYTES as u64).to_ne_bytes());
    if unsafe {
        libc::ioctl(
            folder.as_raw_fd(),
            GET_POLICY as libc::Ioctl,
            policy.as_mut_ptr(),
        )
    } != 0
    {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENODATA) {
            return Ok(true);
        }
        return Err(e).with_context(|| format!("read how {} is encrypted", dir.display()));
    }
    let mut status = [0u8; 128];
    match policy[8] {
        0 => {
            status[..4].copy_from_slice(&BY_DESCRIPTOR.to_ne_bytes());
            status[8..16].copy_from_slice(&policy[12..20]);
        }
        2 => {
            status[..4].copy_from_slice(&BY_IDENTIFIER.to_ne_bytes());
            status[8..8 + NAME_BYTES].copy_from_slice(&policy[16..16 + NAME_BYTES]);
        }
        other => bail!(
            "{} is encrypted under a policy of version {other}, which is not known here",
            dir.display()
        ),
    }
    if unsafe {
        libc::ioctl(
            folder.as_raw_fd(),
            GET_KEY_STATUS as libc::Ioctl,
            status.as_mut_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("ask whether the key for {} is in", dir.display()));
    }
    Ok(u32::from_ne_bytes(status[64..68].try_into().expect("four bytes")) == PRESENT)
}

/// Whether what a phone says about how it encrypts its files means the
/// keys are ones only the storage hardware can unwrap.
pub fn hardware_wrapped(mode: &str) -> bool {
    mode.split(['+', ':']).any(|part| part == "wrappedkey_v0")
}

/// Read the name the phone recorded for a key it let in, to check against
/// the name the kernel works out now.
pub fn recorded_name(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    match raw.len() == OLD_NAME_BYTES || raw.len() == NEW_NAME_BYTES {
        true => Ok(raw),
        false => bail!(
            "{} holds {} bytes, and a key's name is {OLD_NAME_BYTES} or {NEW_NAME_BYTES}",
            path.display(),
            raw.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phone_says_whether_the_hardware_holds_the_keys() {
        assert!(hardware_wrapped(
            "aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0"
        ));
        assert!(!hardware_wrapped("aes-256-xts:aes-256-cts:v2"));
        assert!(!hardware_wrapped(
            "aes-256-xts:aes-256-cts:v2+wrappedkey_v1"
        ));
    }

    #[test]
    fn a_name_is_read_back_only_at_its_own_length() {
        let dir = std::env::temp_dir().join(format!("skyward-fscrypt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("ref");
        std::fs::write(&good, [7u8; NAME_BYTES]).unwrap();
        assert_eq!(recorded_name(&good).unwrap(), [7u8; NAME_BYTES]);
        let short = dir.join("short");
        std::fs::write(&short, [7u8; 8]).unwrap();
        assert!(recorded_name(&short).is_err());
    }
}
