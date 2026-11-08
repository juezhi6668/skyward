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
pub fn add_key(
    mount: &Path,
    raw: &[u8],
    wrapped: bool,
    recorded: Option<&[u8]>,
    mode: u32,
) -> Result<Vec<u8>> {
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
        Err(e) if e.raw_os_error() == Some(libc::ENOTTY) => {
            keep_in_keyring(raw, recorded, mode, None)
        }
        Err(e) => Err(e),
    };
    name.with_context(|| format!("let a key into {}", mount.display()))
}

/// Let the same key in with the word in front of it and the size after it of
/// the caller's choosing, for finding what this kernel takes. The name it is
/// let in under is the one the phone recorded beside it.
#[cfg(target_os = "android")]
pub fn add_key_trying(raw: &[u8], recorded: &[u8], mode: u32, size: usize) -> Result<()> {
    keep_in_keyring(raw, Some(recorded), mode, Some(size))
        .map(|_| ())
        .context("let a key in that way")
}

#[cfg(target_os = "android")]
/// The request's fixed part, before the key itself, for the newer way of
/// naming one: sixteen bytes of name and eighty of header.
const NEW_HEADER_BYTES: usize = 80;

/// The largest key the kernel's own structure for one holds.
const MAX_KEY_BYTES: usize = 64;

#[cfg(any(target_os = "android", test))]
/// Where that structure keeps the key, and how much of it is the key.
const KEY_AT: usize = 4;
#[cfg(any(target_os = "android", test))]
const KEY_SIZE_AT: usize = 68;

/// How long that structure is: a word of how the key encrypts, the key in a
/// buffer of the largest size a key can be, and how much of that buffer is
/// the key.
pub const KEYRING_KEY_BYTES: usize = 4 + MAX_KEY_BYTES + 4;

#[cfg(any(target_os = "android", test))]
/// The key as the kernel takes it into its ring — **not the key by itself.**
/// A kernel of this age reads the key out of this structure and takes no
/// other length at all, refusing one handed over as the key alone: the
/// folders then read as scrambled names, which is exactly what a key that
/// was never let in looks like, and why one was thought not to work when it
/// was only written down wrongly.
fn key_payload(raw: &[u8], mode: u32, size: Option<usize>) -> Vec<u8> {
    let mut payload = vec![0u8; KEYRING_KEY_BYTES];
    payload[..4].copy_from_slice(&mode.to_ne_bytes());
    let held = raw.len().min(MAX_KEY_BYTES);
    payload[KEY_AT..KEY_AT + held].copy_from_slice(&raw[..held]);
    let size = size.unwrap_or(held).min(held);
    payload[KEY_SIZE_AT..].copy_from_slice(&(size as u32).to_ne_bytes());
    payload
}

/// How a phone's own words for how it encrypts say the contents of a file
/// are encrypted, in the numbering the kernel uses for the same thing.
pub fn contents_mode(said: &str) -> u32 {
    for part in said.split(['+', ':', ',']) {
        match part {
            "aes-256-xts" => return 1,
            "aes-256-cts" => return 2,
            "adiantum" => return 9,
            _ => {}
        }
    }
    2
}

/// How each way numbers itself, and where it keeps the length of the key.
#[cfg(target_os = "android")]
const BY_IDENTIFIER: u32 = 2;
#[cfg(target_os = "android")]
const NEW_KEY_BYTES_AT: usize = 40;
/// Where the older way keeps the name it was given.
const NEW_NAME_BYTES: usize = 16;
const OLD_NAME_BYTES: usize = 8;

/// The two calls, whose numbers carry the size of the request they take.
#[cfg(target_os = "android")]
const ADD_BY_IDENTIFIER: u32 = 0xc050_6617;

/// The key is one only the storage hardware can unwrap.
#[cfg(target_os = "android")]
const HARDWARE_WRAPPED: u32 = 1;

/// Hand the kernel a key it names by a hash it works out itself.
#[cfg(target_os = "android")]
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

/// The name a key is let in under where the phone recorded none beside it:
/// the first eight bytes of the key's own hash. The phone's own users' keys
/// are kept with no word beside them, so this is the only name they can have.
pub fn own_name(raw: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(raw)[..OLD_NAME_BYTES].to_vec()
}

/// Keep the key in the kernel's own ring of them, under the name the
/// filesystem looks a key up by: `ext4:` and the first eight bytes of the
/// key's own hash, written out in hex.
#[cfg(target_os = "android")]
fn keep_in_keyring(
    raw: &[u8],
    recorded: Option<&[u8]>,
    mode: u32,
    size: Option<usize>,
) -> std::io::Result<Vec<u8>> {
    /// The ring a recovery's own lookups are answered from.
    const SESSION_KEYRING: libc::c_long = -3;
    // The name is the phone's own, where it recorded one: on this way of
    // naming a key it is a word the phone chose when it made the key, not
    // one worked out from the key, and nothing can work it out again.
    let computed;
    let name = match recorded.filter(|name| name.len() == OLD_NAME_BYTES) {
        Some(name) => name,
        None => {
            computed = own_name(raw);
            &computed[..]
        }
    };
    let payload = key_payload(raw, mode, size);
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
#[cfg(target_os = "android")]
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

/// How a folder says it is encrypted, and whether the key it is kept by is
/// in. Read off the folder itself, which is the only place that knows: a
/// folder whose names come back scrambled is one whose key the kernel could
/// not find, and the name it looked for is here to compare against the name
/// a key was let in under.
#[cfg(target_os = "android")]
pub fn describe(dir: &Path) -> String {
    use std::os::fd::AsRawFd;
    const POLICY_V1_BYTES: usize = 12;
    const GET_POLICY: u32 = 0x400c_6615;
    const GET_POLICY_EX: u32 = 0xc009_6616;
    /// The larger kind of policy: its version, three bytes of how it
    /// encrypts, four reserved, and the key's name.
    const POLICY_BYTES: usize = 24;
    const GET_KEY_STATUS: u32 = 0xc080_661a;
    /// How each kind of policy names its key.
    const BY_DESCRIPTOR: u32 = 1;
    const BY_IDENTIFIER: u32 = 2;
    /// Where the kernel puts the answer, after the request's own part.
    const STATUS_AT: usize = 64;
    const ABSENT: u32 = 1;
    const PRESENT: u32 = 2;

    let folder = match std::fs::File::open(dir) {
        Ok(folder) => folder,
        Err(e) => return format!("cannot be opened: {e}"),
    };
    let mut kind = BY_DESCRIPTOR;
    let name;
    // The newer call first: it says which kind of policy the folder keeps,
    // which the older one cannot.
    let mut larger = [0u8; 8 + POLICY_BYTES];
    larger[..8].copy_from_slice(&(POLICY_BYTES as u64).to_ne_bytes());
    if unsafe {
        libc::ioctl(
            folder.as_raw_fd(),
            GET_POLICY_EX as libc::Ioctl,
            larger.as_mut_ptr(),
        )
    } == 0
    {
        match larger[8] {
            0 => name = larger[12..20].to_vec(),
            2 => {
                kind = BY_IDENTIFIER;
                name = larger[16..16 + NAME_BYTES].to_vec();
            }
            other => return format!("a policy of version {other}"),
        }
    } else {
        let mut small = [0u8; POLICY_V1_BYTES];
        if unsafe {
            libc::ioctl(
                folder.as_raw_fd(),
                GET_POLICY as libc::Ioctl,
                small.as_mut_ptr(),
            )
        } != 0
        {
            return match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ENODATA) => "not encrypted".to_string(),
                Some(e) => format!("not encrypted ({e})"),
                None => "not encrypted".to_string(),
            };
        }
        name = small[4..12].to_vec();
    }
    let mut status = [0u8; 128];
    status[..4].copy_from_slice(&kind.to_ne_bytes());
    status[8..8 + name.len()].copy_from_slice(&name);
    let kept = match unsafe {
        libc::ioctl(
            folder.as_raw_fd(),
            GET_KEY_STATUS as libc::Ioctl,
            status.as_mut_ptr(),
        )
    } {
        0 => match u32::from_ne_bytes(
            status[STATUS_AT..STATUS_AT + 4]
                .try_into()
                .expect("four bytes"),
        ) {
            ABSENT => "the key is not in".to_string(),
            PRESENT => "the key is in".to_string(),
            other => format!("the key is {other}"),
        },
        _ => format!(
            "whether the key is in is not told ({})",
            std::io::Error::last_os_error()
        ),
    };
    let (version, word) = match kind {
        BY_IDENTIFIER => ("v2", "identifier"),
        _ => ("v1", "descriptor"),
    };
    format!("{version} {word} {}: {kept}", hex(&name))
}

/// Bytes as the words the phone writes them as.
pub fn hex(bytes: &[u8]) -> String {
    let mut said = String::new();
    for byte in bytes {
        said.push_str(&format!("{byte:02x}"));
    }
    said
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
        // A phone of one age records sixteen bytes of name beside a key and
        // one of the age before it eight, and both are read back as they are.
        for name in [NEW_NAME_BYTES, OLD_NAME_BYTES] {
            let at = dir.join(format!("name-{name}"));
            std::fs::write(&at, vec![7u8; name]).unwrap();
            assert_eq!(recorded_name(&at).unwrap(), vec![7u8; name]);
        }
        let neither = dir.join("neither");
        std::fs::write(&neither, [7u8; 10]).unwrap();
        assert!(recorded_name(&neither).is_err());
    }

    #[test]
    fn a_key_is_handed_over_in_the_structure_the_kernel_takes() {
        // A key is not handed over as itself: the kernel reads it out of a
        // structure with a word in front and a size behind, and takes no
        // other length at all. Getting this wrong leaves every folder
        // reading as scrambled names, which looks exactly like no key.
        let key = [9u8; 64];
        let payload = key_payload(&key, 2, None);
        assert_eq!(payload.len(), KEYRING_KEY_BYTES);
        assert_eq!(payload.len(), 72);
        assert_eq!(&payload[..4], &2u32.to_ne_bytes());
        assert_eq!(&payload[4..68], &key[..]);
        assert_eq!(&payload[68..], &64u32.to_ne_bytes());
    }

    #[test]
    fn a_phone_says_how_its_contents_are_encrypted() {
        // The word in front of a key is how the contents are encrypted, in
        // the kernel's numbering: XTS is 1, CTS is 2, Adiantum is 9.
        assert_eq!(contents_mode("ice:aes-256-cts:v1"), 2);
        assert_eq!(contents_mode("aes-256-xts"), 1);
        assert_eq!(
            contents_mode("aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized"),
            1
        );
        assert_eq!(contents_mode("adiantum"), 9);
    }
}
