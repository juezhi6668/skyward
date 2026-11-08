//! Giving the data partition's files the SELinux labels the installed
//! system's own rules give them, looked up by the recovery's libselinux
//! as Android's restorecon looks them up.

use anyhow::{ensure, Context, Result};
use skyward_files::Relabeling;
use skyward_vab::Slot;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

const DATA: &str = "/data";

/// The rules each of the slot's partitions keeps for its files, by where
/// they are in it once mounted, in the order Android reads them.
const RULES: [(&str, &str); 5] = [
    ("system", "system/etc/selinux/plat_file_contexts"),
    ("system_ext", "etc/selinux/system_ext_file_contexts"),
    ("product", "etc/selinux/product_file_contexts"),
    ("vendor", "etc/selinux/vendor_file_contexts"),
    ("odm", "etc/selinux/odm_file_contexts"),
];

const LABEL: &CStr = c"security.selinux";

/// A partition of the slot that keeps rules is not mounted, by its base
/// name.
#[derive(Debug)]
pub struct Unmounted(pub String);

impl std::fmt::Display for Unmounted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is not mounted", self.0)
    }
}

impl std::error::Error for Unmounted {}

/// The installed system's rules for labeling files, from each partition of
/// `slot` that keeps some: every one of those partitions the slot has must
/// be mounted, and the system's own are always there.
pub fn rule_files(slot: Slot) -> Result<Vec<PathBuf>> {
    let bases = skyward_vab::slot_bases(slot)?;
    let mounted: Vec<PathBuf> = skyward_vab::mounted_partitions(slot)?
        .into_iter()
        .map(|m| m.mount_point)
        .collect();
    let mut found = Vec::new();
    for (base, file) in RULES {
        if !bases.iter().any(|b| b == base) {
            continue;
        }
        let point = skyward_vab::mount_point(base);
        if !mounted.contains(&point) {
            return Err(Unmounted(base.into()).into());
        }
        let path = point.join(file);
        if path.exists() {
            found.push(path);
        }
    }
    let system = skyward_vab::mount_point("system").join(RULES[0].1);
    ensure!(
        found.first() == Some(&system),
        "the system keeps no rules at {}",
        system.display()
    );
    Ok(found)
}

#[repr(C)]
struct SelinuxOpt {
    kind: c_int,
    value: *const c_char,
}

/// The kind of labels looked up, files', and the option naming a file of
/// rules, as libselinux's label.h numbers them.
const SELABEL_CTX_FILE: c_uint = 0;
const SELABEL_OPT_PATH: c_int = 3;

type Open = unsafe extern "C" fn(c_uint, *const SelinuxOpt, c_uint) -> *mut c_void;
type Lookup = unsafe extern "C" fn(*mut c_void, *mut *mut c_char, *const c_char, c_int) -> c_int;
type Close = unsafe extern "C" fn(*mut c_void);
type Free = unsafe extern "C" fn(*mut c_char);

/// Rules for labeling files, read by the recovery's libselinux.
struct Rules {
    lib: *mut c_void,
    handle: *mut c_void,
    lookup: Lookup,
    close: Close,
    free: Free,
}

impl Rules {
    /// The rules in `files`, a later file's taking the place of an earlier
    /// one's for the same path, as Android reads them.
    fn open(files: &[PathBuf]) -> Result<Rules> {
        let lib = unsafe { libc::dlopen(c"libselinux.so".as_ptr(), libc::RTLD_NOW) };
        ensure!(
            !lib.is_null(),
            "load libselinux.so: {}",
            unsafe { CStr::from_ptr(libc::dlerror()) }.to_string_lossy()
        );
        let find = |name: &CStr| -> Result<*mut c_void> {
            let symbol = unsafe { libc::dlsym(lib, name.as_ptr()) };
            ensure!(
                !symbol.is_null(),
                "find {} in libselinux.so",
                name.to_string_lossy()
            );
            Ok(symbol)
        };
        let open: Open =
            unsafe { std::mem::transmute::<*mut c_void, Open>(find(c"selabel_open")?) };
        let lookup =
            unsafe { std::mem::transmute::<*mut c_void, Lookup>(find(c"selabel_lookup")?) };
        let close = unsafe { std::mem::transmute::<*mut c_void, Close>(find(c"selabel_close")?) };
        let free = unsafe { std::mem::transmute::<*mut c_void, Free>(find(c"freecon")?) };
        let paths = files
            .iter()
            .map(|f| CString::new(f.as_os_str().as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .context("a rules path holds a NUL")?;
        let opts: Vec<SelinuxOpt> = paths
            .iter()
            .map(|p| SelinuxOpt {
                kind: SELABEL_OPT_PATH,
                value: p.as_ptr(),
            })
            .collect();
        let handle = unsafe { open(SELABEL_CTX_FILE, opts.as_ptr(), opts.len() as c_uint) };
        if handle.is_null() {
            let e = std::io::Error::last_os_error();
            unsafe { libc::dlclose(lib) };
            return Err(e).with_context(|| format!("read the labeling rules in {files:?}"));
        }
        Ok(Rules {
            lib,
            handle,
            lookup,
            close,
            free,
        })
    }

    /// The label the rules give the entry the system names `path`, of the
    /// type in `mode`, as the attribute stores it; none where no rule does.
    fn lookup(&self, path: &Path, mode: u32) -> Result<Option<Vec<u8>>> {
        let key = CString::new(path.as_os_str().as_bytes())
            .with_context(|| format!("{} holds a NUL", path.display()))?;
        let mut found: *mut c_char = std::ptr::null_mut();
        if unsafe { (self.lookup)(self.handle, &mut found, key.as_ptr(), mode as c_int) } < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(e).with_context(|| format!("look up the label of {}", path.display()));
        }
        let label = unsafe { CStr::from_ptr(found) }
            .to_bytes_with_nul()
            .to_vec();
        unsafe { (self.free)(found) };
        Ok(Some(label))
    }
}

impl Drop for Rules {
    fn drop(&mut self) {
        unsafe {
            (self.close)(self.handle);
            libc::dlclose(self.lib);
        }
    }
}

/// The label an entry carries, without the NUL it is stored with; none on
/// an entry that has none.
fn label(path: &Path) -> Result<Option<Vec<u8>>> {
    let c = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("{} holds a NUL", path.display()))?;
    let mut buf = vec![0u8; 256];
    let n = unsafe {
        libc::lgetxattr(
            c.as_ptr(),
            LABEL.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENODATA) {
            return Ok(None);
        }
        return Err(e).with_context(|| format!("read the label of {}", path.display()));
    }
    buf.truncate(n as usize);
    while buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(Some(buf))
}

/// Give an entry, a link its own, the label `value`, stored with its NUL
/// as libselinux stores one.
fn set_label(path: &Path, value: &[u8]) -> Result<()> {
    let c = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("{} holds a NUL", path.display()))?;
    if unsafe {
        libc::lsetxattr(
            c.as_ptr(),
            LABEL.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("label {}", path.display()));
    }
    Ok(())
}

/// Give each entry of the data partition the label the rules in `files`
/// give it, as [`skyward_files::relabel`] goes through them.
pub fn run(
    files: &[PathBuf],
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(Relabeling),
) -> Result<()> {
    let rules = Rules::open(files)?;
    let root = Path::new(DATA);
    let mut give = |path: &Path, rel: &Path, meta: &std::fs::Metadata| -> Result<bool> {
        let named = if rel.as_os_str().is_empty() {
            root.to_path_buf()
        } else {
            root.join(rel)
        };
        let Some(wanted) = rules.lookup(&named, meta.mode())? else {
            return Ok(false);
        };
        if label(path)?.is_some_and(|had| had == wanted[..wanted.len() - 1]) {
            return Ok(false);
        }
        set_label(path, &wanted)?;
        Ok(true)
    };
    skyward_files::relabel(root, &mut give, cancel, progress)
}
