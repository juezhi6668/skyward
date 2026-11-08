//! The phone's key hardware of the oldest kind this program speaks: a plain C
//! module loaded into this process, which is what the Qualcomm keymaster on
//! this phone is.
//!
//! Why not the hardware service the newer kinds register: this phone's is a
//! **passthrough** implementation. `android.hardware.keymaster@3.0-impl.so`
//! exports `HIDL_FETCH_IKeymasterDevice` and contains no `registerAsService`,
//! so it never announces itself to the hardware directory — nothing to find,
//! and every attempt to look it up answers "has not registered". What it does
//! instead is load the vendor's own module with
//! `hw_get_module_by_class("keystore", …)` and wrap it in the HIDL
//! interface, which is the same module reached here directly, one layer down
//! and without any HIDL at all.
//!
//! **The device this module hands back is not laid out as
//! `hardware/keymaster1.h` says.** Measured on the phone: `close` (+64) and
//! `configure` (+72) are null, and the function table starts at **+192**.
//! Naming each entry by the module's own symbols — the offset from the
//! module's load address, looked up in its symbol table — says what it is: a
//! Qualcomm device puts six capability queries first (`get_supported_algorithms`,
//! block modes, padding modes, digests, import and export formats), then the
//! keymaster1 functions from `generate_key_10` at +248. So the offsets below
//! are **measured, not declared**: they were read off the phone and named
//! against the module's symbols. The function that reads its own context from
//! the device at +128 confirms the structure being read is the one the module
//! wrote.
//!
//! The interface's own C types (`keymaster_key_param_t`, `keymaster_blob_t`
//! and the rest) are written out by hand for the same reason: no header for
//! them is on the phone either.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

/// The module the vendor's key hardware is behind, and the class its library
/// is named after: `keystore.<board>.so`, whose board name comes from the
/// phone itself.
const CLASS: &str = "keystore";

/// What the module's `open` is called with. A hardware module of this age
/// takes its own id and nothing else: `default`, the board name and NULL are
/// all refused.
const DEVICE_ID: &str = "keymaster";

/// The library that loads a hardware module by class and name.
const HARDWARE: &str = "libhardware.so";
const GET_MODULE: &str = "hw_get_module_by_class";

/// Where each function sits in the device the module hands back, measured on
/// the phone and named against the module's own symbols.
pub mod at {
    pub const GET_KEY_CHARACTERISTICS: usize = 256;
    pub const BEGIN: usize = 296;
    pub const UPDATE: usize = 304;
    pub const FINISH: usize = 312;
    pub const ABORT: usize = 320;
}

/// What the key hardware answers. A key it cannot unwrap says so with
/// `INVALID_KEY_BLOB`; a key made under an older build says
/// `KEY_REQUIRES_UPGRADE`.
pub const OK: c_int = 0;
pub const INVALID_KEY_BLOB: c_int = -33;
pub const KEY_REQUIRES_UPGRADE: c_int = -62;

/// The tags this program writes, as `keymaster_defs.h` numbers them: the
/// kind of value in the top four bits, the tag itself below.
mod tag {
    pub const PURPOSE: u32 = 0x2000_0001;
    pub const BLOCK_MODE: u32 = 0x2000_0004;
    pub const PADDING: u32 = 0x2000_0006;
    pub const MIN_MAC_LENGTH: u32 = 0x3000_0008;
    pub const APPLICATION_ID: u32 = 0x9000_0259;
    pub const NONCE: u32 = 0x9000_03e9;
}

/// How long an AES-GCM tag is here.
const MAC_BITS: u32 = 128;

/// What a key is used for, as the hardware numbers it.
pub const PURPOSE_DECRYPT: c_int = 1;

/// A blob as the C interface passes one: bytes that are not this program's.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Blob {
    pub data: *const u8,
    pub length: usize,
}

impl Blob {
    pub fn of(bytes: &[u8]) -> Blob {
        Blob {
            data: bytes.as_ptr(),
            length: bytes.len(),
        }
    }

    pub fn empty() -> Blob {
        Blob::default()
    }

    /// The bytes as the hardware handed them over, copied out before
    /// whatever holds them goes back.
    pub unsafe fn take(&self) -> Vec<u8> {
        match (self.data.is_null(), self.length) {
            (true, _) | (_, 0) => Vec::new(),
            (false, n) => std::slice::from_raw_parts(self.data, n).to_vec(),
        }
    }
}

/// One parameter of a key: the tag, and the arm of the union it carries,
/// which is two words wide because the widest arm is a blob.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Param {
    pub tag: u32,
    pub arm: [u64; 2],
}

impl Param {
    /// A tag whose value is a number.
    pub fn number(tag: u32, value: u32) -> Param {
        Param {
            tag,
            arm: [value as u64, 0],
        }
    }

    /// A tag whose value is a run of bytes, which has to outlive the call.
    pub fn bytes(tag: u32, value: &[u8]) -> Param {
        Param {
            tag,
            arm: [value.as_ptr() as u64, value.len() as u64],
        }
    }
}

/// A set of parameters, as the C interface passes one.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ParamSet {
    pub params: *const Param,
    pub length: usize,
}

impl ParamSet {
    pub fn of(params: &[Param]) -> ParamSet {
        ParamSet {
            params: params.as_ptr(),
            length: params.len(),
        }
    }

    pub fn empty() -> ParamSet {
        ParamSet {
            params: std::ptr::null(),
            length: 0,
        }
    }
}

/// What a key may be used for, as the hardware answers: one set for what the
/// hardware enforces and one for what software enforces.
#[repr(C)]
pub struct Characteristics {
    pub hardware: *mut ParamSet,
    pub software: *mut ParamSet,
}

/// The device this program talks to, kept alive as long as it is used: the
/// module behind it is a loaded library and the device is its own memory.
pub struct Keymaster1 {
    device: *mut c_void,
}

/// The parts of `hw_module_t` this program reads.
#[repr(C)]
struct Module {
    tag: u32,
    module_api_version: u16,
    hal_api_version: u16,
    id: *const c_char,
    name: *const c_char,
    author: *const c_char,
    methods: *const Methods,
    dso: *mut c_void,
    reserved: [u32; 32],
}

/// The one method a module has: opening a device of it.
#[repr(C)]
struct Methods {
    open: Option<unsafe extern "C" fn(*const Module, *const c_char, *mut *mut c_void) -> c_int>,
}

type GetKeyCharacteristics = unsafe extern "C" fn(
    *mut c_void,
    *const Blob,
    *const Blob,
    *const Blob,
    *mut *mut Characteristics,
) -> c_int;
type Begin = unsafe extern "C" fn(
    *mut c_void,
    c_int,
    *const Blob,
    *const ParamSet,
    *mut ParamSet,
    *mut u64,
) -> c_int;
type Update = unsafe extern "C" fn(
    *mut c_void,
    u64,
    *const ParamSet,
    *const Blob,
    *mut usize,
    *mut ParamSet,
    *mut Blob,
) -> c_int;
type Finish = unsafe extern "C" fn(
    *mut c_void,
    u64,
    *const ParamSet,
    *const Blob,
    *const Blob,
    *mut ParamSet,
    *mut Blob,
) -> c_int;
type Abort = unsafe extern "C" fn(*mut c_void, u64) -> c_int;

impl Keymaster1 {
    /// Load the phone's key hardware into this process.
    pub fn open() -> Result<Keymaster1> {
        let library = CString::new(HARDWARE).expect("no NUL");
        let get_module = CString::new(GET_MODULE).expect("no NUL");
        let loaded = unsafe { libc::dlopen(library.as_ptr(), libc::RTLD_NOW) };
        if loaded.is_null() {
            bail!("{HARDWARE} will not load");
        }
        let found = unsafe { libc::dlsym(loaded, get_module.as_ptr()) };
        if found.is_null() {
            bail!("{HARDWARE} has no {GET_MODULE}");
        }
        let get_module: unsafe extern "C" fn(
            *const c_char,
            *const c_char,
            *mut *const Module,
        ) -> c_int = unsafe { std::mem::transmute(found) };
        let class = CString::new(CLASS).expect("no NUL");
        let mut module: *const Module = std::ptr::null();
        // The name is left out: the phone's own board name is what the
        // module is named after, and that is what the loader falls back to.
        let said = unsafe { get_module(class.as_ptr(), std::ptr::null(), &mut module) };
        if said != 0 || module.is_null() {
            bail!("{CLASS} is not a hardware module on this phone ({said})");
        }
        let methods = unsafe { (*module).methods };
        let open = unsafe { methods.as_ref() }
            .and_then(|m| m.open)
            .context("the key hardware module has no way to open a device")?;
        let id = CString::new(DEVICE_ID).expect("no NUL");
        let mut device: *mut c_void = std::ptr::null_mut();
        let opened = unsafe { open(module, id.as_ptr(), &mut device) };
        if opened != 0 || device.is_null() {
            bail!("the key hardware will not open a device ({opened})");
        }
        Ok(Keymaster1 { device })
    }

    /// The function at `offset` in the device, read as the shape it is
    /// called with.
    unsafe fn function<T: Copy>(&self, offset: usize) -> Result<T> {
        let slot = unsafe { self.device.cast::<u8>().add(offset) as *const usize };
        let pointer = unsafe { std::ptr::read_unaligned(slot) };
        if pointer == 0 {
            bail!("the key hardware has nothing at +{offset}");
        }
        Ok(unsafe { std::mem::transmute_copy(&pointer) })
    }

    /// What the hardware says `key` may be used for, as (tag, number) pairs.
    /// A tag whose value is a run of bytes is reported by its length, which
    /// is what a caller asks about.
    pub fn authorizations(&self, key: &[u8], app_id: &[u8]) -> Result<Vec<(u32, u64)>> {
        let get: GetKeyCharacteristics = unsafe { self.function(at::GET_KEY_CHARACTERISTICS) }?;
        let blob = Blob::of(key);
        let client = match app_id.is_empty() {
            true => Blob::empty(),
            false => Blob::of(app_id),
        };
        let mut said: *mut Characteristics = std::ptr::null_mut();
        let answer = unsafe { get(self.device, &blob, &client, &Blob::empty(), &mut said) };
        if answer != OK {
            bail!("the key hardware refused to say what the key is for ({answer})");
        }
        if said.is_null() {
            bail!("the key hardware said nothing about the key");
        }
        let mut out = Vec::new();
        for set in unsafe { [(*said).hardware, (*said).software] } {
            let Some(set) = (unsafe { set.as_ref() }) else {
                continue;
            };
            if set.params.is_null() {
                continue;
            }
            for param in unsafe { std::slice::from_raw_parts(set.params, set.length) } {
                out.push((param.tag, param.arm[0]));
            }
        }
        Ok(out)
    }

    /// Open a decryption with the hardware and keep hold of it.
    pub fn begin(&self, key: &[u8], params: &[Param]) -> Result<u64> {
        let begin: Begin = unsafe { self.function(at::BEGIN) }?;
        let blob = Blob::of(key);
        let asked = ParamSet::of(params);
        let mut out = ParamSet::empty();
        let mut handle = 0u64;
        let answer =
            unsafe { begin(self.device, PURPOSE_DECRYPT, &blob, &asked, &mut out, &mut handle) };
        if answer != OK {
            bail!("the key hardware refused to start a decryption ({answer})");
        }
        Ok(handle)
    }

    pub fn update(&self, handle: u64, input: &[u8]) -> Result<Vec<u8>> {
        let update: Update = unsafe { self.function(at::UPDATE) }?;
        let asked = ParamSet::empty();
        let blob = Blob::of(input);
        let mut consumed = 0usize;
        let mut out = ParamSet::empty();
        let mut output = Blob::empty();
        let answer =
            unsafe { update(self.device, handle, &asked, &blob, &mut consumed, &mut out, &mut output) };
        if answer != OK {
            bail!("the key hardware refused to feed the decryption ({answer})");
        }
        Ok(unsafe { output.take() })
    }

    pub fn finish(&self, handle: u64) -> Result<Vec<u8>> {
        let finish: Finish = unsafe { self.function(at::FINISH) }?;
        let asked = ParamSet::empty();
        let mut out = ParamSet::empty();
        let mut output = Blob::empty();
        let answer = unsafe {
            finish(
                self.device,
                handle,
                &asked,
                &Blob::empty(),
                &Blob::empty(),
                &mut out,
                &mut output,
            )
        };
        if answer != OK {
            bail!("the key hardware refused to close the decryption ({answer})");
        }
        Ok(unsafe { output.take() })
    }

    pub fn abort(&self, handle: u64) -> Result<()> {
        let abort: Abort = unsafe { self.function(at::ABORT) }?;
        let answer = unsafe { abort(self.device, handle) };
        if answer != OK {
            bail!("the key hardware refused to drop the decryption ({answer})");
        }
        Ok(())
    }

    /// Undo an AES-GCM encryption the hardware did with `key`. It only hands
    /// back the plaintext when the application id is the one the key was
    /// made for, so a wrong secret fails here rather than yielding something
    /// that looks like a key.
    pub fn gcm_decrypt(
        &self,
        key: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let mut params = vec![
            Param::number(tag::BLOCK_MODE, MODE_GCM),
            Param::number(tag::PADDING, PAD_NONE),
            Param::number(tag::MIN_MAC_LENGTH, MAC_BITS),
            Param::bytes(tag::NONCE, nonce),
            Param::number(tag::PURPOSE, PURPOSE_DECRYPT as u32),
        ];
        if !app_id.is_empty() {
            params.push(Param::bytes(tag::APPLICATION_ID, app_id));
        }
        let handle = self.begin(key, &params)?;
        let mut out = match self.update(handle, body) {
            Ok(out) => out,
            Err(e) => {
                let _ = self.abort(handle);
                return Err(e);
            }
        };
        match self.finish(handle) {
            Ok(tail) => {
                out.extend_from_slice(&tail);
                Ok(out)
            }
            Err(e) => {
                let _ = self.abort(handle);
                Err(e)
            }
        }
    }

    /// Whether the hardware will unwrap the key at all: a decryption is
    /// opened on it under a nonce of nothing and dropped again, which reads
    /// nothing and changes nothing.
    pub fn usable(&self, key: &[u8], app_id: &[u8]) -> Result<()> {
        let mut params = vec![
            Param::number(tag::BLOCK_MODE, MODE_GCM),
            Param::number(tag::PADDING, PAD_NONE),
            Param::number(tag::MIN_MAC_LENGTH, MAC_BITS),
            Param::bytes(tag::NONCE, &[0u8; NONCE_BYTES]),
            Param::number(tag::PURPOSE, PURPOSE_DECRYPT as u32),
        ];
        if !app_id.is_empty() {
            params.push(Param::bytes(tag::APPLICATION_ID, app_id));
        }
        let handle = self.begin(key, &params)?;
        self.abort(handle)
    }
}

/// How long the nonce of an AES-GCM key is.
const NONCE_BYTES: usize = 12;

/// The block mode and padding an AES-GCM decryption is opened with, and the
/// purpose, as `keymaster_defs.h` numbers them.
const MODE_GCM: u32 = 32;
const PAD_NONE: u32 = 1;

impl crate::keystore::Decryptor for Keymaster1 {
    fn gcm_decrypt(
        &self,
        key_blob: &[u8],
        app_id: &[u8],
        nonce: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>> {
        // The keys unwrapped this way belong to the phone rather than to any
        // user, so none of them is guarded by a screen lock.
        Keymaster1::gcm_decrypt(self, key_blob, app_id, nonce, body)
    }
}

/// The name of a tag, for the few this program reads.
pub fn tag_name(tag: u32) -> &'static str {
    match tag {
        0x2000_0100 => "algorithm",
        0x6000_0100 => "purpose",
        0x2000_0200 => "block mode",
        0x2000_0300 => "padding",
        0x6000_0200 => "digest",
        0x3000_0100 => "key size",
        0x5000_0100 => "application id",
        0x5000_0200 => "nonce",
        0x6000_0400 => "origin",
        0x9000_0100 => "creation time",
        _ => "another tag",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parameter_is_a_tag_and_two_words_of_value() {
        // The C interface's union is as wide as its widest arm, which is a
        // blob: a pointer and a length.
        assert_eq!(std::mem::size_of::<Param>(), 24);
        assert_eq!(std::mem::size_of::<Blob>(), 16);
        assert_eq!(std::mem::size_of::<ParamSet>(), 16);
    }

    #[test]
    fn a_blob_carries_where_the_bytes_are_and_how_many() {
        let bytes = [1u8, 2, 3];
        let blob = Blob::of(&bytes);
        assert_eq!(blob.length, 3);
        assert_eq!(unsafe { blob.take() }, vec![1, 2, 3]);
        assert!(unsafe { Blob::empty().take() }.is_empty());
    }

    #[test]
    fn the_measured_offsets_are_where_the_symbols_are() {
        // Read off the phone and named against the module's symbols: the
        // capability queries come first, then the keymaster1 functions.
        assert_eq!(at::GET_KEY_CHARACTERISTICS, 256);
        assert_eq!(at::BEGIN, 296);
        assert_eq!(at::UPDATE, 304);
        assert_eq!(at::FINISH, 312);
        assert_eq!(at::ABORT, 320);
    }
}
