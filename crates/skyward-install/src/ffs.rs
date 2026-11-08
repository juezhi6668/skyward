//! The adb function over USB through FunctionFS, set up the way the
//! recovery's own adbd sets it up, and moving the phone's USB between what
//! it offers at rest and sideload with the init rules the recovery ramdisk
//! has.

use crate::adb::Link;
use anyhow::{bail, ensure, Context, Result};
use skyward_sys::set_prop;
use skyward_sys::usb::{resting, set};
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

const EP0: &str = "/dev/usb-ffs/adb/ep0";
/// Bulk out, computer to phone.
const EP_OUT: &str = "/dev/usb-ffs/adb/ep1";
/// Bulk in, phone to computer.
const EP_IN: &str = "/dev/usb-ffs/adb/ep2";

/// How long init gets to carry out a change of USB configuration.
const SWITCH: Duration = Duration::from_secs(10);

// From linux/usb/functionfs.h and linux/usb/ch9.h.
const DESCRIPTORS_MAGIC_V2: u32 = 3;
const STRINGS_MAGIC: u32 = 2;
const HAS_FS_DESC: u32 = 1;
const HAS_HS_DESC: u32 = 2;
const HAS_SS_DESC: u32 = 4;
const HAS_MS_OS_DESC: u32 = 8;
const DT_INTERFACE: u8 = 4;
const DT_ENDPOINT: u8 = 5;
const DT_SS_ENDPOINT_COMP: u8 = 0x30;
const DIR_IN: u8 = 0x80;
const XFER_BULK: u8 = 2;

const ADB_CLASS: u8 = 0xff;
const ADB_SUBCLASS: u8 = 0x42;
const ADB_PROTOCOL: u8 = 1;

const BIND: u8 = 0;
const UNBIND: u8 = 1;
const ENABLE: u8 = 2;
const DISABLE: u8 = 3;
const SETUP: u8 = 4;
const SUSPEND: u8 = 5;
const RESUME: u8 = 6;

#[derive(IntoBytes, Immutable)]
#[repr(C)]
struct InterfaceDesc {
    length: u8,
    descriptor_type: u8,
    interface_number: u8,
    alternate_setting: u8,
    num_endpoints: u8,
    interface_class: u8,
    interface_subclass: u8,
    interface_protocol: u8,
    interface: u8,
}

#[derive(IntoBytes, Immutable)]
#[repr(C)]
struct EndpointDesc {
    length: u8,
    descriptor_type: u8,
    endpoint_address: u8,
    attributes: u8,
    max_packet_size: U16,
    interval: u8,
}

#[derive(IntoBytes, Immutable)]
#[repr(C)]
struct SsCompanionDesc {
    length: u8,
    descriptor_type: u8,
    max_burst: u8,
    attributes: u8,
    bytes_per_interval: U16,
}

#[derive(IntoBytes, Immutable)]
#[repr(C)]
struct Function {
    interface: InterfaceDesc,
    source: EndpointDesc,
    sink: EndpointDesc,
}

#[derive(IntoBytes, Immutable)]
#[repr(C)]
struct SsFunction {
    interface: InterfaceDesc,
    source: EndpointDesc,
    source_comp: SsCompanionDesc,
    sink: EndpointDesc,
    sink_comp: SsCompanionDesc,
}

/// usb_os_desc_header; `count` is bCount and its reserved byte, or wCount.
#[derive(IntoBytes, Immutable)]
#[repr(C)]
struct OsDescHeader {
    interface: u8,
    length: U32,
    bcd_version: U16,
    index: U16,
    count: U16,
}

#[derive(IntoBytes, Immutable)]
#[repr(C)]
struct ExtCompatDesc {
    first_interface_number: u8,
    reserved1: u8,
    compatible_id: [u8; 8],
    sub_compatible_id: [u8; 8],
    reserved2: [u8; 6],
}

/// The DeviceInterfaceGUID property Windows finds adb's driver by. The
/// kernel takes the name and value in ASCII and widens them itself.
#[derive(IntoBytes, Immutable)]
#[repr(C)]
struct ExtPropDesc {
    size: U32,
    data_type: U32,
    name_length: U16,
    name: [u8; 20],
    data_length: U32,
    data: [u8; 39],
}

#[derive(IntoBytes, Immutable)]
#[repr(C)]
struct Descriptors {
    magic: U32,
    length: U32,
    flags: U32,
    fs_count: U32,
    hs_count: U32,
    ss_count: U32,
    os_count: U32,
    fs: Function,
    hs: Function,
    ss: SsFunction,
    compat_header: OsDescHeader,
    compat: ExtCompatDesc,
    prop_header: OsDescHeader,
    prop: ExtPropDesc,
}

#[derive(IntoBytes, Immutable)]
#[repr(C)]
struct Strings {
    magic: U32,
    length: U32,
    str_count: U32,
    lang_count: U32,
    lang: U16,
    interface: [u8; 14],
}

/// usb_functionfs_event: the setup packet, then the event's type.
#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C)]
struct Event {
    request_type: u8,
    request: u8,
    value: U16,
    index: U16,
    length: U16,
    kind: u8,
    pad: [u8; 3],
}

// The sizes the kernel's own definitions come to.
const _: () = assert!(size_of::<Descriptors>() == 228);
const _: () = assert!(size_of::<Strings>() == 32);
const _: () = assert!(size_of::<Event>() == 12);

fn interface() -> InterfaceDesc {
    InterfaceDesc {
        length: 9,
        descriptor_type: DT_INTERFACE,
        interface_number: 0,
        alternate_setting: 0,
        num_endpoints: 2,
        interface_class: ADB_CLASS,
        interface_subclass: ADB_SUBCLASS,
        interface_protocol: ADB_PROTOCOL,
        interface: 1,
    }
}

fn endpoint(address: u8, max_packet_size: u16) -> EndpointDesc {
    EndpointDesc {
        length: 7,
        descriptor_type: DT_ENDPOINT,
        endpoint_address: address,
        attributes: XFER_BULK,
        max_packet_size: U16::new(max_packet_size),
        interval: 0,
    }
}

fn function(max_packet_size: u16) -> Function {
    Function {
        interface: interface(),
        source: endpoint(1, max_packet_size),
        sink: endpoint(2 | DIR_IN, max_packet_size),
    }
}

fn companion() -> SsCompanionDesc {
    SsCompanionDesc {
        length: 6,
        descriptor_type: DT_SS_ENDPOINT_COMP,
        max_burst: 4,
        attributes: 0,
        bytes_per_interval: U16::new(0),
    }
}

fn descriptors() -> Descriptors {
    let mut name = [0u8; 20];
    name[..19].copy_from_slice(b"DeviceInterfaceGUID");
    let mut data = [0u8; 39];
    data[..38].copy_from_slice(b"{F72FE0D4-CBCB-407D-8814-9ED673D0DD6B}");
    let prop = ExtPropDesc {
        size: U32::new(size_of::<ExtPropDesc>() as u32),
        data_type: U32::new(1),
        name_length: U16::new(20),
        name,
        data_length: U32::new(39),
        data,
    };
    Descriptors {
        magic: U32::new(DESCRIPTORS_MAGIC_V2),
        length: U32::new(size_of::<Descriptors>() as u32),
        flags: U32::new(HAS_FS_DESC | HAS_HS_DESC | HAS_SS_DESC | HAS_MS_OS_DESC),
        fs_count: U32::new(3),
        hs_count: U32::new(3),
        ss_count: U32::new(5),
        os_count: U32::new(2),
        fs: function(64),
        hs: function(512),
        ss: SsFunction {
            interface: interface(),
            source: endpoint(1, 1024),
            source_comp: companion(),
            sink: endpoint(2 | DIR_IN, 1024),
            sink_comp: companion(),
        },
        compat_header: OsDescHeader {
            interface: 0,
            length: U32::new((size_of::<OsDescHeader>() + size_of::<ExtCompatDesc>()) as u32),
            bcd_version: U16::new(1),
            index: U16::new(4),
            count: U16::new(1),
        },
        compat: ExtCompatDesc {
            first_interface_number: 0,
            reserved1: 1,
            compatible_id: *b"WINUSB\0\0",
            sub_compatible_id: [0; 8],
            reserved2: [0; 6],
        },
        prop_header: OsDescHeader {
            interface: 0,
            length: U32::new((size_of::<OsDescHeader>() + size_of::<ExtPropDesc>()) as u32),
            bcd_version: U16::new(1),
            index: U16::new(5),
            count: U16::new(1),
        },
        prop,
    }
}

fn strings() -> Strings {
    Strings {
        magic: U32::new(STRINGS_MAGIC),
        length: U32::new(size_of::<Strings>() as u32),
        str_count: U32::new(1),
        lang_count: U32::new(1),
        lang: U16::new(0x0409),
        interface: *b"ADB Interface\0",
    }
}

/// What the endpoints' users and the control thread share.
#[derive(Default)]
pub struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Default)]
struct State {
    /// The computer has configured the function, so the endpoints work.
    enabled: bool,
    /// The installer waits for the computer to start sending, which may
    /// take as long as the person takes.
    accepting: bool,
    cancelled: bool,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("the USB state lock is never poisoned")
    }

    fn set(&self, f: impl FnOnce(&mut State)) {
        f(&mut self.lock());
        self.changed.notify_all();
    }

    /// Whether the installer waits for the computer to start sending.
    pub fn accepting(&self, on: bool) {
        self.set(|s| s.accepting = on);
    }

    /// Stop waiting for the computer; whether it was being waited for.
    pub fn cancel(&self) -> bool {
        let mut accepting = false;
        self.set(|s| {
            s.cancelled = true;
            accepting = s.accepting;
        });
        accepting
    }

    pub fn cancelled(&self) -> bool {
        self.lock().cancelled
    }

    /// Wait until the function is configured. While the installer waits
    /// for the computer, that may take long, and cancelling ends it; once
    /// a transfer runs, the function going away means the cable came out.
    fn ready(&self) -> io::Result<()> {
        let mut s = self.lock();
        loop {
            if s.accepting && s.cancelled {
                return Err(io::Error::from(ErrorKind::Interrupted));
            }
            if s.enabled {
                return Ok(());
            }
            if !s.accepting {
                return Err(io::Error::from(ErrorKind::ConnectionAborted));
            }
            s = self
                .changed
                .wait(s)
                .expect("the USB state lock is never poisoned");
        }
    }

    /// The function went away before the control thread heard of it: give
    /// it a moment to.
    fn settle(&self) {
        let _ = self
            .changed
            .wait_timeout(self.lock(), Duration::from_millis(10));
    }
}

/// The bulk endpoints, which the adb connection runs over. Both are
/// non-blocking, so using one while the function is not configured fails
/// at once instead of sleeping in the kernel, out of reach of cancelling.
pub struct Endpoints {
    out: File,
    inn: File,
    shared: Arc<Shared>,
}

/// The cable came out while a transfer waited.
fn aborted(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ESHUTDOWN)
}

impl Link for Endpoints {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            self.shared.ready()?;
            match (&self.out).read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == ErrorKind::WouldBlock => self.shared.settle(),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) if aborted(&e) => return Err(io::Error::from(ErrorKind::ConnectionAborted)),
                Err(e) => return Err(e),
            }
        }
    }

    fn write(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            self.shared.ready()?;
            match (&self.inn).write(data) {
                Ok(n) => data = &data[n..],
                Err(e) if e.kind() == ErrorKind::WouldBlock => self.shared.settle(),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) if aborted(&e) => return Err(io::Error::from(ErrorKind::ConnectionAborted)),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// The function's control side: the thread that holds ep0 and answers the
/// computer's control requests there.
pub struct Usb {
    stop: Option<OwnedFd>,
    control: Option<JoinHandle<Result<()>>>,
}

impl Usb {
    /// Take USB over from adbd and offer the adb function for sideload;
    /// `shared` is how the endpoints' users are told to stop waiting. If
    /// that fails, the port goes back to what it offers at rest before the
    /// error is returned.
    pub fn open(shared: Arc<Shared>) -> Result<(Usb, Endpoints)> {
        set("none", SWITCH)?;
        Usb::take(shared).or_else(|e| {
            set(resting(), SWITCH).with_context(|| format!("after {e:#}"))?;
            Err(e)
        })
    }

    fn take(shared: Arc<Shared>) -> Result<(Usb, Endpoints)> {
        let ep0 = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(EP0)
            .context("open ep0")?;
        (&ep0)
            .write_all(descriptors().as_bytes())
            .context("write the USB descriptors")?;
        (&ep0)
            .write_all(strings().as_bytes())
            .context("write the USB strings")?;
        let out = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(EP_OUT)
            .context("open the bulk out endpoint")?;
        let inn = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(EP_IN)
            .context("open the bulk in endpoint")?;

        let mut pipe = [0; 2];
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error()).context("make the control thread's stop pipe");
        }
        let (stop_read, stop) =
            unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
        let answering = shared.clone();
        let control = thread::Builder::new()
            .name("sideload-usb".into())
            .spawn(move || answer(&ep0, &stop_read, &answering))
            .context("start the USB control thread")?;
        let usb = Usb {
            stop: Some(stop),
            control: Some(control),
        };

        set_prop("sys.usb.ffs.ready", "1")?;
        set("sideload", SWITCH)?;
        Ok((usb, Endpoints { out, inn, shared }))
    }

    /// Hand USB back to what it offers at rest. Every endpoint closes
    /// first, so adbd finds the function free; the port is back before any
    /// error from the control thread is returned.
    pub fn close(mut self, endpoints: Endpoints) -> Result<()> {
        set("none", SWITCH)?;
        drop(endpoints);
        let answered = self.stop_control();
        drop(self);
        set(resting(), SWITCH)?;
        answered
    }

    /// Closing the pipe's write end stops the control thread.
    fn stop_control(&mut self) -> Result<()> {
        drop(self.stop.take());
        match self.control.take() {
            Some(control) => control
                .join()
                .expect("the USB control thread does not panic"),
            None => Ok(()),
        }
    }
}

impl Drop for Usb {
    fn drop(&mut self) {
        let _ = self.stop_control();
    }
}

/// Answer the computer's control requests on ep0 and follow whether the
/// function is configured, until the stop pipe closes.
fn answer(ep0: &File, stop: &OwnedFd, shared: &Shared) -> Result<()> {
    let mut event = [0u8; size_of::<Event>()];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: ep0.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stop.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e).context("wait for USB control events");
        }
        if fds[1].revents != 0 {
            return Ok(());
        }
        if fds[0].revents & libc::POLLIN == 0 {
            bail!("ep0 reported {:#x}", fds[0].revents);
        }
        let n = { ep0 }
            .read(&mut event)
            .context("read a USB control event")?;
        ensure!(n == event.len(), "a USB control event of {n} bytes");
        let ev = Event::read_from_bytes(&event).expect("the buffer is one event");
        match ev.kind {
            ENABLE => shared.set(|s| s.enabled = true),
            DISABLE | UNBIND => shared.set(|s| s.enabled = false),
            SETUP if ev.request_type & DIR_IN != 0 => {
                // Nothing to send: an empty answer acknowledges it.
                { ep0 }
                    .write(&[])
                    .context("acknowledge a control request")?;
            }
            SETUP => {
                let mut data = vec![0u8; usize::from(ev.length.get())];
                { ep0 }
                    .read_exact(&mut data)
                    .context("read a control request's data")?;
            }
            BIND | SUSPEND | RESUME => {}
            other => bail!("unknown USB control event {other}"),
        }
    }
}
