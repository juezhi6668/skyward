//! Backing up and restoring on a thread of its own, telling the screen how
//! far it has come.

use anyhow::{ensure, Context, Result};
use skyward_backup::archive::{self, Skipped};
use skyward_backup::store::{self, Reader, Stored, Writer};
use skyward_backup::{Item, Manifest, Part, FORMAT};
use skyward_block::{fstab, mount, BY_NAME};
use skyward_files::{Cancelled, Ownership};
use skyward_vab::{Slot, SnapshotState};
use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// The most often how far the work has come is told.
const PROGRESS_EVERY: Duration = Duration::from_millis(100);

/// How much is read or written at a time between two checks of whether
/// the work is to stop.
const CHUNK: usize = 4 << 20;

/// The data partition, and the reference of the key its own folders are
/// encrypted with: one made afresh has another.
const DATA: &str = "/data";
const DATA_KEY: &str = "/data/unencrypted/ref";

/// What the data partition's archive takes for each entry beyond what a
/// file holds: its headers, and the end of its last block.
const ENTRY_BYTES: u64 = 2048;

/// The slot's partitions that start the phone and check what it starts, in
/// the order a backup takes them: those the phone has.
const BOOT: [&str; 8] = [
    "boot",
    "init_boot",
    "vendor_boot",
    "dtbo",
    "vbmeta",
    "vbmeta_system",
    "vbmeta_vendor",
    "recovery",
];

/// The order a restore writes the parts in: what starts the phone and what
/// it starts, then the baseband's, then the data partition's files, which
/// take longest.
const RESTORE_ORDER: [Part; 4] = [Part::Boot, Part::System, Part::Efs, Part::Data];

/// What a backup of the data partition leaves out on every phone, and a
/// restore leaves as it is: internal storage, which is the user's own; the
/// keys the partition opens with, and what the lock screen and the key
/// service bind to the secure world, which an older copy would not open;
/// what the system makes again, its caches, compiled code and the updates
/// it downloaded; and the second system, which lies where /metadata keeps
/// it.
const DATA_SKIPPED: [&str; 21] = [
    "media",
    "lost+found",
    "per_boot",
    "unencrypted",
    "misc/vold",
    "misc/keystore",
    "misc/gatekeeper",
    "system/locksettings.db",
    "system/locksettings.db-wal",
    "system/locksettings.db-shm",
    "system/locksettings.db-journal",
    "system_de/*/spblob",
    "vendor_de/*/fpdata",
    "dalvik-cache",
    "resource-cache",
    "system/package_cache",
    "misc/apexdata/com.android.art/dalvik-cache",
    "cache",
    "ota",
    "ota_package",
    "skyward/systems",
];

/// What of the data partition backups leave out on this phone: what every
/// phone's do, and what the phone's own secure world keeps in step.
pub fn data_skipped(phone: &[String]) -> Vec<String> {
    DATA_SKIPPED
        .iter()
        .map(|s| s.to_string())
        .chain(phone.iter().cloned())
        .collect()
}

pub struct BackupTask {
    /// Which of the partitions [`choices`] offers to take, by name; `data`
    /// is the data partition's files.
    pub chosen: Vec<String>,
    /// The names the phone's configuration offers, which decide the list
    /// where it gives one.
    pub offered: Vec<String>,
    /// The folder of backups at the place chosen; this one goes into a
    /// folder of its own there, called `stamp`.
    pub into: PathBuf,
    pub stamp: String,
    pub ownership: Ownership,
    pub compress: bool,
    pub verify: bool,
    /// The mount the place is, when it is shown read-only and so is made
    /// writable for the backup, and read-only again after: a USB drive.
    pub remount: Option<PathBuf>,
    /// When the backup is made, in Unix seconds, the phone by its
    /// codename, and the system it runs, by its version.
    pub made: i64,
    pub device: String,
    pub system: Option<String>,
    /// The phone's partitions of the baseband's settings and the sensors'
    /// calibration, and what of the data partition it leaves out.
    pub efs: Vec<String>,
    pub skipped: Vec<String>,
}

pub struct RestoreTask {
    pub folder: PathBuf,
    /// Which of the names the backup's own manifest holds to put back.
    pub chosen: Vec<String>,
    pub device: String,
    pub skipped: Vec<String>,
    /// What has to happen before the slot's partitions in super are written
    /// over, as before an update.
    pub detach: skyward_install::Detach,
}

pub enum Task {
    Backup(BackupTask),
    Restore(RestoreTask),
}

/// Why backing up or restoring does not start.
#[derive(Debug)]
pub enum Refusal {
    /// Too little room where the backup goes: the bytes it takes, and the
    /// bytes free.
    Room { needed: u64, free: u64 },
    /// An update is in flight, and the slot's partitions in super are its
    /// to change.
    Update(SnapshotState),
    /// The backup was made on this other phone.
    OtherPhone(String),
    /// This partition in super is not the size it was backed up at.
    Resized(String),
    /// The data partition has been made afresh since the backup.
    DataReset,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Room { needed, free } => {
                write!(f, "the backup takes {needed} bytes, and {free} are free")
            }
            Refusal::Update(state) => write!(f, "an update is in flight ({state:?})"),
            Refusal::OtherPhone(device) => write!(f, "the backup was made on {device}"),
            Refusal::Resized(name) => write!(f, "{name} is not the size it was backed up at"),
            Refusal::DataReset => write!(
                f,
                "the data partition has been made afresh since the backup"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

pub enum Event {
    /// The parts the work goes through, each by name with its bytes; told
    /// once they are known, as measuring the data partition's files takes
    /// a while.
    Plan(Vec<(String, u64)>),
    /// The part under way, the bytes of it done of how many in this pass
    /// over it, and whether this is the pass that checks a backup against
    /// what it recorded.
    At {
        item: usize,
        done: u64,
        of: u64,
        checking: bool,
    },
    Ended(End),
}

pub enum End {
    /// A backup made, in this folder.
    Saved(PathBuf),
    /// A backup restored, but for the folders a key of their own began in
    /// that are gone, which only the system makes, with what the backup
    /// held in them.
    Restored {
        unmade: Vec<PathBuf>,
    },
    /// Stopped as asked, with nothing of the backup left, or nothing of
    /// the restore written.
    Stopped,
    Refused(Refusal),
    Failed(String),
}

pub struct Worker {
    events: Receiver<Event>,
    /// Readable while events wait.
    wake: OwnedFd,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn start(task: Task) -> Result<Worker> {
        let mut fds = [0; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error()).context("make the backup worker's wake pipe");
        }
        let (wake, signal) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let (tx, events) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = cancel.clone();
        let thread = thread::Builder::new()
            .name("backup".into())
            .spawn(move || {
                let tell = |event: Event| {
                    // The screen only stops listening once it has let the
                    // worker go.
                    let _ = tx.send(event);
                    unsafe { libc::write(signal.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
                };
                let ended = match task {
                    Task::Backup(t) => backup(t, &tell, &stop).map(End::Saved),
                    Task::Restore(t) => {
                        restore(t, &tell, &stop).map(|unmade| End::Restored { unmade })
                    }
                };
                let end = match ended {
                    Ok(end) => end,
                    Err(e) if e.is::<Cancelled>() => End::Stopped,
                    Err(e) => match e.downcast::<Refusal>() {
                        Ok(refusal) => End::Refused(refusal),
                        Err(e) => End::Failed(format!("{e:#}")),
                    },
                };
                let said = match &end {
                    End::Saved(folder) => format!("backup saved in {}", folder.display()),
                    End::Restored { unmade } => format!("backup restored, all but {unmade:?}"),
                    End::Stopped => "backup stopped".into(),
                    End::Refused(why) => format!("backup refused: {why}"),
                    End::Failed(why) => format!("backup failed: {why}"),
                };
                skyward_sys::kmsg(&said).expect("the kernel log takes a line");
                tell(Event::Ended(end));
            })
            .context("start the backup worker")?;
        Ok(Worker {
            events,
            wake,
            cancel,
            thread: Some(thread),
        })
    }

    pub fn fd(&self) -> RawFd {
        self.wake.as_raw_fd()
    }

    /// The events since the last call.
    pub fn events(&self) -> Vec<Event> {
        let mut drain = [0u8; 64];
        while unsafe {
            libc::read(
                self.wake.as_raw_fd(),
                drain.as_mut_ptr().cast(),
                drain.len(),
            )
        } > 0
        {}
        self.events.try_iter().collect()
    }

    /// Ask the work to stop; it does between two chunks, and a restore
    /// only while nothing is written yet.
    pub fn stop(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl Drop for Worker {
    /// The screen lets the worker go once its work has ended.
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the backup worker does not panic");
        }
    }
}

/// Where a part comes from for a backup.
#[derive(Debug, Clone)]
pub(crate) enum Source {
    /// A partition of its own, at this device.
    Block(PathBuf),
    /// One of the slot's partitions in super, by its base name.
    Logical(String),
    /// The data partition's files.
    Data,
}

/// A partition by its name among the links the phone gives them.
fn partition(name: &str) -> PathBuf {
    Path::new(BY_NAME).join(name)
}

/// How a phone names and reaches the partitions it keeps whole. Where it has
/// a set of each, those carry the booted slot's suffix and its system lives
/// in logical partitions of one `super`, read and written through a mapping
/// made for the job; where it has one set, the names are bare and every
/// partition is one image of the device itself.
struct Phone {
    suffix: String,
    slot: Option<Slot>,
}

impl Phone {
    fn now() -> Result<Phone> {
        Ok(match skyward_vab::current_slot()? {
            Some(slot) => Phone {
                suffix: slot.suffix().to_string(),
                slot: Some(slot),
            },
            None => Phone {
                suffix: String::new(),
                slot: None,
            },
        })
    }

    /// The partition `base` as this phone names it.
    fn device(&self, base: &str) -> PathBuf {
        partition(&format!("{base}{}", self.suffix))
    }

    /// Every partition this phone keeps its system in: the slot's logical
    /// ones that hold something, and where there is no super, every
    /// filesystem the phone's own table mounts — the data partition aside,
    /// which is kept as its files rather than as an image of the whole.
    fn system(&self) -> Result<Vec<(String, Source, u64)>> {
        match self.slot {
            Some(slot) => Ok(skyward_vab::slot_sizes(slot)?
                .into_iter()
                .filter(|(_, size)| *size > 0)
                .map(|(base, size)| (base.clone(), Source::Logical(base), size))
                .collect()),
            None => {
                let mut out = Vec::new();
                for one in fstab::mountable()? {
                    if one.point == DATA || one.name == "userdata" {
                        continue;
                    }
                    // A table may name a partition this phone does not have:
                    // the Mi MIX 2's names a card reader with no card in it
                    // (/dev/block/mmcblk0p1), and this phone's bootloader
                    // path need not be a recovery's. What is not there cannot
                    // be backed up, and one absent partition is not a reason
                    // for the whole page to say nothing — this runs before
                    // the first frame, so it used to be a reason for the
                    // recovery not to start at all.
                    let Ok(device) = fstab::device(&one.ways[0]) else {
                        continue;
                    };
                    let device = PathBuf::from(device);
                    let Ok(size) = skyward_block::size_bytes(&device) else {
                        continue;
                    };
                    out.push((one.name.clone(), Source::Block(device.clone()), size));
                }
                Ok(out)
            }
        }
    }

    /// How large each of those is by its base name, which is what a restore
    /// compares the bytes a backup stored against.
    fn system_sizes(&self) -> Result<Vec<(String, u64)>> {
        Ok(self
            .system()?
            .into_iter()
            .map(|(base, _, size)| (base, size))
            .collect())
    }

    /// Whether an update in flight could be changing these partitions at all.
    fn has_super(&self) -> bool {
        self.slot.is_some()
    }
}

/// The partitions a phone with one set of them keeps its system across: the
/// table's own mount points, deepest place first, so a folder is not taken
/// away from under what is mounted in it.
pub fn system_points() -> Result<Vec<String>> {
    let mut points: Vec<String> = fstab::mountable()?
        .into_iter()
        .map(|one| one.point)
        .filter(|point| point != DATA)
        .collect();
    let places = |p: &str| p.chars().filter(|c| *c == '/').count();
    points.sort_by_key(|p| std::cmp::Reverse(places(p)));
    Ok(points)
}

/// Tells how far a part has come in a pass over it, at most every
/// [`PROGRESS_EVERY`].
struct Telling<'a> {
    tell: &'a dyn Fn(Event),
    item: usize,
    of: u64,
    checking: bool,
    told: Instant,
}

impl Telling<'_> {
    fn new(tell: &dyn Fn(Event), item: usize, of: u64, checking: bool) -> Telling<'_> {
        tell(Event::At {
            item,
            done: 0,
            of,
            checking,
        });
        Telling {
            tell,
            item,
            of,
            checking,
            told: Instant::now(),
        }
    }

    fn done(&mut self, done: u64) {
        if self.told.elapsed() >= PROGRESS_EVERY {
            self.told = Instant::now();
            (self.tell)(Event::At {
                item: self.item,
                done,
                of: self.of,
                checking: self.checking,
            });
        }
    }
}

/// Copy `len` bytes from `from` to `to`, telling how far, and stopping when
/// asked.
fn copy(
    from: &mut impl Read,
    to: &mut impl Write,
    len: u64,
    cancel: &AtomicBool,
    telling: &mut Telling,
) -> Result<()> {
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;
    while done < len {
        if cancel.load(Ordering::Relaxed) {
            return Err(Cancelled.into());
        }
        let want = (len - done).min(CHUNK as u64) as usize;
        from.read_exact(&mut buf[..want]).context("read")?;
        to.write_all(&buf[..want]).context("write")?;
        done += want as u64;
        telling.done(done);
    }
    Ok(())
}

/// The reference of the key the data partition's own folders are encrypted
/// with, in hex.
fn data_key() -> Result<String> {
    let bytes = fs::read(DATA_KEY).with_context(|| format!("read {DATA_KEY}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The bytes free where `path` is, or would be made.
fn free_bytes(path: &Path) -> Result<u64> {
    let there = path
        .ancestors()
        .find(|p| p.exists())
        .context("the root is always there")?;
    let c = std::ffi::CString::new(there.as_os_str().as_bytes())
        .with_context(|| format!("{} holds a NUL", there.display()))?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("look at the room on {}", there.display()));
    }
    Ok(st.f_bavail as u64 * st.f_frsize as u64)
}

/// The slot's partitions in super are read or written whole only while no
/// update is changing them. A phone with one set of partitions has no
/// snapshot to be in flight and no `super` to change, and its state cannot
/// be read at all where `/metadata` is not mounted: that is not a reason to
/// One thing a backup can take on this phone: the name the page ticks, the
/// kind of item it makes, where it is read from or mounted as the page says,
/// how it is read, and how large it is. Which these are is the phone's own
/// affair. A configuration that names the partitions says so; otherwise the
/// partitions the phone's own table mounts and the ones that start the
/// phone, where they exist on this board, say it.
#[derive(Debug, Clone)]
pub struct Choice {
    /// The partition's name, or `data` for the data partition's files.
    pub name: String,
    pub part: Part,
    /// Where it is read from or mounted, which the page says under the name.
    pub hint: String,
    pub source: Source,
    pub size: u64,
}

/// Everything a backup can take here, in the order to offer it: what starts
/// the phone, then what the phone runs, then its files, then the baseband's
/// settings. A configuration that names the partitions is followed, since
/// which of them a person should be asked about at all is the phone's
/// affair, and a name that is not a partition here is left out rather than
/// offered with nothing behind it.
pub fn choices(efs: &[String], named: &[String]) -> Result<Vec<Choice>> {
    let phone = Phone::now()?;
    let whole = phone.system()?;
    let boot: Vec<String> = BOOT
        .iter()
        .map(|name| name.to_string())
        .filter(|name| phone.device(name).exists())
        .collect();
    let order: Vec<String> = match named.is_empty() {
        true => boot
            .iter()
            .chain(whole.iter().map(|(base, _, _)| base))
            .chain(std::iter::once(&"data".to_string()))
            .chain(efs.iter())
            .cloned()
            .collect(),
        false => named.to_vec(),
    };
    let table = skyward_block::fstab::mountable()?;
    let mut out = Vec::new();
    for name in order {
        let (part, source, size, hint) = match name.as_str() {
            "data" => (Part::Data, Source::Data, 0, DATA.to_string()),
            _ if boot.contains(&name) => {
                let device = phone.device(&name);
                let size = skyward_block::size_bytes(&device)?;
                (
                    Part::Boot,
                    Source::Block(device.clone()),
                    size,
                    device.display().to_string(),
                )
            }
            _ if efs.contains(&name) => {
                let device = partition(&name);
                if !device.exists() {
                    continue;
                }
                let size = skyward_block::size_bytes(&device)?;
                (
                    Part::Efs,
                    Source::Block(device.clone()),
                    size,
                    device.display().to_string(),
                )
            }
            _ => match whole.iter().find(|(base, _, _)| *base == name) {
                Some((_, source, size)) => {
                    let hint = match table.iter().find(|one| one.name == name) {
                        Some(one) => one.point.clone(),
                        None => phone.device(&name).display().to_string(),
                    };
                    (Part::System, source.clone(), *size, hint)
                }
                None => continue,
            },
        };
        out.push(Choice {
            name,
            part,
            hint,
            source,
            size,
        });
    }
    Ok(out)
}

/// refuse an image of a partition it owns outright.
fn no_update(has_super: bool) -> Result<()> {
    if !has_super {
        return Ok(());
    }
    let state = skyward_vab::snapshot_state()?;
    if state != SnapshotState::None {
        return Err(Refusal::Update(state).into());
    }
    Ok(())
}

fn backup(t: BackupTask, tell: &dyn Fn(Event), cancel: &AtomicBool) -> Result<PathBuf> {
    let phone = Phone::now()?;
    let all = choices(&t.efs, &t.offered)?;
    let picked: Vec<&Choice> = all.iter().filter(|c| t.chosen.contains(&c.name)).collect();
    ensure!(
        !picked.is_empty(),
        "none of what is chosen is a partition this phone can back up"
    );
    let system = picked.iter().any(|c| c.part == Part::System);
    if system {
        no_update(phone.has_super())?;
    }
    let skipped = Skipped::new(&t.skipped);
    // What the parts' files take uncompressed: the bytes each holds, and
    // the data partition's archive headers. A partition that holds nothing
    // has nothing to keep, and is left out as it is left out of the offer.
    let mut plan: Vec<(Part, String, Source, u64)> = Vec::new();
    let mut needed = 0;
    let boot = picked.iter().any(|c| c.part == Part::Boot);
    if boot {
        // The boot partitions are backed up as the installed system's,
        // whose boot set goes back into them first.
        skyward_systems::install::ensure_installed()?;
    }
    for c in &picked {
        match c.part {
            Part::Data => {
                let (bytes, entries) = archive::measure(Path::new(DATA), &skipped, cancel)
                    .context("measure the data partition's files")?;
                plan.push((Part::Data, c.name.clone(), Source::Data, bytes));
                needed += entries * ENTRY_BYTES;
            }
            Part::System if c.size == 0 => {}
            _ => plan.push((c.part, c.name.clone(), c.source.clone(), c.size)),
        }
    }
    // Whether the data partition's files are among the parts, as the
    // manifest keeps the key that opens them only when they are.
    let data = plan.iter().any(|(part, ..)| *part == Part::Data);
    // Compressed, what the files take is not known until they are written.
    needed += plan.iter().map(|p| p.3).sum::<u64>();
    let free = free_bytes(&t.into)?;
    if !t.compress && needed > free {
        return Err(Refusal::Room { needed, free }.into());
    }
    tell(Event::Plan(
        plan.iter()
            .map(|(_, name, _, size)| (name.clone(), *size))
            .collect(),
    ));
    if let Some(at) = &t.remount {
        mount::remount_writable(at, true)?;
    }
    let folder = t.into.join(&t.stamp);
    let made = (|| -> Result<()> {
        skyward_files::make_folders(&folder, t.ownership)?;
        let mut items = Vec::new();
        for (k, (part, name, source, size)) in plan.iter().enumerate() {
            let file = match (part, t.compress) {
                (Part::Data, false) => format!("{name}.tar"),
                (Part::Data, true) => format!("{name}.tar.lz4"),
                (_, false) => format!("{name}.img"),
                (_, true) => format!("{name}.img.lz4"),
            };
            let mut writer = Writer::create(&folder, &file, t.compress, t.ownership);
            let mut telling = Telling::new(tell, k, *size, false);
            match source {
                Source::Block(device) => {
                    let mut from =
                        File::open(device).with_context(|| format!("open {}", device.display()))?;
                    copy(&mut from, &mut writer, *size, cancel, &mut telling)
                        .with_context(|| format!("back up {name}"))?;
                }
                Source::Logical(base) => {
                    // A logical partition is only reached whole through a
                    // mapping, which is a thing a phone with one set of them
                    // does not have; the plan puts those in as their own
                    // devices, so this is the shape of a slot phone alone.
                    let Some(slot) = phone.slot else {
                        anyhow::bail!("{base} is a logical partition on a phone that has no super");
                    };
                    let whole = skyward_vab::map_whole(
                        slot,
                        base,
                        &format!("skyward-backup-{base}{}", phone.suffix),
                        true,
                    )?;
                    let copied = File::open(&whole.device)
                        .with_context(|| format!("open {}", whole.device.display()))
                        .and_then(|mut from| {
                            copy(&mut from, &mut writer, whole.size, cancel, &mut telling)
                        });
                    skyward_vab::unmap_whole(&whole)?;
                    copied.with_context(|| format!("back up {name}"))?;
                }
                Source::Data => {
                    archive::pack(
                        Path::new(DATA),
                        &skipped,
                        &mut writer,
                        cancel,
                        &mut |done| telling.done(done),
                    )
                    .context("back up the data partition's files")?;
                }
            }
            items.push(Item {
                part: *part,
                name: name.clone(),
                stored: writer.finish()?,
            });
        }
        if t.verify {
            for (k, item) in items.iter().enumerate() {
                let mut telling = Telling::new(tell, k, item.stored.size, true);
                check(&folder, &item.stored, cancel, &mut telling)
                    .with_context(|| format!("check {}", item.name))?;
            }
        }
        let data_key = if data { Some(data_key()?) } else { None };
        let manifest = Manifest {
            format: FORMAT,
            device: t.device.clone(),
            made: t.made,
            slot: phone.suffix.clone(),
            system: t.system.clone(),
            data_key,
            items,
        };
        manifest.write(&folder, t.ownership)?;
        unsafe { libc::sync() };
        Ok(())
    })();
    // A backup that did not finish is not left half made.
    let made = match made {
        Err(e) if folder.exists() => match fs::remove_dir_all(&folder) {
            Ok(()) => Err(e),
            Err(r) => Err(e.context(format!(
                "taking away {} afterwards failed too: {r}",
                folder.display()
            ))),
        },
        other => other,
    };
    if let Some(at) = &t.remount {
        let read_only = mount::remount_writable(at, false);
        made?;
        read_only?;
    } else {
        made?;
    }
    Ok(folder)
}

/// Read a part back from its files whole and see that it is what was
/// stored.
fn check(folder: &Path, stored: &Stored, cancel: &AtomicBool, telling: &mut Telling) -> Result<()> {
    let mut reader = Reader::open(folder, stored);
    copy(&mut reader, &mut io::sink(), stored.size, cancel, telling)?;
    let mut rest = Vec::new();
    reader.read_to_end(&mut rest).context("read")?;
    ensure!(rest.is_empty(), "the backup holds more than was stored");
    reader.check(stored)
}

/// A reader that counts the bytes it gives, where the count can be read
/// while the reader is lent out.
struct Counted<'a, R> {
    inner: R,
    read: &'a Cell<u64>,
}

impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read.set(self.read.get() + n as u64);
        Ok(n)
    }
}

fn restore(t: RestoreTask, tell: &dyn Fn(Event), cancel: &AtomicBool) -> Result<Vec<PathBuf>> {
    let manifest = Manifest::read(&t.folder)?;
    if manifest.device != t.device {
        return Err(Refusal::OtherPhone(manifest.device).into());
    }
    let phone = Phone::now()?;
    let mut items: Vec<&Item> = manifest
        .items
        .iter()
        .filter(|i| t.chosen.contains(&i.name))
        .collect();
    ensure!(
        !items.is_empty(),
        "nothing chosen to restore is in the backup"
    );
    items.sort_by_key(|i| RESTORE_ORDER.iter().position(|&p| p == i.part));
    // All that can be seen before anything is written.
    let system = items.iter().any(|i| i.part == Part::System);
    if system || items.iter().any(|i| i.part == Part::Boot) {
        no_update(phone.has_super())?;
    }
    let sizes = if system {
        phone.system_sizes()?
    } else {
        Vec::new()
    };
    for item in &items {
        match item.part {
            Part::Boot | Part::Efs => {
                let device = target(item, &phone);
                ensure!(
                    device.exists(),
                    "the phone has no partition {}",
                    device.display()
                );
                let size = skyward_block::size_bytes(&device)?;
                ensure!(
                    size == item.stored.size,
                    "{} holds {size} bytes, and its backup {}",
                    device.display(),
                    item.stored.size
                );
            }
            Part::System => {
                let size = sizes
                    .iter()
                    .find(|(base, _)| *base == item.name)
                    .map(|(_, size)| *size);
                if size != Some(item.stored.size) {
                    return Err(Refusal::Resized(item.name.clone()).into());
                }
            }
            Part::Data => {
                if manifest.data_key.as_deref() != Some(data_key()?.as_str()) {
                    return Err(Refusal::DataReset.into());
                }
            }
        }
    }
    tell(Event::Plan(
        items
            .iter()
            .map(|i| (i.name.clone(), i.stored.size))
            .collect(),
    ));
    // A damaged backup is not written anywhere.
    for (k, item) in items.iter().enumerate() {
        let mut telling = Telling::new(tell, k, item.stored.size, true);
        check(&t.folder, &item.stored, cancel, &mut telling)
            .with_context(|| format!("check {}", item.name))?;
    }
    for item in items
        .iter()
        .filter(|i| matches!(i.part, Part::Boot | Part::Efs))
    {
        let device = target(item, &phone);
        for point in mount::points_of(skyward_block::devnum(&device)?)? {
            mount::umount(&point).with_context(|| {
                format!("{} is in use at {}", device.display(), point.display())
            })?;
        }
    }
    if system && phone.slot.is_some() {
        // A phone with a super has every logical partition taken off the
        // running system at once, before anything is written. A phone with
        // one set of partitions comes off each one where it is mounted,
        // just before it is written, below — which leaves a partition this
        // backup does not hold mounted and undisturbed: the cache a log is
        // open on could not be taken off any other way.
        (t.detach)().context("take the system's partitions off before writing over them")?;
    }
    // The boot partitions are restored as the installed system's, whose
    // boot set goes back into them first, so that the second system's is
    // not left kept as being there.
    if items.iter().any(|i| i.part == Part::Boot) {
        skyward_systems::install::ensure_installed()?;
    }
    // Once anything is written, the restore goes on to its end.
    let go_on = AtomicBool::new(false);
    let skipped = Skipped::new(&t.skipped);
    let mut unmade = Vec::new();
    for (k, item) in items.iter().enumerate() {
        match item.part {
            Part::Boot | Part::Efs => {
                let mut telling = Telling::new(tell, k, item.stored.size * 2, false);
                write_image(&target(item, &phone), &t.folder, &item.stored, &mut telling)?;
            }
            Part::System => {
                let mut telling = Telling::new(tell, k, item.stored.size * 2, false);
                // Where the phone has a super, its logical partitions are only
                // reached whole through a mapping made for this; where it has
                // one set of partitions, the partition itself is written.
                let written = match phone.slot {
                    Some(slot) => {
                        let whole = skyward_vab::map_whole(
                            slot,
                            &item.name,
                            &format!("skyward-restore-{}{}", item.name, phone.suffix),
                            false,
                        )?;
                        let written =
                            write_image(&whole.device, &t.folder, &item.stored, &mut telling);
                        skyward_vab::unmap_whole(&whole)?;
                        written
                    }
                    None => {
                        let device = phone.device(&item.name);
                        for point in mount::points_of(skyward_block::devnum(&device)?)? {
                            mount::umount(&point).with_context(|| {
                                format!("{} is in use at {}", device.display(), point.display())
                            })?;
                        }
                        write_image(&device, &t.folder, &item.stored, &mut telling)
                    }
                };
                written?;
            }
            Part::Data => {
                let mut telling = Telling::new(tell, k, item.stored.size, false);
                let read = Cell::new(0);
                let mut reader = Reader::open(&t.folder, &item.stored);
                let from = Counted {
                    inner: &mut reader,
                    read: &read,
                };
                let unpacked =
                    archive::unpack(from, Path::new(DATA), &skipped, &go_on, &mut |_| {
                        telling.done(read.get())
                    })
                    .context("restore the data partition's files")?;
                io::copy(&mut reader, &mut io::sink()).context("read the rest of the backup")?;
                reader.check(&item.stored)?;
                unmade = unpacked
                    .unmade
                    .iter()
                    .map(|u| Path::new(DATA).join(u))
                    .collect();
            }
        }
        skyward_sys::kmsg(&format!("restored {}", item.name))?;
    }
    unsafe { libc::sync() };
    Ok(unmade)
}

/// The partition a part of a backup goes back to.
fn target(item: &Item, phone: &Phone) -> PathBuf {
    match item.part {
        Part::Efs => partition(&item.name),
        _ => phone.device(&item.name),
    }
}

/// Write a part's image to the partition at `device`, then read it back
/// from the storage and see that it holds what was stored: twice the
/// part's bytes, told as they go.
fn write_image(device: &Path, folder: &Path, stored: &Stored, telling: &mut Telling) -> Result<()> {
    let mut reader = Reader::open(folder, stored);
    let mut out = OpenOptions::new()
        .write(true)
        .open(device)
        .with_context(|| format!("open {}", device.display()))?;
    copy(
        &mut reader,
        &mut out,
        stored.size,
        &AtomicBool::new(false),
        telling,
    )
    .with_context(|| format!("write {}", device.display()))?;
    reader.check(stored)?;
    out.sync_all()
        .with_context(|| format!("write {}", device.display()))?;
    // What is read back comes from the storage, not the pages just written.
    let rc = unsafe { libc::posix_fadvise(out.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc))
            .with_context(|| format!("drop the cached pages of {}", device.display()));
    }
    let back = File::open(device).with_context(|| format!("open {}", device.display()))?;
    let read = store::digest(back, stored.size, &mut |n| telling.done(stored.size + n))
        .with_context(|| format!("read {} back", device.display()))?;
    ensure!(
        read == stored.sha256,
        "{} reads back different from the backup",
        device.display()
    );
    Ok(())
}
