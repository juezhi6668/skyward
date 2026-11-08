//! The table a phone keeps of its own filesystems: where each one is, what
//! it holds, and how it is encrypted.

use anyhow::{ensure, Context, Result};
use std::path::{Path, PathBuf};

/// Where the phone's own partitions keep the table. The vendor and odm
/// places are what a running system mounts its table from; a recovery for an
/// older Qualcomm phone carries the very same table in its own system folder,
/// where nothing is mounted yet, and that is the only copy a phone whose
/// partitions are not up can be read from.
/// **The recovery's own table comes first.** It is the one written for this
/// program; a phone's `fstab.qcom` is the installed *system's* plan, and on
/// this phone it is not even readable until the vendor files are mounted —
/// `/vendor/etc/fstab.qcom` only appears when `cust` is mounted at /vendor.
/// Letting it win once that happened is what made two things go wrong at
/// once: its system line mounts at `/system` (over the recovery's own, which
/// is where this binary and its tools live), and its data line carries no
/// `formattable`, so a format of /data answered "the partition is not one
/// this recovery rebuilds" while the recovery's own table says it is. A
/// phone whose recovery carries no table of its own still gets fstab.qcom,
/// which is why it is kept rather than dropped.
pub const FILES: [&str; 4] = [
    "/system/etc/recovery.fstab",
    // Lines this recovery adds for a partition the phone's own table says
    // nothing about, written into the ramdisk from the device
    // configuration: a phone that keeps no metadata partition but has one
    // that answers for it says so there.
    "/system/etc/skyward.fstab",
    "/vendor/etc/fstab.qcom",
    "/odm/etc/fstab.qcom",
];

/// What a table entry can name that is not a filesystem to put anywhere:
/// these partitions the recovery reads and writes whole, so a mount page has
/// nothing to ask of them.
pub const RAW: [&str; 4] = ["emmc", "mtd", "swap", "tmpfs"];

/// Where a system whose whole layout starts at its own root is mounted in a
/// recovery: the recovery runs from the ramdisk at `/`, and mounting over it
/// would hide the programs it is running.
pub const SYSTEM_ROOT: &str = "/system_root";

/// Where an entry of the table goes.
pub fn point(mount_point: &str) -> &str {
    match mount_point {
        // The recovery's own /system is the ramdisk's, and everything it
        // runs from is in it: /system/bin holds this binary, the shell and
        // the box of tools, /system/lib64 the libraries they load, and
        // /system/bin/linker64 starts them. Mounting the installed system
        // there takes all of that away from under the recovery — its own
        // /system/bin/sh then resolves inside the phone's system partition
        // and nothing that runs from it starts again. So the installed
        // system goes to /system_root, whether the table calls it `/`
        // (system-as-root) or `/system` (the older layout).
        //
        // The second name is not academic. `/vendor/etc/fstab.qcom` is read
        // before the recovery's own table, and it only exists once the
        // vendor files are mounted: mounting `cust` at /vendor makes the
        // phone's own fstab.qcom appear, and it names this partition
        // `/system` — so mounting `system` after `vendor` used to mount it
        // over the recovery and leave the recovery unable to read anything.
        "/" | "/system" => SYSTEM_ROOT,
        other => other,
    }
}

/// One filesystem the phone knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub device: String,
    pub mount_point: String,
    pub filesystem: String,
    /// How the phone mounts it: the kernel's flags and the filesystem's
    /// own options, as one list.
    pub options: Vec<String>,
    /// What the phone says about the filesystem beyond how to mount it,
    /// such as how it is encrypted.
    pub extras: Vec<String>,
}

impl Entry {
    /// The value of an extra written as `name=value`.
    pub fn extra(&self, name: &str) -> Option<&str> {
        let prefix = format!("{name}=");
        self.extras.iter().find_map(|e| e.strip_prefix(&prefix))
    }
}

/// Every filesystem a table names. A phone may name the same mount point
/// more than once, once per filesystem it might hold.
pub fn entries(text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [device, mount_point, filesystem, options, extras] = fields[..] else {
            continue;
        };
        out.push(Entry {
            device: device.to_string(),
            mount_point: mount_point.to_string(),
            filesystem: filesystem.to_string(),
            options: options.split(',').map(str::to_string).collect(),
            extras: extras.split(',').map(str::to_string).collect(),
        });
    }
    out
}

/// Every entry of the phone's own table, read from wherever the table is.
fn table() -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for file in FILES {
        let text = match std::fs::read_to_string(file) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("read {file}")),
        };
        out.extend(entries(&text));
    }
    Ok(out)
}

/// What the phone's own table says about `mount_point`.
pub fn read(mount_point: &str) -> Result<Vec<Entry>> {
    Ok(table()?
        .into_iter()
        .filter(|e| e.mount_point == mount_point)
        .collect())
}

/// What the phone's own table says about the partition `name`: the first
/// entry naming it, by whichever path the table reaches it.
pub fn partition(name: &str) -> Result<Option<Entry>> {
    Ok(table()?.into_iter().find(|e| names(e, name)))
}

/// Whether an entry is of the partition `name`.
fn names(entry: &Entry, name: &str) -> bool {
    Path::new(&entry.device)
        .file_name()
        .is_some_and(|n| n == name)
}

/// Whether an entry is about the partition `name`: reached by that name, or
/// mounted where that name is what the partition is for. A partition that
/// stands in for another answers to what it stands for: this phone's
/// `oops` holds the metadata a phone with a metadata partition would keep
/// there, and a recovery asked to mount `metadata` means that one.
fn about(entry: &Entry, name: &str) -> bool {
    names(entry, name) || entry.mount_point == name || entry.mount_point == format!("/{name}")
}

/// The partition an entry names, as it is reachable now: of the booted
/// slot, where the phone keeps one of it per slot. A phone's table points
/// at its storage controller by a path a recovery need not have.
pub fn device(entry: &Entry) -> Result<String> {
    let path = match entry.extras.iter().any(|e| e == "slotselect") {
        true => format!(
            "{}{}",
            entry.device,
            crate::slot_suffix()?.with_context(|| format!(
                "{} is of a slot, and the phone has none",
                entry.device
            ))?
        ),
        false => entry.device.clone(),
    };
    if Path::new(&path).exists() {
        return Ok(path);
    }
    let name = Path::new(&path)
        .file_name()
        .with_context(|| format!("{path} names no partition"))?;
    let by_name = Path::new(crate::BY_NAME).join(name);
    if by_name.exists() {
        return Ok(by_name.to_string_lossy().into_owned());
    }
    anyhow::bail!("neither {path} nor {} is here", by_name.display())
}

/// One partition the recovery can put a filesystem on, with every way the
/// phone's own table says to mount it, in the order the table lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mountable {
    /// The partition's name, as the path the table reaches it by ends: what
    /// the mount page titles the row with and the runtime acts on.
    pub name: String,
    /// Where the table mounts it, as a recovery can reach it.
    pub point: String,
    pub ways: Vec<Entry>,
}

/// Every partition a recovery can mount, as the phone's own table says, read
/// off wherever that table is. Nothing else is asked of the phone: a phone
/// with one set of partitions has no slot to be named by, and its table is
/// complete on its own.
pub fn mountable() -> Result<Vec<Mountable>> {
    let mut out: Vec<Mountable> = Vec::new();
    for entry in table()? {
        if RAW.contains(&entry.filesystem.as_str()) {
            continue;
        }
        let Some(name) = Path::new(&entry.device)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
        else {
            continue;
        };
        let point = point(&entry.mount_point).to_string();
        match out
            .iter_mut()
            .find(|one| one.name == name && one.point == point)
        {
            Some(one) => one.ways.push(entry),
            None => out.push(Mountable {
                name,
                point,
                ways: vec![entry],
            }),
        }
    }
    Ok(out)
}

/// Mount the partition `name` where and as the phone's own table mounts
/// it, and say where. Whatever shows there already, as what an earlier run
/// of the recovery service mounted does, is taken as it is.
pub fn mount(name: &str) -> Result<PathBuf> {
    let ways: Vec<Entry> = table()?.into_iter().filter(|e| about(e, name)).collect();
    ensure!(
        !ways.is_empty(),
        "the phone's own table does not mount {name}"
    );
    let at = PathBuf::from(point(&ways[0].mount_point));
    if crate::mount::is_mount_point(&at)? {
        return Ok(at);
    }
    crate::mount::prepare(&at)?;
    // The table may name one partition once for every filesystem it might
    // hold, an ext4 cache before an f2fs one and an erofs system before an
    // ext4 one, and only the phone knows which it was last written with.
    // Each is tried in the order the table gives, and what the last of them
    // answers is what is told.
    let mut why = anyhow::anyhow!(
        "{name} mounted as none of the {} filesystems the table names",
        ways.len()
    );
    for entry in &ways {
        let where_ = device(entry)?;
        let path = Path::new(&where_);
        match crate::mount::mount(path, &at, &entry.filesystem, &entry.options) {
            Ok(()) => return Ok(at),
            Err(e) => why = e.context(format!("mount {where_} as {}", entry.filesystem)),
        }
    }
    Err(why)
}

/// Take the partition `name` off every place the phone's own table mounts
/// it, since one partition may be read from more than one place at once.
pub fn unmount(name: &str) -> Result<()> {
    let ways: Vec<Entry> = table()?.into_iter().filter(|e| about(e, name)).collect();
    ensure!(
        !ways.is_empty(),
        "the phone's own table does not mount {name}"
    );
    let mut failed = None;
    for at in ways
        .iter()
        .map(|e| PathBuf::from(point(&e.mount_point)))
        .collect::<std::collections::BTreeSet<_>>()
    {
        if !crate::mount::is_mount_point(&at)? {
            continue;
        }
        if let Err(e) = crate::mount::umount(&at) {
            failed = Some(e.context(format!("take {} off", at.display())));
        }
    }
    match failed {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "\
# a comment
/dev/block/bootdevice/by-name/metadata /metadata f2fs noatime,nosuid wait,check,formattable
/dev/block/bootdevice/by-name/userdata /data f2fs noatime,discard latemount,wait,fileencryption=aes-256-xts:aes-256-cts:v2,keydirectory=/metadata/vold/metadata_encryption,metadata_encryption=aes-256-xts:wrappedkey_v0,quota
/dev/block/bootdevice/by-name/userdata /data mifs noatime,discard latemount,wait,keydirectory=/metadata/vold/metadata_encryption
";

    #[test]
    fn the_installed_system_never_lands_on_the_recovery_s_own_system() {
        // Whatever the table calls it, the installed system is mounted at
        // /system_root: /system is the ramdisk's, and the recovery runs from
        // it. Both names are real — recovery.fstab says `/` and the phone's
        // own vendor/etc/fstab.qcom says `/system`, and that second file
        // only becomes readable once the vendor files are mounted, which is
        // how mounting system after vendor used to take the recovery's own
        // /system away from under it.
        assert_eq!(point("/"), SYSTEM_ROOT);
        assert_eq!(point("/system"), SYSTEM_ROOT);
        // Everything else keeps the phone's own word for it.
        assert_eq!(point("/vendor"), "/vendor");
        assert_eq!(point("/data"), "/data");
    }

    #[test]
    fn a_mount_point_can_be_named_once_per_filesystem_it_might_hold() {
        let data: Vec<Entry> = entries(TABLE)
            .into_iter()
            .filter(|e| e.mount_point == "/data")
            .collect();
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].filesystem, "f2fs");
        assert_eq!(data[1].filesystem, "mifs");
        assert_eq!(data[0].device, "/dev/block/bootdevice/by-name/userdata");
    }

    #[test]
    fn how_the_phone_mounts_a_filesystem_is_kept_apart_from_the_rest() {
        let data = &entries(TABLE)[1];
        assert_eq!(data.options, ["noatime", "discard"]);
        assert!(
            data.extras.iter().any(|e| e == "latemount")
                && !data.extras.iter().any(|e| e == "noatime")
        );
    }

    #[test]
    fn what_the_phone_says_about_encryption_is_read_off_the_entry() {
        let data = &entries(TABLE)[1];
        assert_eq!(
            data.extra("metadata_encryption"),
            Some("aes-256-xts:wrappedkey_v0")
        );
        assert_eq!(
            data.extra("keydirectory"),
            Some("/metadata/vold/metadata_encryption")
        );
        assert_eq!(data.extra("quota"), None, "a word on its own has no value");
        assert_eq!(
            data.extra("keydir"),
            None,
            "a shorter name is another extra"
        );
    }

    #[test]
    fn an_entry_is_of_the_partition_its_path_ends_in() {
        let modem = &entries(
            "/dev/block/bootdevice/by-name/modem /vendor/firmware_mnt vfat ro,uid=1000,context=u:object_r:firmware_file:s0 wait,slotselect\n",
        )[0];
        assert!(names(modem, "modem"));
        assert!(
            !names(modem, "modemfirmware") && !names(modem, "mode"),
            "a name is matched whole"
        );
        assert_eq!(modem.options[0], "ro");
        assert!(
            modem.extras.iter().any(|e| e == "slotselect"),
            "one of each slot"
        );
    }

    #[test]
    fn comments_and_short_lines_are_passed_over() {
        assert!(entries("# nothing\n\n/dev/x /y f2fs rw\n").is_empty());
        assert_eq!(entries(TABLE).len(), 3);
    }

    const OLDER: &str = "\
/dev/block/bootdevice/by-name/boot      /boot        emmc  defaults  defaults
/dev/block/bootdevice/by-name/system    /            ext4  ro,barrier=1  wait
/dev/block/bootdevice/by-name/cust      /vendor      ext4  ro,barrier=1  wait
/dev/block/bootdevice/by-name/cache     /cache       ext4  nosuid,nodev,noatime  defaults
/dev/block/bootdevice/by-name/cache     /cache       f2fs  nosuid,nodev,noatime  defaults
/dev/block/bootdevice/by-name/userdata  /data        ext4  nosuid  wait,check,fileencryption=ice
/dev/block/bootdevice/by-name/persist   /persist     ext4  nosuid  defaults
/dev/block/bootdevice/by-name/modem     /vendor/firmware_mnt vfat ro,uid=1000 defaults
";

    #[test]
    fn a_recovery_table_names_what_can_be_mounted_and_what_cannot() {
        let list = mountable_of(OLDER);
        let names: Vec<&str> = list.iter().map(|one| one.name.as_str()).collect();
        assert_eq!(
            names,
            ["system", "cust", "cache", "userdata", "persist", "modem"],
            "the raw boot partition is not a filesystem to mount"
        );
        assert_eq!(
            list[0].point, "/system_root",
            "a system whose root holds everything is mounted in a folder of its own"
        );
        assert_eq!(
            list[2].ways.len(),
            2,
            "one cache, the two filesystems it might hold"
        );
        assert_eq!(
            list[2].ways[0].filesystem, "ext4",
            "in the order the table gives them"
        );
    }

    #[test]
    fn a_partition_mounted_in_more_than_one_place_is_one_row_per_place() {
        let list = mountable_of("/dev/x /a ext4 rw defaults\n/dev/x /b ext4 rw defaults\n");
        assert_eq!(list.len(), 2);
        assert_eq!((list[0].name.as_str(), list[0].point.as_str()), ("x", "/a"));
        assert_eq!((list[1].name.as_str(), list[1].point.as_str()), ("x", "/b"));
    }

    /// The listing over a table given as text, which is what the page reads.
    fn mountable_of(text: &str) -> Vec<Mountable> {
        let mut out: Vec<Mountable> = Vec::new();
        for entry in entries(text) {
            if RAW.contains(&entry.filesystem.as_str()) {
                continue;
            }
            let name = std::path::Path::new(&entry.device)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let point = point(&entry.mount_point).to_string();
            match out
                .iter_mut()
                .find(|one| one.name == name && one.point == point)
            {
                Some(one) => one.ways.push(entry),
                None => out.push(Mountable {
                    name,
                    point,
                    ways: vec![entry],
                }),
            }
        }
        out
    }
}
