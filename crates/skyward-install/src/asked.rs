//! Where a package the system asked to be installed is, as the recovery
//! reaches it, and what has to be open for the recovery to read it.

use crate::blockmap;
use std::path::PathBuf;

/// A package the system asked for: a file on the phone, or one it left on
/// a partition, by the path of the map of its blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asked {
    File(PathBuf),
    Mapped(PathBuf),
}

/// What has to be open for the recovery to read where the package is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Needs {
    /// Nothing the recovery does not have already.
    Nothing,
    /// The cache partition, mounted.
    Cache,
    /// The data partition, open as far as it opens with nothing a user
    /// knows.
    Data,
    /// The own files of this user, which may wait on their screen lock.
    User(u32),
}

/// The package the system named `package` as the recovery reaches it, and
/// what has to be open for it. The system keeps /cache in the data
/// partition on a phone with no cache partition, and /sdcard is the
/// owner's shared storage, which is the data partition's /data/media/0.
pub fn locate(package: &str, cache_partition: bool) -> (Asked, Needs) {
    let (map, path) = match blockmap::mapped(package) {
        Some(map) => (true, map),
        None => (false, package),
    };
    let path = match path.strip_prefix("/cache/") {
        Some(rest) if !cache_partition => format!("/data/cache/{rest}"),
        _ => path.to_string(),
    };
    let needs = if let Some(rest) = path.strip_prefix("/data/media/") {
        rest.split('/')
            .next()
            .and_then(|user| user.parse().ok())
            .map_or(Needs::Data, Needs::User)
    } else if path.starts_with("/sdcard/") {
        Needs::User(0)
    } else if path.starts_with("/data/") {
        Needs::Data
    } else if path.starts_with("/cache/") {
        Needs::Cache
    } else {
        Needs::Nothing
    };
    let asked = if map {
        Asked::Mapped(path.into())
    } else {
        Asked::File(path.into())
    };
    (asked, needs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_map_in_cache_is_in_the_data_partition_on_a_phone_without_a_cache_partition() {
        let (asked, needs) = locate("@/cache/recovery/block.map", false);
        assert_eq!(
            asked,
            Asked::Mapped("/data/cache/recovery/block.map".into())
        );
        assert_eq!(needs, Needs::Data);
        let (asked, needs) = locate("@/cache/recovery/block.map", true);
        assert_eq!(asked, Asked::Mapped("/cache/recovery/block.map".into()));
        assert_eq!(needs, Needs::Cache);
    }

    #[test]
    fn a_package_in_a_users_storage_waits_for_that_user() {
        assert_eq!(
            locate("/sdcard/update.zip", false),
            (Asked::File("/sdcard/update.zip".into()), Needs::User(0))
        );
        assert_eq!(
            locate("/data/media/10/Download/update.zip", false).1,
            Needs::User(10)
        );
        assert_eq!(
            locate("/data/media/obb/x.zip", false).1,
            Needs::Data,
            "a folder not a user's own"
        );
    }

    #[test]
    fn a_package_elsewhere_needs_the_data_partition_or_nothing() {
        assert_eq!(
            locate("/data/ota_package/update.zip", false),
            (
                Asked::File("/data/ota_package/update.zip".into()),
                Needs::Data
            )
        );
        assert_eq!(
            locate("/mnt/usb/update.zip", false),
            (Asked::File("/mnt/usb/update.zip".into()), Needs::Nothing)
        );
    }
}
