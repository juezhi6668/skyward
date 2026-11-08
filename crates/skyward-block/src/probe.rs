//! What a partition holds now: the filesystem on it, which need not be the
//! one the phone's own table names for it. It is read off the partition's
//! own superblock, which is the fact on the disk — the ramdisk's blkid does
//! not know erofs, and the erofs tool this used to fall back on is not in
//! the image at all, so a partition holding erofs used to end as an error
//! rather than as a name.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Where each filesystem keeps its magic, and what it is: erofs's `h_magic`
/// is the first word of the superblock a kilobyte in, ext4 keeps `s_magic`
/// 56 bytes into that same superblock, and f2fs keeps its whole superblock
/// at `F2FS_SUPER_OFFSET`, a kilobyte in as well, with `s_magic` as its
/// first field. The same three places an image of a filesystem is
/// recognised by, so a partition and an image of it answer alike.
///
/// f2fs's is **not** at the partition's first byte: an earlier reading of
/// this had it there, and a data partition that is f2fs then read as holding
/// nothing at all, which is what stopped the recovery opening /data without
/// keys. Measured on the Mi 6: the first eight bytes of `by-name/userdata`
/// are zero and `10 20 f5 f2` is at 1024.
const EROFS: (usize, &[u8], &str) = (1024, &[0xe2, 0xe1, 0xf5, 0xe0], "erofs");
const EXT4: (usize, &[u8], &str) = (1080, &[0x53, 0xef], "ext4");
const F2FS: (usize, &[u8], &str) = (1024, &[0x10, 0x20, 0xf5, 0xf2], "f2fs");

/// How much of a partition is read: far enough to reach ext4's magic.
const HEAD: usize = 1082;

/// The filesystem on `device`; none where it holds nothing known, which is
/// how a partition reads after it has been discarded.
pub fn filesystem(device: &Path) -> Result<Option<String>> {
    let file = File::open(device).with_context(|| format!("open {}", device.display()))?;
    // A partition shorter than a superblock reads short, and a magic only
    // counts where all of it was read: `head.len()` is what came back.
    let mut head = Vec::with_capacity(HEAD);
    file.take(HEAD as u64)
        .read_to_end(&mut head)
        .with_context(|| format!("read {}", device.display()))?;
    for (at, magic, name) in [EROFS, EXT4, F2FS] {
        if head.len() >= at + magic.len() && &head[at..at + magic.len()] == magic {
            return Ok(Some(name.to_string()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn holding(at: usize, magic: &[u8], size: usize) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = vec![0u8; size];
        if at + magic.len() <= size {
            bytes[at..at + magic.len()].copy_from_slice(magic);
        }
        std::fs::write(dir.path().join("partition"), &bytes).unwrap();
        dir
    }

    #[test]
    fn a_partition_is_named_by_the_superblock_it_holds() {
        for (at, magic, name) in [EROFS, EXT4, F2FS] {
            let dir = holding(at, magic, 4096);
            let device = dir.path().join("partition");
            assert_eq!(filesystem(&device).unwrap().as_deref(), Some(name), "{name}");
        }
    }

    #[test]
    fn a_partition_with_nothing_known_on_it_is_named_nothing() {
        let dir = holding(0, &[], 4096);
        let device = dir.path().join("partition");
        assert_eq!(filesystem(&device).unwrap(), None, "a discarded partition");
        // A partition shorter than a superblock cannot hold a magic at 1024,
        // and reading what is there must not be mistaken for reading one.
        let dir = holding(0, &[], 8);
        let device = dir.path().join("partition");
        assert_eq!(filesystem(&device).unwrap(), None, "a partition of 8 bytes");
    }

    #[test]
    fn a_magic_at_the_wrong_place_is_not_a_filesystem() {
        // The mistake this file was fixed for: f2fs's magic read at the
        // partition's first byte. A partition holding f2fs has zeroes there.
        let dir = holding(0, F2FS.1, 4096);
        let device = dir.path().join("partition");
        assert_eq!(filesystem(&device).unwrap(), None, "the magic at 0 is not f2fs's");
        // And where it really is, it is named.
        let dir = holding(F2FS.0, F2FS.1, 4096);
        let device = dir.path().join("partition");
        assert_eq!(filesystem(&device).unwrap().as_deref(), Some("f2fs"));
    }

    #[test]
    fn erofs_and_f2fs_share_the_kilobyte_and_are_told_apart_by_their_magic() {
        let dir = holding(EROFS.0, EROFS.1, 4096);
        let device = dir.path().join("partition");
        assert_eq!(filesystem(&device).unwrap().as_deref(), Some("erofs"));
    }
}
