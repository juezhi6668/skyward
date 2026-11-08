//! A package the system left on a partition and wrote a map of: which of
//! the partition's blocks hold it, in order. The system writes one for a
//! package it put in the data partition, whose filesystem a recovery
//! cannot read where each user's own files are still locked; the blocks are
//! read through the partition itself.

use crate::adb::Offer;
use crate::fuse::Source;
use anyhow::{ensure, Context, Result};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// A run of blocks on the partition, and which of the package's blocks it
/// holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    /// The package's block this run starts at.
    at: u64,
    /// The partition's block it starts at.
    device: u64,
    blocks: u64,
}

/// A map of where a package is: the partition, how long the package is and
/// in what blocks the map counts, and the runs of blocks it holds, in the
/// package's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMap {
    pub device: PathBuf,
    pub size: u64,
    pub block_size: u32,
    spans: Vec<Span>,
}

impl BlockMap {
    /// Read a map as the system writes it: the partition, then the
    /// package's length and the size of a block, then how many runs
    /// follow, then each run as the block it starts at and the one after
    /// its last.
    pub fn parse(text: &str) -> Result<BlockMap> {
        let lines: Vec<&str> = text.trim().lines().collect();
        ensure!(
            lines.len() >= 4,
            "a block map holds the partition, the sizes, how many runs follow and the runs, not {} lines",
            lines.len()
        );
        let (device, count, runs) = (lines[0], lines[2], &lines[3..]);
        let mut sizes = lines[1].split_whitespace();
        let size: u64 = number(sizes.next(), "the package's length")?;
        let block_size: u32 = number(sizes.next(), "the size of a block")?;
        ensure!(
            size > 0 && block_size > 0,
            "a map of {size} bytes in blocks of {block_size}"
        );
        let count: usize = number(Some(count.trim()), "how many runs follow")?;
        ensure!(
            count > 0 && count == runs.len(),
            "the map says {count} runs and holds {}",
            runs.len()
        );
        let blocks = size.div_ceil(u64::from(block_size));
        ensure!(
            blocks <= u64::from(u32::MAX),
            "a package of {blocks} blocks is longer than a map holds"
        );
        let mut spans = Vec::with_capacity(count);
        let mut at = 0;
        for run in runs {
            let mut ends = run.split_whitespace();
            let start: u64 = number(ends.next(), "a run's first block")?;
            let end: u64 = number(ends.next(), "the block after a run's last")?;
            ensure!(end > start, "a run from block {start} to {end}");
            let held = end - start;
            ensure!(
                at + held <= blocks,
                "the runs hold more than the package's {blocks} blocks"
            );
            spans.push(Span {
                at,
                device: start,
                blocks: held,
            });
            at += held;
        }
        ensure!(
            at == blocks,
            "the runs hold {at} of the package's {blocks} blocks"
        );
        Ok(BlockMap {
            device: PathBuf::from(device),
            size,
            block_size,
            spans,
        })
    }

    /// Read the map the system wrote at `path`.
    pub fn read(path: &Path) -> Result<BlockMap> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        BlockMap::parse(&text).with_context(|| format!("read the block map in {}", path.display()))
    }

    /// Open the partition to serve the package from it, with the size and
    /// the block size it is served in.
    pub fn open(&self) -> Result<(Mapped, Offer)> {
        let file =
            File::open(&self.device).with_context(|| format!("open {}", self.device.display()))?;
        let block_size = crate::fuse::file_block(self.size);
        let mapped = Mapped {
            file,
            block_size: u64::from(block_size),
            map_block: u64::from(self.block_size),
            spans: self.spans.clone(),
        };
        Ok((
            mapped,
            Offer {
                size: self.size,
                block_size,
            },
        ))
    }

    /// How many of the partition's blocks the package takes.
    pub fn blocks(&self) -> u64 {
        self.spans.iter().map(|s| s.blocks).sum()
    }
}

fn number<T: std::str::FromStr>(field: Option<&str>, what: &str) -> Result<T> {
    let field = field.with_context(|| format!("a block map without {what}"))?;
    field
        .parse()
        .map_err(|_| anyhow::anyhow!("{what} reads {field:?}"))
}

/// The package as the partition holds it: served in blocks of its own,
/// each read from wherever on the partition the map puts it.
pub struct Mapped {
    file: File,
    /// The size of the blocks the package is served in.
    block_size: u64,
    /// The size of the blocks the map counts in.
    map_block: u64,
    spans: Vec<Span>,
}

impl Mapped {
    /// Read `out` from `offset` in the package, run by run: a read runs
    /// over as many of them as it has to.
    fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let mut read = 0;
        while read < out.len() {
            let at = offset + read as u64;
            let (block, within) = (at / self.map_block, at % self.map_block);
            let span = self
                .spans
                .binary_search_by(|s| match () {
                    _ if block < s.at => std::cmp::Ordering::Greater,
                    _ if block >= s.at + s.blocks => std::cmp::Ordering::Less,
                    _ => std::cmp::Ordering::Equal,
                })
                .map(|i| self.spans[i])
                .map_err(|_| {
                    io::Error::other(format!("the map does not hold the package's block {block}"))
                })?;
            // As much as is left of the run, and no more than is wanted.
            let left = (span.at + span.blocks - block) * self.map_block - within;
            let take = left.min((out.len() - read) as u64) as usize;
            let device_at = (span.device + block - span.at) * self.map_block + within;
            self.file
                .read_exact_at(&mut out[read..read + take], device_at)?;
            read += take;
        }
        Ok(())
    }
}

impl Source for Mapped {
    fn read_block(&mut self, index: u64, out: &mut [u8]) -> Result<(), String> {
        self.read_at(index * self.block_size, out)
            .map_err(|e| e.to_string())
    }
}

/// Whether a package the system named is a map of one rather than a file:
/// the system writes `@` before the map's path.
pub fn mapped(package: &str) -> Option<&str> {
    package.strip_prefix('@')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A map as uncrypt writes one: 10 KiB in blocks of 4096, held in two
    /// runs of the partition.
    const MAP: &str = "/dev/block/by-name/userdata\n10240 4096\n2\n100 102\n500 501\n";

    #[test]
    fn a_map_says_where_each_of_the_packages_blocks_is() {
        let map = BlockMap::parse(MAP).unwrap();
        assert_eq!(map.device, Path::new("/dev/block/by-name/userdata"));
        assert_eq!((map.size, map.block_size, map.blocks()), (10240, 4096, 3));
        assert_eq!(
            map.spans,
            [
                Span {
                    at: 0,
                    device: 100,
                    blocks: 2
                },
                Span {
                    at: 2,
                    device: 500,
                    blocks: 1
                }
            ]
        );
    }

    #[test]
    fn a_map_that_does_not_add_up_is_refused() {
        let short = "/dev/block/x\n10240 4096\n1\n100 102\n";
        assert!(
            BlockMap::parse(short).is_err(),
            "two of the package's three blocks"
        );
        let miscounted = "/dev/block/x\n10240 4096\n2\n100 103\n";
        assert!(
            BlockMap::parse(miscounted).is_err(),
            "one run where it says two"
        );
        let backwards = "/dev/block/x\n10240 4096\n1\n102 100\n";
        assert!(BlockMap::parse(backwards).is_err());
        let sizeless = "/dev/block/x\n0 4096\n1\n100 103\n";
        assert!(BlockMap::parse(sizeless).is_err());
        assert!(
            BlockMap::parse("/dev/block/x\n10240 4096\n").is_err(),
            "too few lines"
        );
        assert!(
            BlockMap::parse("/dev/block/x\nmany 4096\n1\n0 3\n").is_err(),
            "a length that is not a number"
        );
    }

    #[test]
    fn only_a_path_after_an_at_sign_is_a_map() {
        assert_eq!(
            mapped("@/cache/recovery/block.map"),
            Some("/cache/recovery/block.map")
        );
        assert_eq!(mapped("/sdcard/update.zip"), None);
    }

    /// The map above over a partition whose blocks each hold their own
    /// number, so what is read says where it came from.
    fn partition(name: &str) -> (PathBuf, Mapped) {
        let path =
            std::env::temp_dir().join(format!("skyward-blockmap-{name}-{}", std::process::id()));
        let mut bytes = vec![0u8; 4096 * 501 + 4096];
        for block in 0..bytes.len() / 4096 {
            bytes[block * 4096..block * 4096 + 4].copy_from_slice(&(block as u32).to_le_bytes());
            bytes[block * 4096 + 4095] = block as u8;
        }
        std::fs::write(&path, &bytes).unwrap();
        let map = BlockMap::parse(MAP).unwrap();
        let file = File::open(&path).unwrap();
        let mapped = Mapped {
            file,
            block_size: 4096,
            map_block: 4096,
            spans: map.spans.clone(),
        };
        (path, mapped)
    }

    #[test]
    fn the_packages_blocks_are_read_from_where_the_map_puts_them() {
        let (path, mut mapped) = partition("blocks");
        let mut out = [0u8; 4096];
        let first = |out: &[u8]| u32::from_le_bytes(out[..4].try_into().unwrap());
        for (index, block) in [(0, 100), (1, 101), (2, 500)] {
            mapped.read_block(index, &mut out).unwrap();
            assert_eq!(first(&out), block, "the package's block {index}");
        }
        assert!(
            mapped.read_block(3, &mut out).is_err(),
            "past the package's last block"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_read_runs_over_as_many_of_the_partitions_blocks_as_it_has_to() {
        let (path, mapped) = partition("across");
        // Both blocks of the first run and the one block of the second,
        // read in one go from halfway into the first.
        let mut out = vec![0u8; 4096 * 2];
        mapped.read_at(2048, &mut out).unwrap();
        assert_eq!(out[2047], 100, "the end of the partition's block 100");
        assert_eq!(u32::from_le_bytes(out[2048..2052].try_into().unwrap()), 101);
        assert_eq!(u32::from_le_bytes(out[6144..6148].try_into().unwrap()), 500);
        std::fs::remove_file(&path).unwrap();
    }
}
