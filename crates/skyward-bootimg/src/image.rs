use abootimg_oxide::{binrw::io::Cursor, Header, HeaderV3};
use anyhow::{anyhow, ensure, Context, Result};
use std::fs;
use std::path::Path;

/// The page a version 3 or 4 header pads its sections to. Version 0 to 2
/// headers carry their own page size, which is the same 4096 on the older
/// Qualcomm recoveries but is not on every one of them.
const PAGE_V3: usize = 4096;

/// A boot image split into its header, kernel and ramdisk. Version 3 and 4
/// headers hold the ramdisk-only layout a HyperOS recovery ships; version 0
/// to 2 hold the kernel and ramdisk beside each other, with the board's
/// device trees riding at the end of the kernel section.
pub struct BootImage {
    pub header: Header,
    pub kernel: Vec<u8>,
    pub ramdisk: Vec<u8>,
}

fn section(bytes: &[u8], at: usize, len: u32, what: &str) -> Result<Vec<u8>> {
    let end = at + len as usize;
    bytes
        .get(at..end)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| anyhow!("{what} runs past the end of the image"))
}

/// The page `header` pads its sections to.
fn page(header: &Header) -> usize {
    match header {
        Header::V0(h) => h.page_size as usize,
        Header::V3(_) => PAGE_V3,
    }
}

/// Where a header's kernel and ramdisk sections start.
fn positions(header: &Header) -> (usize, usize) {
    match header {
        Header::V0(h) => (h.kernel_position(), h.ramdisk_position()),
        Header::V3(h) => (HeaderV3::kernel_position(), h.ramdisk_position()),
    }
}

/// A header's kernel and ramdisk sizes.
fn sizes(header: &Header) -> (u32, u32) {
    match header {
        Header::V0(h) => (h.kernel_size, h.ramdisk_size),
        Header::V3(h) => (h.kernel_size, h.ramdisk_size),
    }
}

impl BootImage {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        BootImage::parse(&bytes).with_context(|| format!("read {}", path.display()))
    }

    /// The image `bytes` hold, as a partition holds it: the image, then
    /// whatever fills the partition after it. Version 0 to 2 headers carry
    /// the kernel and ramdisk beside each other; version 3 and 4 hold the
    /// ramdisk alone.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = match Header::parse(&mut Cursor::new(bytes)) {
            Ok(h) => h,
            Err(e) => return Err(anyhow!(e).context("header")),
        };
        let pg = page(&header);
        let (kernel_at, ramdisk_at) = positions(&header);
        let (kernel_len, ramdisk_len) = sizes(&header);
        // Everything past the ramdisk of a version 0 to 2 image would be a
        // second bootloader, a recovery device tree or the room a partition
        // dump leaves after the image. Moving the ramdisk moves none of them
        // with it, so only empty room is accepted.
        let after = ramdisk_at + (ramdisk_len as usize).div_ceil(pg) * pg;
        if let Header::V0(_) = &header {
            ensure!(
                bytes[after.min(bytes.len())..].iter().all(|&b| b == 0),
                "holds a section after its ramdisk, which cannot be moved"
            );
        }
        let kernel = section(bytes, kernel_at, kernel_len, "kernel")?;
        let ramdisk = section(bytes, ramdisk_at, ramdisk_len, "ramdisk")?;
        Ok(BootImage {
            header,
            kernel,
            ramdisk,
        })
    }

    /// The image with sizes taken from its parts. A version 4 header keeps its
    /// version but carries no boot signature; unlocked bootloaders do not ask
    /// for one.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut header = self.header.clone();
        match &mut header {
            Header::V0(h) => {
                h.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
                h.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
            }
            Header::V3(h) => {
                h.kernel_size = u32::try_from(self.kernel.len()).context("kernel size")?;
                h.ramdisk_size = u32::try_from(self.ramdisk.len()).context("ramdisk size")?;
                h.v4_signature_size = h.v4_signature_size.map(|_| 0);
            }
        }
        let pg = page(&header);
        let mut out = Vec::new();
        header.write(&mut out).context("write header")?;
        pad(&mut out, pg);
        out.extend_from_slice(&self.kernel);
        pad(&mut out, pg);
        out.extend_from_slice(&self.ramdisk);
        pad(&mut out, pg);
        Ok(out)
    }
}

fn pad(out: &mut Vec<u8>, page: usize) {
    out.resize(out.len().div_ceil(page) * page, 0);
}
