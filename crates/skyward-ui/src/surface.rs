use crate::canvas::Canvas;
use anyhow::Result;

/// A present target. The device backend scans out through KMS; the host
/// preview backend encodes PNGs. Keeping the renderer behind this trait is
/// what lets the whole UI be built and reviewed without the phone.
pub trait Surface {
    fn size(&self) -> (u32, u32);
    /// Hand `canvas` to the display. It returns once the frame before it is
    /// on the panel and this one is on its way, so the next frame is drawn
    /// while this one goes out.
    fn present(&mut self, canvas: &Canvas) -> Result<()>;
    /// Wait until the frame presented last is on the panel.
    fn settle(&mut self) -> Result<()>;
}

/// How the display stands: lit, resting with nothing shown on it, or off.
#[cfg(target_os = "android")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Power {
    On,
    /// The panel rests, ready to light again at once, with the display
    /// processor stopped or the backlight down.
    Resting,
    Off,
}

/// How Qualcomm's display driver drives a mode, from the text of the
/// connector's mode_properties blob: key=value lines, a block per mode_name.
#[cfg(any(target_os = "android", test))]
#[derive(Debug, PartialEq, Eq)]
struct SdeMode {
    /// Layer mixers in the mode's topology, each blending one vertical
    /// strip of the screen.
    mixers: u32,
    dsc: bool,
}

#[cfg(any(target_os = "android", test))]
impl SdeMode {
    fn find(text: &str, name: &str) -> Result<SdeMode> {
        let mut current = false;
        let (mut topology, mut dsc) = (None, false);
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key == "mode_name" {
                if current {
                    break;
                }
                current = value == name;
            } else if current {
                match key {
                    "topology" => topology = Some(value),
                    "dsc_mode" => dsc = value == "1",
                    _ => {}
                }
            }
        }
        let topology = topology
            .ok_or_else(|| anyhow::anyhow!("mode_properties describes no topology for {name}"))?;
        let mixers = if topology.contains("quadpipe") {
            4
        } else if topology.contains("dualpipe") {
            2
        } else {
            1
        };
        Ok(SdeMode { mixers, dsc })
    }
}

/// Sub-pixel rendering by the display processor. A panel that shows two of
/// the three colours at each pixel, and leaves the rendering for that to the
/// display processor, names its layout as spr_pack_type in the connector's
/// capabilities blob; without the rendering, its red sub-pixels show the
/// blue of the frame. The CRTC takes the setup in SDE_SPR_INIT_CFG_V1, or
/// in SDE_SPR_INIT_CFG_V2, which adds the cfg18 fields after the first's.
#[cfg(any(target_os = "android", test))]
mod spr {
    use anyhow::{bail, Result};

    /// Red and blue taken at every other pixel, green at each.
    const DECIMATION: [u16; 4] = [1, 0, 1, 0];
    /// Two colour phases, eight steps apart.
    const COLOUR_PHASE_STEP: u16 = 8;
    const COLOUR_PHASE_REPEAT: u16 = 2;
    const COLOUR_PHASES: [i32; 24] = [
        -2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, -2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    /// Filtering through four taps, with their coefficients.
    const FOUR_TAP: u16 = 2;
    const FOUR_TAP_COEFFICIENTS: [i32; 16] = [
        128, 256, 128, 0, 86, 241, 164, 21, 52, 204, 204, 52, 21, 164, 241, 86,
    ];
    const ADAPTIVE_YYGM: u16 = 0;
    const ADAPTIVE_STRENGTHS: [u16; 5] = [0, 4, 8, 12, 16];
    const OPR_GAINS: [u16; 4] = [341, 341, 341, 0];
    const OPR_OFFSETS: [u16; 32] = [
        0, 132, 264, 396, 529, 661, 793, 925, 1057, 1189, 1321, 1453, 1586, 1718, 1850, 1982, 2114,
        2246, 2378, 2510, 2643, 2775, 2907, 3039, 3171, 3303, 3435, 3567, 3700, 3832, 3964, 4095,
    ];

    /// The layout the capabilities blob names, among its key=value lines.
    pub fn pack_type(capabilities: &str) -> Option<&str> {
        capabilities
            .lines()
            .find_map(|line| line.strip_prefix("spr_pack_type="))
    }

    /// The setup for a panel laid out as `pack_type`, as the CRTC property
    /// `property` takes it: the driver's structure, its fields in order and
    /// aligned as the phone's C compiler aligns them.
    pub fn setup(pack_type: &str, property: &str) -> Result<Vec<u8>> {
        if pack_type != "pentile" {
            bail!("the panel's sub-pixels are laid out as {pack_type}, and only a pentile layout is set up");
        }
        let cfg18 = match property {
            "SDE_SPR_INIT_CFG_V1" => false,
            "SDE_SPR_INIT_CFG_V2" => true,
            other => bail!("no sub-pixel rendering setup is laid out for {other}"),
        };
        let mut out = Vec::new();
        // flags
        out.extend(0u64.to_ne_bytes());
        // cfg0 to cfg9: the block on, no white sub-pixel, and the phases,
        // filter and adaptive mode
        put16(
            &mut out,
            &[
                1,
                1,
                1,
                0,
                0,
                COLOUR_PHASE_STEP,
                COLOUR_PHASE_REPEAT,
                FOUR_TAP,
                ADAPTIVE_YYGM,
                0,
            ],
        );
        // cfg10
        out.extend(0u32.to_ne_bytes());
        // cfg11 to cfg15
        put16(&mut out, &DECIMATION);
        put16(&mut out, &[0; 4]);
        put16(&mut out, &OPR_GAINS);
        put16(&mut out, &ADAPTIVE_STRENGTHS);
        put16(&mut out, &OPR_OFFSETS);
        // cfg16 and cfg17, on four bytes
        out.extend([0; 2]);
        put32(&mut out, &FOUR_TAP_COEFFICIENTS);
        put32(&mut out, &COLOUR_PHASES);
        // cfg18_en and cfg18, off
        if cfg18 {
            out.extend([0; 9]);
        }
        // The structure ends on eight bytes, as its flags are aligned.
        out.resize(out.len().next_multiple_of(8), 0);
        Ok(out)
    }

    fn put16(out: &mut Vec<u8>, values: &[u16]) {
        for v in values {
            out.extend(v.to_ne_bytes());
        }
    }

    fn put32(out: &mut Vec<u8>, values: &[i32]) {
        for v in values {
            out.extend(v.to_ne_bytes());
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn u16_at(b: &[u8], at: usize) -> u16 {
            u16::from_ne_bytes([b[at], b[at + 1]])
        }

        fn i32_at(b: &[u8], at: usize) -> i32 {
            i32::from_ne_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
        }

        #[test]
        fn the_layout_is_read_from_the_capabilities() {
            let text = "panel name=xiaomi o2 42 02 0a cmd mode dsc dsi panel\nspr_pack_type=pentile\nspr_pack_type_mode=BG-RG Type B\n";
            assert_eq!(pack_type(text), Some("pentile"));
            assert_eq!(pack_type("panel name=xiaomi 42 02 0a cmd mode dsc dsi panel\nspr_pack_type_mode=BG-RG Type B\n"), None, "the mode alone names none");
        }

        #[test]
        fn the_pentile_setup_is_laid_out_as_the_driver_s_structure() {
            let v1 = setup("pentile", "SDE_SPR_INIT_CFG_V1").unwrap();
            let v2 = setup("pentile", "SDE_SPR_INIT_CFG_V2").unwrap();
            assert_eq!((v1.len(), v2.len()), (296, 304));
            assert_eq!(
                v1[..292],
                v2[..292],
                "the second adds fields after the first's"
            );
            assert_eq!(v2[292..], [0; 12], "cfg18 off");
            assert_eq!(u16_at(&v1, 8), 1, "cfg0, the block on");
            assert_eq!(
                (
                    u16_at(&v1, 18),
                    u16_at(&v1, 20),
                    u16_at(&v1, 22),
                    u16_at(&v1, 24)
                ),
                (8, 2, 2, 0),
                "cfg5 to cfg8"
            );
            assert_eq!(
                (u16_at(&v1, 32), u16_at(&v1, 34)),
                (1, 0),
                "cfg11: red decimated, green not"
            );
            assert_eq!(u16_at(&v1, 68), 132, "cfg15 starts at 66");
            assert_eq!(u16_at(&v1, 128), 4095, "and ends at 130");
            assert_eq!(
                (i32_at(&v1, 132), i32_at(&v1, 136)),
                (128, 256),
                "cfg16 starts at 132"
            );
            assert_eq!(
                (i32_at(&v1, 196), i32_at(&v1, 200), i32_at(&v1, 244)),
                (-2, 2, 2),
                "cfg17 starts at 196"
            );
        }

        #[test]
        fn only_a_pentile_layout_and_the_known_properties_are_set_up() {
            assert!(setup("rgbw", "SDE_SPR_INIT_CFG_V2").is_err());
            assert!(setup("pentile", "SDE_SPR_INIT_CFG_V3").is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISHTAR: &str = "mode_name=1440x3200x60cmd\nbit_clk_rate=1360000000\ndsc_mode=1\ntopology=sde_dualpipe_dscmerge\n\
                          mode_name=1440x3200x120cmd\nsubmode_idx=1\ndsc_mode=1\ntopology=sde_dualpipe_dscmerge\n\
                          mode_name=1080x2400x60cmd\ndsc_mode=0\ntopology=sde_singlepipe\n";

    #[test]
    fn reads_the_topology_of_the_named_mode() {
        assert_eq!(
            SdeMode::find(ISHTAR, "1440x3200x120cmd").unwrap(),
            SdeMode {
                mixers: 2,
                dsc: true
            }
        );
        assert_eq!(
            SdeMode::find(ISHTAR, "1080x2400x60cmd").unwrap(),
            SdeMode {
                mixers: 1,
                dsc: false
            }
        );
        assert!(SdeMode::find(ISHTAR, "1440x3200x90cmd").is_err());
    }
}

#[cfg(target_os = "android")]
pub mod kms {
    use super::*;
    use anyhow::{anyhow, Context};
    use drm::buffer::{self, DrmFourcc, DrmModifier, PlanarBuffer};
    use drm::control::dumbbuffer::DumbBuffer;
    use drm::control::{
        atomic, connector, framebuffer, plane, property, AtomicCommitFlags,
        Device as ControlDevice, Event, FbCmd2Flags, ModeTypeFlags, PlaneType, ResourceHandle,
    };
    use drm::Device;
    use std::collections::HashMap;
    use std::fs::{File, OpenOptions};
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
    use std::time::{Duration, Instant};

    /// How long the display may take to complete a commit.
    const COMMIT_TIMEOUT: Duration = Duration::from_secs(2);

    struct Card(File);

    impl AsFd for Card {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.0.as_fd()
        }
    }

    impl Device for Card {}
    impl ControlDevice for Card {}

    /// A single-plane dumb buffer presented to ADDFB2, so the framebuffer
    /// keeps the buffer's own pixel format.
    struct Planar<'a>(&'a DumbBuffer);

    impl PlanarBuffer for Planar<'_> {
        fn size(&self) -> (u32, u32) {
            buffer::Buffer::size(self.0)
        }
        fn format(&self) -> DrmFourcc {
            buffer::Buffer::format(self.0)
        }
        fn modifier(&self) -> Option<DrmModifier> {
            None
        }
        fn pitches(&self) -> [u32; 4] {
            [buffer::Buffer::pitch(self.0), 0, 0, 0]
        }
        fn handles(&self) -> [Option<buffer::Handle>; 4] {
            [Some(buffer::Buffer::handle(self.0)), None, None, None]
        }
        fn offsets(&self) -> [u32; 4] {
            [0; 4]
        }
    }

    /// Byte order of the scanout buffer against the canvas's RGBA.
    #[derive(Clone, Copy, Debug)]
    enum Order {
        Rgba,
        Bgra,
    }

    struct Buf {
        db: DumbBuffer,
        fb: framebuffer::Handle,
        /// The buffer mapped for writing for as long as the surface lives;
        /// mapping it per frame costs a page fault per page on every frame.
        map: *mut u8,
        len: usize,
    }

    /// A KMS object's properties by name, with their current values.
    struct Props(HashMap<String, (property::Handle, u64)>);

    impl Props {
        fn read<T: ResourceHandle>(card: &Card, handle: T) -> Result<Self> {
            let values = card.get_properties(handle).context("read properties")?;
            let mut map = HashMap::new();
            for (&id, &value) in values.iter() {
                let info = card.get_property(id).context("read property")?;
                map.insert(info.name().to_string_lossy().into_owned(), (id, value));
            }
            Ok(Props(map))
        }

        fn get(&self, name: &str) -> Result<(property::Handle, u64)> {
            self.0
                .get(name)
                .copied()
                .ok_or_else(|| anyhow!("KMS property {name} missing"))
        }

        fn handle(&self, name: &str) -> Result<property::Handle> {
            Ok(self.get(name)?.0)
        }

        fn value(&self, name: &str) -> Result<u64> {
            Ok(self.get(name)?.1)
        }

        fn line(&self) -> String {
            let mut parts: Vec<String> = self
                .0
                .iter()
                .map(|(name, (_, value))| format!("{name}={value}"))
                .collect();
            parts.sort();
            parts.join(" ")
        }
    }

    fn open_card(path: &str) -> Result<Card> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("open {path}"))?;
        let card = Card(file);
        card.set_client_capability(drm::ClientCapability::UniversalPlanes, true)
            .context("enable universal planes")?;
        card.set_client_capability(drm::ClientCapability::Atomic, true)
            .context("enable atomic modesetting")?;
        Ok(card)
    }

    /// The value of the choice named `choice` of an enum property.
    fn enum_value(card: &Card, id: property::Handle, choice: &str) -> Result<u64> {
        let info = card.get_property(id).context("read property")?;
        match info.value_type() {
            property::ValueType::Enum(e) => e
                .values()
                .1
                .iter()
                .find(|v| v.name().to_str() == Ok(choice))
                .map(|v| v.value()),
            _ => None,
        }
        .ok_or_else(|| anyhow!("{} offers no {choice}", info.name().to_string_lossy()))
    }

    /// Built-in panel interfaces. Writeback and external outputs are never
    /// the recovery's screen.
    fn is_panel(interface: connector::Interface) -> bool {
        matches!(
            interface,
            connector::Interface::DSI
                | connector::Interface::EmbeddedDisplayPort
                | connector::Interface::LVDS
        )
    }

    /// Commit without blocking and wait for the flip event, so a commit the
    /// display never completes surfaces as an error instead of an endless
    /// wait.
    fn commit(card: &Card, req: atomic::AtomicModeReq, flags: AtomicCommitFlags) -> Result<()> {
        card.atomic_commit(
            flags | AtomicCommitFlags::NONBLOCK | AtomicCommitFlags::PAGE_FLIP_EVENT,
            req,
        )
        .context("atomic commit")?;
        flipped(card)
    }

    /// Wait for the flip event of the commit made last, or fail once the
    /// display has kept it waiting too long.
    fn flipped(card: &Card) -> Result<()> {
        let deadline = Instant::now() + COMMIT_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let mut pfd = libc::pollfd {
                fd: card.as_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut pfd, 1, left.as_millis() as i32) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err).context("wait for the display");
            }
            if n == 0 {
                return Err(anyhow!(
                    "the display did not complete the commit within {} ms",
                    COMMIT_TIMEOUT.as_millis()
                ));
            }
            for event in card.receive_events().context("read display events")? {
                if let Event::PageFlip(_) = event {
                    return Ok(());
                }
            }
        }
    }

    /// Connectors with their modes and properties, encoders with the CRTC
    /// they feed, CRTCs with their mode and properties, and the planes in
    /// use: what a device has for scanout and how it is wired right now.
    pub fn report(path: &str) -> Result<String> {
        use std::fmt::Write;
        let card = open_card(path)?;
        let res = card.resource_handles().context("read KMS resources")?;
        let mut out = String::new();
        for &h in res.connectors() {
            let c = card.get_connector(h, true).context("read connector")?;
            let encoder = c.current_encoder().map(u32::from);
            writeln!(
                out,
                "connector {} {:?} {:?} encoder {encoder:?} {} modes",
                u32::from(h),
                c.interface(),
                c.state(),
                c.modes().len()
            )?;
            let props = Props::read(&card, h)?;
            writeln!(out, "  {}", props.line())?;
            if is_panel(c.interface()) {
                if let Ok((_, blob)) = props.get("mode_properties") {
                    let text = card
                        .get_property_blob(blob)
                        .context("read mode_properties")?;
                    writeln!(
                        out,
                        "  mode_properties: {}",
                        String::from_utf8_lossy(&text).replace('\n', " | ")
                    )?;
                }
                if let Ok((_, blob)) = props.get("capabilities") {
                    let text = card.get_property_blob(blob).context("read capabilities")?;
                    writeln!(
                        out,
                        "  capabilities: {}",
                        String::from_utf8_lossy(&text).replace('\n', " | ")
                    )?;
                }
                for m in c.modes() {
                    let (w, hgt) = m.size();
                    writeln!(
                        out,
                        "  mode {:?} {w}x{hgt} {} Hz clock {} type {:?} flags {:?}",
                        m.name(),
                        m.vrefresh(),
                        m.clock(),
                        m.mode_type(),
                        m.flags()
                    )?;
                }
            }
        }
        for &h in res.encoders() {
            let e = card.get_encoder(h).context("read encoder")?;
            let possible: Vec<u32> = res
                .filter_crtcs(e.possible_crtcs())
                .into_iter()
                .map(u32::from)
                .collect();
            writeln!(
                out,
                "encoder {} {:?} crtc {:?} possible {possible:?}",
                u32::from(h),
                e.kind(),
                e.crtc().map(u32::from)
            )?;
        }
        for &h in res.crtcs() {
            let i = card.get_crtc(h).context("read CRTC")?;
            let mode = i
                .mode()
                .map(|m| format!("{:?} {} Hz", m.name(), m.vrefresh()));
            writeln!(
                out,
                "crtc {} mode {mode:?} fb {:?}",
                u32::from(h),
                i.framebuffer().map(u32::from)
            )?;
            writeln!(out, "  {}", Props::read(&card, h)?.line())?;
        }
        for p in card.plane_handles().context("list planes")? {
            let i = card.get_plane(p).context("read plane")?;
            let props = Props::read(&card, p)?;
            writeln!(
                out,
                "plane {} type {} crtc {:?} fb {:?} possible {} formats {}",
                u32::from(p),
                props.value("type")?,
                i.crtc().map(u32::from),
                i.framebuffer().map(u32::from),
                res.filter_crtcs(i.possible_crtcs()).len(),
                i.formats().len()
            )?;
            if i.crtc().is_some() {
                writeln!(out, "  {}", props.line())?;
            }
        }
        Ok(out)
    }

    /// The panel connector's CRTC, from the encoder driving it.
    fn panel_crtc(card: &Card) -> Result<drm::control::crtc::Handle> {
        let res = card.resource_handles().context("read KMS resources")?;
        for &h in res.connectors() {
            let info = card.get_connector(h, false).context("read connector")?;
            if is_panel(info.interface()) && info.state() == connector::State::Connected {
                let encoder = info
                    .current_encoder()
                    .ok_or_else(|| anyhow!("the panel has no encoder; is anything showing?"))?;
                return card
                    .get_encoder(encoder)
                    .context("read encoder")?
                    .crtc()
                    .ok_or_else(|| anyhow!("the panel's encoder drives no CRTC"));
            }
        }
        Err(anyhow!("no connected built-in panel"))
    }

    /// The framebuffer the panel scans out right now, as tightly packed RGBA
    /// rows: what the display controller sends to the screen. Reading another
    /// client's framebuffer needs root.
    pub fn capture(path: &str) -> Result<Canvas> {
        let card = open_card(path)?;
        let crtc = panel_crtc(&card)?;
        let fb = card
            .get_crtc(crtc)
            .context("read CRTC")?
            .framebuffer()
            .ok_or_else(|| anyhow!("nothing is scanned out"))?;
        let info = card.get_framebuffer(fb).context("read framebuffer")?;
        if info.bpp() != 32 {
            return Err(anyhow!(
                "framebuffer has {} bits per pixel, not 32",
                info.bpp()
            ));
        }
        let handle = info
            .buffer()
            .ok_or_else(|| anyhow!("no buffer handle for the framebuffer; capturing needs root"))?;
        let (w, h) = info.size();
        let pitch = info.pitch() as usize;
        let map = drm_ffi::mode::dumbbuffer::map(card.as_fd(), handle.into(), 0, 0)
            .context("map the framebuffer")?;
        let len = pitch * h as usize;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                card.as_fd().as_raw_fd(),
                map.offset as libc::off_t,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error()).context("mmap the framebuffer");
        }
        let src = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
        let mut c = Canvas::new(w, h);
        let row = w as usize * 4;
        for y in 0..h as usize {
            c.data[y * row..(y + 1) * row].copy_from_slice(&src[y * pitch..y * pitch + row]);
        }
        unsafe { libc::munmap(ptr, len) };
        Ok(c)
    }

    /// Direct scanout on the built-in panel: its fastest mode on the CRTC
    /// driving it, three dumb buffers taken in turn on its primary planes,
    /// and every other connector and plane taken off that CRTC.
    pub struct KmsSurface {
        card: Card,
        bufs: [Buf; 3],
        /// The buffer the next frame goes into.
        back: usize,
        /// A frame was committed whose flip has not come yet.
        flipping: bool,
        /// The planes showing the buffer, one per layer mixer, with their
        /// FB_ID properties.
        planes: Vec<(plane::Handle, property::Handle)>,
        /// The CRTC driving the panel, with its ACTIVE and MODE_ID
        /// properties.
        crtc: drm::control::crtc::Handle,
        active: property::Handle,
        mode_id: property::Handle,
        /// The panel's preferred mode, which it comes up in, and its
        /// fastest, which it switches to after, where that is another.
        preferred: property::Value<'static>,
        fastest: Option<property::Value<'static>>,
        /// The sub-pixel rendering setup the CRTC takes with each mode,
        /// where the panel leaves its sub-pixel rendering to the display.
        spr: Option<(property::Handle, property::Value<'static>)>,
        /// The panel's connector, with its low-power switch where the
        /// display driver has one, and the switch's values for running and
        /// for resting.
        conn: connector::Handle,
        lp: Option<(property::Handle, u64, u64)>,
        power: Power,
        /// The display came on again in the panel's preferred mode, and the
        /// panel has yet to switch to its fastest.
        slow: bool,
        w: u32,
        h: u32,
        order: Order,
        summary: String,
    }

    impl KmsSurface {
        pub fn open(path: &str) -> Result<Self> {
            let card = open_card(path)?;
            let res = card.resource_handles().context("read KMS resources")?;

            let mut panel = None;
            for &h in res.connectors() {
                let info = card.get_connector(h, true).context("read connector")?;
                if is_panel(info.interface()) && info.state() == connector::State::Connected {
                    panel = Some(info);
                    break;
                }
            }
            let conn = panel.ok_or_else(|| anyhow!("no connected built-in panel"))?;
            let preferred = conn
                .modes()
                .iter()
                .find(|m| m.mode_type().contains(ModeTypeFlags::PREFERRED))
                .ok_or_else(|| anyhow!("the panel reports no preferred mode"))?;
            // The fastest refresh at the preferred size, the first listed among
            // equals: Android scrolls at it, and the 13 Ultra's touch reports
            // come at the same 120 Hz.
            let mode = *conn
                .modes()
                .iter()
                .filter(|m| m.size() == preferred.size())
                .rev()
                .max_by_key(|m| m.vrefresh())
                .expect("the preferred mode itself has the preferred size");
            let (w, h) = (mode.size().0 as u32, mode.size().1 as u32);

            // The CRTC already driving the panel, or the first one an
            // encoder of this connector can drive.
            let current = match conn.current_encoder() {
                Some(e) => card.get_encoder(e).context("read encoder")?.crtc(),
                None => None,
            };
            let crtc = match current {
                Some(c) => c,
                None => {
                    let mut found = None;
                    for &e in conn.encoders() {
                        let enc = card.get_encoder(e).context("read encoder")?;
                        if let Some(&c) = res.filter_crtcs(enc.possible_crtcs()).first() {
                            found = Some(c);
                            break;
                        }
                    }
                    found.ok_or_else(|| anyhow!("no CRTC can drive the panel"))?
                }
            };

            // Qualcomm's display driver blends a mode on one or more layer
            // mixers, each owning a vertical strip of the screen; the 13
            // Ultra's dual-pipe topology has two. The pipeline is set up the
            // way Android's compositor sets it up: one plane per mixer
            // covering its strip, the mode's DSC variant selected, and frame
            // starts posted to the hardware. With one plane across both
            // mixers, no DSC selection and the default trigger, the 13
            // Ultra's panel tore while scrolling.
            let conn_props = Props::read(&card, conn.handle())?;
            let layout = match conn_props.get("mode_properties") {
                Ok((_, blob)) => {
                    let text = card
                        .get_property_blob(blob)
                        .context("read mode_properties")?;
                    SdeMode::find(
                        &String::from_utf8_lossy(&text),
                        &mode.name().to_string_lossy(),
                    )?
                }
                Err(_) => SdeMode {
                    mixers: 1,
                    dsc: false,
                },
            };
            let strips = layout.mixers as usize;
            if w % layout.mixers != 0 {
                return Err(anyhow!("{w} pixels do not split into {strips} strips"));
            }

            // Primary planes that can drive the CRTC, those already on it
            // first so the boot splash's planes are reused; planes on the
            // CRTC that are not used are switched off.
            let mut candidates: Vec<(plane::Handle, Vec<u32>, Props, bool)> = Vec::new();
            let mut attached = Vec::new();
            for p in card.plane_handles().context("list planes")? {
                let info = card.get_plane(p).context("read plane")?;
                let props = Props::read(&card, p)?;
                let on_crtc = info.crtc() == Some(crtc);
                if on_crtc {
                    attached.push(p);
                }
                if props.value("type")? == PlaneType::Primary as u64
                    && res.filter_crtcs(info.possible_crtcs()).contains(&crtc)
                {
                    candidates.push((p, info.formats().to_vec(), props, on_crtc));
                }
            }
            candidates.sort_by_key(|c| !c.3);
            if candidates.len() < strips {
                return Err(anyhow!(
                    "{strips} primary planes needed, {} can drive the CRTC",
                    candidates.len()
                ));
            }
            candidates.truncate(strips);

            let pick = [
                (DrmFourcc::Xbgr8888, Order::Rgba),
                (DrmFourcc::Abgr8888, Order::Rgba),
                (DrmFourcc::Xrgb8888, Order::Bgra),
                (DrmFourcc::Argb8888, Order::Bgra),
            ];
            let (fourcc, order) = pick
                .into_iter()
                .find(|(f, _)| candidates.iter().all(|c| c.1.contains(&(*f as u32))))
                .ok_or_else(|| {
                    anyhow!("the primary planes share none of the 32-bit RGB formats")
                })?;

            let make = || -> Result<Buf> {
                let db = card
                    .create_dumb_buffer((w, h), fourcc, 32)
                    .context("create dumb buffer")?;
                let fb = card
                    .add_planar_framebuffer(&Planar(&db), FbCmd2Flags::empty())
                    .context("add framebuffer")?;
                let len = buffer::Buffer::pitch(&db) as usize * h as usize;
                let offset = drm_ffi::mode::dumbbuffer::map(
                    card.as_fd(),
                    buffer::Buffer::handle(&db).into(),
                    0,
                    0,
                )
                .context("map dumb buffer")?
                .offset;
                let fd = card.as_fd().as_raw_fd();
                let map = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        fd,
                        offset as libc::off_t,
                    )
                };
                if map == libc::MAP_FAILED {
                    return Err(std::io::Error::last_os_error()).context("mmap dumb buffer");
                }
                Ok(Buf {
                    db,
                    fb,
                    map: map.cast(),
                    len,
                })
            };
            let bufs = [make()?, make()?, make()?];

            let crtc_id = u64::from(u32::from(crtc));
            let mut req = atomic::AtomicModeReq::new();
            for &other in res.connectors().iter().filter(|&&c| c != conn.handle()) {
                let props = Props::read(&card, other)?;
                if props.value("CRTC_ID")? == crtc_id {
                    req.add_property(other, props.handle("CRTC_ID")?, property::Value::CRTC(None));
                }
            }
            let crtc_props = Props::read(&card, crtc)?;
            let blob = card
                .create_property_blob(&mode)
                .context("create mode blob")?;
            let first = card
                .create_property_blob(preferred)
                .context("create mode blob")?;
            req.add_property(
                conn.handle(),
                conn_props.handle("CRTC_ID")?,
                property::Value::CRTC(Some(crtc)),
            );
            // The mode is DSC-compressed: select its DSC variant, as Android's
            // compositor does.
            if layout.dsc {
                let (id, _) = conn_props.get("dsc_mode")?;
                req.add_property(
                    conn.handle(),
                    id,
                    property::Value::UnsignedRange(enum_value(&card, id, "dsc_enabled")?),
                );
            }
            // Frame starts are posted to the hardware: the driver's own
            // default on display hardware of this generation, and Android's
            // compositor sets the same.
            if let Ok((id, _)) = conn_props.get("frame_trigger_mode") {
                req.add_property(
                    conn.handle(),
                    id,
                    property::Value::UnsignedRange(enum_value(&card, id, "posted_start")?),
                );
            }
            let (mode_id, active) = (crtc_props.handle("MODE_ID")?, crtc_props.handle("ACTIVE")?);
            req.add_property(crtc, mode_id, first);
            req.add_property(crtc, active, property::Value::Boolean(true));
            // A panel whose sub-pixel rendering is the display processor's
            // has it set up with each mode set: this one, the switch to the
            // fastest refresh, and each time the display comes on again.
            let spr = match conn_props.get("capabilities") {
                Ok((_, caps)) => {
                    let text = card.get_property_blob(caps).context("read capabilities")?;
                    match spr::pack_type(&String::from_utf8_lossy(&text)) {
                        Some(pack_type) => {
                            let name = ["SDE_SPR_INIT_CFG_V2", "SDE_SPR_INIT_CFG_V1"]
                                .into_iter()
                                .find(|name| crtc_props.get(name).is_ok())
                                .ok_or_else(|| anyhow!("the panel leaves its {pack_type} sub-pixel rendering to a CRTC that takes no setup for it"))?;
                            let setup = card
                                .create_property_blob(spr::setup(pack_type, name)?.as_slice())
                                .context("create sub-pixel rendering blob")?;
                            Some((crtc_props.handle(name)?, setup, name))
                        }
                        None => None,
                    }
                }
                Err(_) => None,
            };
            if let Some((id, setup, _)) = spr {
                req.add_property(crtc, id, setup);
            }
            for &other in attached
                .iter()
                .filter(|&&p| !candidates.iter().any(|c| c.0 == p))
            {
                let props = Props::read(&card, other)?;
                req.add_property(
                    other,
                    props.handle("FB_ID")?,
                    property::Value::Framebuffer(None),
                );
                req.add_property(other, props.handle("CRTC_ID")?, property::Value::CRTC(None));
            }
            let strip = w / layout.mixers;
            let mut planes = Vec::new();
            for (i, (plane, _, props, _)) in candidates.iter().enumerate() {
                let x = strip * i as u32;
                let fb_prop = props.handle("FB_ID")?;
                req.add_property(
                    *plane,
                    fb_prop,
                    property::Value::Framebuffer(Some(bufs[0].fb)),
                );
                req.add_property(
                    *plane,
                    props.handle("CRTC_ID")?,
                    property::Value::CRTC(Some(crtc)),
                );
                req.add_property(
                    *plane,
                    props.handle("SRC_X")?,
                    property::Value::UnsignedRange((x as u64) << 16),
                );
                req.add_property(
                    *plane,
                    props.handle("SRC_Y")?,
                    property::Value::UnsignedRange(0),
                );
                req.add_property(
                    *plane,
                    props.handle("SRC_W")?,
                    property::Value::UnsignedRange((strip as u64) << 16),
                );
                req.add_property(
                    *plane,
                    props.handle("SRC_H")?,
                    property::Value::UnsignedRange((h as u64) << 16),
                );
                req.add_property(
                    *plane,
                    props.handle("CRTC_X")?,
                    property::Value::SignedRange(x as i64),
                );
                req.add_property(
                    *plane,
                    props.handle("CRTC_Y")?,
                    property::Value::SignedRange(0),
                );
                req.add_property(
                    *plane,
                    props.handle("CRTC_W")?,
                    property::Value::UnsignedRange(strip as u64),
                );
                req.add_property(
                    *plane,
                    props.handle("CRTC_H")?,
                    property::Value::UnsignedRange(h as u64),
                );
                planes.push((*plane, fb_prop));
            }
            // The panel comes up in its preferred mode, then switches to the
            // fastest, as `to_fastest` says why.
            commit(&card, req, AtomicCommitFlags::ALLOW_MODESET).context("set the panel mode")?;
            let fastest = (mode.vrefresh() != preferred.vrefresh()).then_some(blob);

            let ids: Vec<u32> = planes.iter().map(|p| u32::from(p.0)).collect();
            let summary = format!(
                "{:?} connector {} mode {:?} {w}x{h} {} Hz, crtc {}, planes {ids:?} {:?}{}",
                conn.interface(),
                u32::from(conn.handle()),
                mode.name(),
                mode.vrefresh(),
                u32::from(crtc),
                fourcc,
                spr.as_ref()
                    .map(|(_, _, name)| format!(", sub-pixel rendering through {name}"))
                    .unwrap_or_default()
            );
            let spr = spr.map(|(id, setup, _)| (id, setup));
            let lp = match conn_props.get("LP") {
                Ok((id, _)) => Some((
                    id,
                    enum_value(&card, id, "ON")?,
                    enum_value(&card, id, "LP2")?,
                )),
                Err(_) => None,
            };
            let conn = conn.handle();
            let s = KmsSurface {
                card,
                bufs,
                back: 1,
                flipping: false,
                planes,
                crtc,
                active,
                mode_id,
                preferred: first,
                fastest,
                spr,
                conn,
                lp,
                power: Power::On,
                slow: false,
                w,
                h,
                order,
                summary,
            };
            s.to_fastest()?;
            Ok(s)
        }

        pub fn describe(&self) -> &str {
            &self.summary
        }

        pub fn is_on(&self) -> bool {
            self.power == Power::On
        }

        pub fn is_off(&self) -> bool {
            self.power == Power::Off
        }

        /// Let the panel rest, ready to light again at once: in its
        /// low-power mode, as Android rests it while dozing, with the
        /// display processor stopped. The 13 Ultra's lights from there in
        /// 13 ms, where coming on from off takes 158, most of it the panel
        /// waiting 120 ms after leaving sleep as its own commands say.
        /// Where the display driver has no low-power mode, the display
        /// turns off. A touch controller that follows the panel, as
        /// Xiaomi's do, rests with it either way.
        pub fn rest(&mut self) -> Result<()> {
            if self.power != Power::On {
                return Ok(());
            }
            let Some((id, _, rest)) = self.lp else {
                return self.turn_off();
            };
            self.settle()?;
            let mut req = atomic::AtomicModeReq::new();
            req.add_property(self.conn, id, property::Value::UnsignedRange(rest));
            self.card
                .atomic_commit(AtomicCommitFlags::empty(), req)
                .context("rest the panel")?;
            self.power = Power::Resting;
            Ok(())
        }

        /// Turn the display off: the panel and the display processor feeding
        /// it stop drawing power. The next frame presented turns it on
        /// again.
        pub fn turn_off(&mut self) -> Result<()> {
            if self.power == Power::Off {
                return Ok(());
            }
            self.settle()?;
            let mut req = atomic::AtomicModeReq::new();
            req.add_property(self.crtc, self.active, property::Value::Boolean(false));
            // Qualcomm's display driver sends no event for a commit that
            // turns its CRTC off, so this one is made to return once it is
            // done.
            self.card
                .atomic_commit(AtomicCommitFlags::ALLOW_MODESET, req)
                .context("turn the display off")?;
            self.power = Power::Off;
            Ok(())
        }

        /// Switch a panel that came on again in its preferred mode to its
        /// fastest. It is called once the backlight is on, which need not
        /// wait the frames the switch takes.
        pub fn speed_up(&mut self) -> Result<()> {
            if self.slow {
                self.settle()?;
                self.to_fastest()?;
                self.slow = false;
            }
            Ok(())
        }

        /// The panel, up in its preferred mode, switched to its fastest.
        /// Powered up in the fast mode directly, the display controller runs
        /// at the fast rate but the panel keeps its own: the 13 Ultra's sends
        /// its TE at 60 Hz, and every frame waits two TEs. Switching a
        /// running panel sends it the commands for the new rate, as Android's
        /// switches do.
        fn to_fastest(&self) -> Result<()> {
            let Some(fastest) = self.fastest else {
                return Ok(());
            };
            let mut req = atomic::AtomicModeReq::new();
            req.add_property(self.crtc, self.mode_id, fastest);
            if let Some((id, setup)) = self.spr {
                req.add_property(self.crtc, id, setup);
            }
            commit(&self.card, req, AtomicCommitFlags::ALLOW_MODESET)
                .context("switch the panel to its fastest refresh")
        }
    }

    impl Drop for KmsSurface {
        fn drop(&mut self) {
            for buf in &self.bufs {
                unsafe { libc::munmap(buf.map.cast(), buf.len) };
            }
        }
    }

    impl Surface for KmsSurface {
        fn size(&self) -> (u32, u32) {
            (self.w, self.h)
        }

        /// A command-mode panel is sent a frame from one of its TE signals
        /// through most of the time to the next (6.8 of 8.3 ms on the 13
        /// Ultra at 120 Hz), and the frame's flip comes as the sending
        /// starts. A frame is committed the moment the flip of the one
        /// before comes, to be sent from the next TE, and drawn while that
        /// one is sent: into the buffer of the frame before both, which the
        /// panel finished reading before the frame now being sent started.
        /// A display turned off comes on again with the frame, in the
        /// panel's preferred mode, as it first came up.
        fn present(&mut self, canvas: &Canvas) -> Result<()> {
            if (canvas.w, canvas.h) != (self.w, self.h) {
                return Err(anyhow!(
                    "canvas {}x{} does not match the display {}x{}",
                    canvas.w,
                    canvas.h,
                    self.w,
                    self.h
                ));
            }
            let order = self.order;
            let buf = &self.bufs[self.back];
            let pitch = buffer::Buffer::pitch(&buf.db) as usize;
            let row = self.w as usize * 4;
            let dst = unsafe { std::slice::from_raw_parts_mut(buf.map, buf.len) };
            for y in 0..self.h as usize {
                let src = &canvas.data[y * row..(y + 1) * row];
                let out = &mut dst[y * pitch..y * pitch + row];
                match order {
                    Order::Rgba => out.copy_from_slice(src),
                    Order::Bgra => {
                        for (o, s) in out
                            .as_chunks_mut::<4>()
                            .0
                            .iter_mut()
                            .zip(src.as_chunks::<4>().0)
                        {
                            *o = [s[2], s[1], s[0], s[3]];
                        }
                    }
                }
            }
            let mut req = atomic::AtomicModeReq::new();
            for &(plane, fb_prop) in &self.planes {
                req.add_property(plane, fb_prop, property::Value::Framebuffer(Some(buf.fb)));
            }
            let mut flags = AtomicCommitFlags::NONBLOCK | AtomicCommitFlags::PAGE_FLIP_EVENT;
            if self.power != Power::On {
                // The panel runs again, and coming on from off it would
                // otherwise rest again as it last did.
                if let Some((id, run, _)) = self.lp {
                    req.add_property(self.conn, id, property::Value::UnsignedRange(run));
                }
            }
            if self.power == Power::Off {
                req.add_property(self.crtc, self.active, property::Value::Boolean(true));
                req.add_property(self.crtc, self.mode_id, self.preferred);
                if let Some((id, setup)) = self.spr {
                    req.add_property(self.crtc, id, setup);
                }
                flags |= AtomicCommitFlags::ALLOW_MODESET;
            }
            self.settle()?;
            self.card
                .atomic_commit(flags, req)
                .context(if self.power == Power::On {
                    "flip"
                } else {
                    "turn the display on"
                })?;
            if self.power == Power::Off {
                self.slow = self.fastest.is_some();
            }
            self.power = Power::On;
            self.flipping = true;
            self.back = (self.back + 1) % self.bufs.len();
            Ok(())
        }

        fn settle(&mut self) -> Result<()> {
            if self.flipping {
                flipped(&self.card).context("flip")?;
                self.flipping = false;
            }
            Ok(())
        }
    }
}

/// The panel as the older Qualcomm kernels leave it lit: an fbdev, whose
/// buffer is mapped once and whose two pages are pointed at in turn.
///
/// `libc` carries none of the framebuffer's own types, so `Var` and `Fix`
/// below are this file's claim about the kernel's `fb.h`. It is checked as
/// the device opens: a field put in the wrong place reads back sizes that
/// cannot be true of a panel, and the checks there refuse the device.
#[cfg(target_os = "android")]
pub mod fb {
    use super::Canvas;
    use super::Power;
    use super::Surface;
    use anyhow::{anyhow, bail, ensure, Context, Result};
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::path::{Path, PathBuf};

    /// The ioctls of the kernel's `fb.h`, numbered as it numbers them.
    const GET_VSCREENINFO: libc::c_int = 0x4600;
    const GET_FSCREENINFO: libc::c_int = 0x4602;
    const PUT_VSCREENINFO: libc::c_int = 0x4601;
    /// Ask about the panel's power. Its argument is the blank mode itself and
    /// not a pointer, so it is not asked for through [`ioctl`].
    const BLANK: libc::c_int = 0x4611;
    const BLANK_UNBLANK: usize = 0;
    const BLANK_POWERDOWN: usize = 4;

    /// How the buffer's bytes stand against the canvas's RGBA.
    #[derive(Clone, Copy, Debug)]
    enum Order {
        Rgba,
        Bgra,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Bitfield {
        offset: u32,
        length: u32,
        msb_first: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Var {
        xres: u32,
        yres: u32,
        xres_virtual: u32,
        yres_virtual: u32,
        xoffset: u32,
        yoffset: u32,
        bits_per_pixel: u32,
        grayscale: u32,
        red: Bitfield,
        green: Bitfield,
        blue: Bitfield,
        transp: Bitfield,
        nonstd: u32,
        activate: u32,
        height: u32,
        width: u32,
        accel_flags: u32,
        pixclock: u32,
        left_margin: u32,
        right_margin: u32,
        upper_margin: u32,
        lower_margin: u32,
        hsync_len: u32,
        vsync_len: u32,
        sync: u32,
        vmode: u32,
        rotate: u32,
        colorspace: u32,
        reserved: [u32; 4],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Fix {
        id: [u8; 16],
        smem_start: usize,
        smem_len: u32,
        type_: u32,
        type_aux: u32,
        visual: u32,
        xpanstep: u16,
        ypanstep: u16,
        ywrapstep: u16,
        /// Where a row begins, which the kernel pads out past the pixels.
        line_length: u32,
        mmio_start: usize,
        mmio_len: u32,
        accel: u32,
        capabilities: u16,
        reserved: [u16; 2],
    }

    fn ioctl<T>(fd: libc::c_int, request: libc::c_int, arg: &mut T) -> Result<()> {
        let r = unsafe { libc::ioctl(fd, request, arg as *mut T) };
        ensure!(r == 0, "{}", std::io::Error::last_os_error());
        Ok(())
    }

    fn ioctl_int(fd: libc::c_int, request: libc::c_int, value: usize) -> std::io::Result<()> {
        let r = unsafe { libc::ioctl(fd, request, value) };
        if r == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// How many blanks in a row a screen may fail to give before its frames
    /// stop being waited for.
    const BLANKS_MISSED: u8 = 3;

    pub struct FbSurface {
        file: std::fs::File,        map: *mut u8,
        len: usize,
        var: Var,
        w: u32,
        h: u32,
        /// Bytes from one row of the buffer to the next, which the virtual
        /// width sets, and pages of `h` rows the buffer holds.
        pitch: usize,
        pages: u32,
        /// The page the next frame goes into, and whether a pan is owed.
        back: u32,
        flipping: bool,
        order: Order,
        /// Where the kernel tells this fbdev's vertical blank, when it does.
        vsync: Option<PathBuf>,
        /// Which flip the kernel took has been told about once already.
        told: bool,
        /// Whether the visible page can be moved at all. A driver with no pan
        /// step has no flip to answer, only a buffer to be drawn into.
        flip: bool,
        /// Frames shown, so that the driver's count of what it transmitted
        /// is read once there are enough of them to mean something.
        frames: u32,
        /// Where the driver tells the panel's own power, if it tells it.
        lit_at: Option<PathBuf>,
        /// Whether the blank that shows a frame has failed to come since the
        /// screen was last set up, and that has been said.
        blank_told: bool,
        /// How many blanks in a row have failed to come. A screen whose
        /// blanks have stopped is one where every frame costs the whole wait,
        /// which is a screen that reads as broken rather than slow.
        blank_missed: u8,
        /// Whether the panel is lit, resting with the backlight down, or
        /// blanked.
        power: Power,
        summary: String,
    }

    impl FbSurface {
        pub fn open(path: &str) -> Result<Self> {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .with_context(|| format!("open {path}"))?;
            let fd = file.as_raw_fd();
            let mut var: Var = unsafe { std::mem::zeroed() };
            ioctl(fd, GET_VSCREENINFO, &mut var)
                .with_context(|| format!("{path}: read its mode"))?;
            let mut fix: Fix = unsafe { std::mem::zeroed() };
            ioctl(fd, GET_FSCREENINFO, &mut fix)
                .with_context(|| format!("{path}: read its layout"))?;

            // The two structs above describe the kernel's by claim, not by
            // construction, so the mode is refused unless what they read back
            // can only be a panel this surface could draw on: the red, green
            // and blue fields of an eight-bit-per-component 32-bit mode lie
            // within it, and one row of the buffer is as wide as the virtual
            // mode asked for.
            ensure!(
                var.bits_per_pixel == 32,
                "{} gives {} bits per pixel, and this surface draws 32",
                path,
                var.bits_per_pixel
            );
            for (name, field) in [
                ("red", &var.red),
                ("green", &var.green),
                ("blue", &var.blue),
            ] {
                ensure!(
                    field.length == 8 && field.offset + field.length <= 32,
                    "{}: {} occupies {} bits at {}, which is not an eight-bit component of a 32-bit pixel",
                    path,
                    name,
                    field.length,
                    field.offset
                );
            }
            let row = fix.line_length as usize;
            ensure!(
                row >= var.xres_virtual as usize * 4,
                "{}: {} pixels wide need {} bytes in a row, where the buffer gives {}",
                path,
                var.xres_virtual,
                var.xres_virtual as usize * 4,
                row
            );
            let (w, h) = (var.xres, var.yres);
            ensure!(w != 0 && h != 0, "{path} reports no mode");
            ensure!(
                var.yres_virtual >= h && var.yres_virtual.is_multiple_of(h),
                "{} holds {} rows, which is not whole pages of {}",
                path,
                var.yres_virtual,
                h
            );
            let pages = var.yres_virtual / h;
            ensure!(
                pages >= 2,
                "{} holds one page of {}; a frame would be drawn over the one showing",
                path,
                h
            );

            let needed = var.yres_virtual as usize * row;
            ensure!(
                fix.smem_len as usize >= needed,
                "{} maps {} bytes, which is not the {} it needs for {} pages of {}",
                path,
                fix.smem_len,
                needed,
                pages,
                h
            );
            let len = fix.smem_len as usize;
            let map = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            ensure!(
                map != libc::MAP_FAILED,
                "mmap {}: {}",
                path,
                std::io::Error::last_os_error()
            );

            // An RGB32 mode lays its pixels out as blue first in memory, so
            // the canvas's red and blue are put across; one whose red sits at
            // byte zero needs nothing done to it.
            let order = match (var.red.offset, var.blue.offset) {
                (0, 16) => Order::Rgba,
                (16, 0) => Order::Bgra,
                (r, b) => bail!(
                    "{} puts red at {} and blue at {}, which this surface does not know",
                    path,
                    r,
                    b
                ),
            };
            let name = Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let vsync = [
                format!("/sys/class/graphics/{name}/vsync_event"),
                "/sys/class/graphics/fb0/vsync_event".to_string(),
            ]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.exists());
            let lit_at = [
                format!("/sys/class/graphics/{name}/show_blank_event"),
                "/sys/class/graphics/fb0/show_blank_event".to_string(),
            ]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.exists());
            let summary = format!(
                "{path} {}x{} of {}x{}, {}, {}, panstep {} {} {}, mode {} layout {} bytes, flipping {}",
                w,
                h,
                var.xres_virtual,
                var.yres_virtual,
                String::from_utf8_lossy(&fix.id).trim_end_matches('\0'),
                if matches!(order, Order::Rgba) { "RGBA" } else { "BGRA" },
                fix.xpanstep,
                fix.ypanstep,
                fix.ywrapstep,
                std::mem::size_of::<Var>(),
                std::mem::size_of::<Fix>(),
                if vsync.is_some() { "at the blank" } else { "at once" }
            );
            Ok(FbSurface {
                file,
                map: map.cast(),
                len,
                var,
                w,
                h,
                pitch: row,
                pages,
                back: 1 % pages,
                flipping: false,
                order,
                vsync,
                told: false,
                flip: pages >= 2,
                frames: 0,
                lit_at,
                blank_told: false,
                blank_missed: 0,
                power: Power::On,
                summary,
            })
        }

        pub fn describe(&self) -> &str {
            &self.summary
        }

        pub fn is_on(&self) -> bool {
            self.power == Power::On
        }

        pub fn is_off(&self) -> bool {
            self.power == Power::Off
        }

        /// Let the panel rest: the backlight is already down and the page
        /// showing is black, so a driver with no low-power mode of its own
        /// leaves the panel as it is until the display turns off.
        pub fn rest(&mut self) -> Result<()> {
            if self.power != Power::On {
                return Ok(());
            }
            self.power = Power::Resting;
            Ok(())
        }

        /// Turn the display off: the panel stops scanning, and the display
        /// engine with it. The next frame presented powers it again.
        pub fn turn_off(&mut self) -> Result<()> {
            if self.power == Power::Off {
                return Ok(());
            }
            self.settle()?;
            let r = ioctl_int(self.file.as_raw_fd(), BLANK, BLANK_POWERDOWN);
            eprintln!("turn the display off: {r:?}");
            r.context("turn the display off")?;
            self.power = Power::Off;
            Ok(())
        }

        /// A panel with one mode needs no switch once it is lit again.
        pub fn speed_up(&mut self) -> Result<()> {
            Ok(())
        }

        /// Power the panel back up after the display turned off — **the whole
        /// of what taking it over does**, not the power cycle alone.
        ///
        /// A blanked driver may forget the virtual height it was given and
        /// hand back a buffer of its own choosing, and this surface would go
        /// on writing the page count it remembered into a mapping it no
        /// longer owns. Every flip after that is then a mode change rather
        /// than a page being named, and a frame that changes the mode costs
        /// many times one that does not: the screen goes from smooth to
        /// unusable after a single sleep and wake, which is what the Mi MIX 2
        /// does. The Mi 6's driver keeps both across a blank, which is why
        /// the power cycle alone was enough there and this never showed.
        fn wake(&mut self) {
            // What the driver has now is what the takeover has to ask from.
            let fd = self.file.as_raw_fd();
            let mut var: Var = unsafe { std::mem::zeroed() };
            if ioctl(fd, GET_VSCREENINFO, &mut var).is_ok() {
                self.var = var;
            }
            self.take_over("after it was turned off");
        }

        /// Make the panel look at the memory the driver owns, the way the
        /// recovery that works on this phone does it: a mode write that really
        /// changes something, the panel powered down and back up, and then the
        /// mapping remade on whatever the driver ended up owning. Before this,
        /// the display engine holds no buffer for the framebuffer at all, so
        /// nothing it could fetch however the page is asked for, and one
        /// unblank can be swallowed by the phone's own panel code while still
        /// answering success, so the cycle is repeated until the driver reports
        /// the panel lit. A failure here is told and not returned: a recovery
        /// that goes on drawing is worth more than no recovery.
        fn take_over(&mut self, why: &str) {
            let fd = self.file.as_raw_fd();
            // The number is what the working recovery asks for, not what it
            // gets back: the driver is free to widen a virtual height it
            // cannot show two pages in, and what matters is that the answer
            // differs from the mode as read, which is what takes the code past
            // the comparison that drops a mode write changing nothing.
            let mut ask = self.var;
            ask.yres_virtual = ask.yres * 2;
            ask.yoffset = 0;
            ask.bits_per_pixel = 32;
            let asked = ioctl(fd, PUT_VSCREENINFO, &mut ask);
            eprintln!(
                "ask the driver for {} rows of {} bits, activate as read {}: {asked:?}",
                ask.yres_virtual, ask.bits_per_pixel, ask.activate
            );
            for try_no in 1..=3 {
                let down = ioctl_int(fd, BLANK, BLANK_POWERDOWN);
                let up = ioctl_int(fd, BLANK, BLANK_UNBLANK);
                std::thread::sleep(std::time::Duration::from_millis(400));
                let now = self
                    .lit_at
                    .as_ref()
                    .and_then(|at| std::fs::read_to_string(at).ok())
                    .unwrap_or_default();
                eprintln!("take over the panel {why} ({try_no}): down {down:?} up {up:?}, lit reads {:?}", now.trim());
                if now.trim().ends_with('1') {
                    break;
                }
            }
            // The buffer the engine reads now is the one allocated during the
            // takeover, so the mapping made before it has to follow. Both
            // answers are read again and the screen they names is mapped; the
            // old mapping is only let go once the new one exists, so a step
            // that fails leaves the surface drawing where it was rather than
            // into memory the driver has handed back.
            let mut var: Var = unsafe { std::mem::zeroed() };
            let mut fix: Fix = unsafe { std::mem::zeroed() };
            let mode = ioctl(fd, GET_VSCREENINFO, &mut var);
            let layout = ioctl(fd, GET_FSCREENINFO, &mut fix);
            let row = fix.line_length as usize;
            let pages = var.yres_virtual.checked_div(var.yres).unwrap_or(0);
            let len = fix.smem_len as usize;
            let fresh = if mode.is_err() || layout.is_err() || pages == 0 || len == 0 {
                None
            } else {
                let map = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        fd,
                        0,
                    )
                };
                if map == libc::MAP_FAILED {
                    None
                } else {
                    Some(map)
                }
            };
            let Some(map) = fresh else {
                eprintln!("the screen could not be mapped after the takeover ({mode:?} {layout:?}, {len} bytes for {pages} pages); drawing goes on where it was");
                return;
            };
            unsafe { libc::munmap(self.map.cast(), self.len) };
            self.map = map.cast();
            unsafe { std::slice::from_raw_parts_mut(self.map, self.len).fill(0) };
            self.len = len;
            self.pitch = row;
            self.pages = pages;
            self.var = var;
            self.back = 0;
            self.flip = pages >= 2;
            // A blank that failed to come before the screen was set up may
            // come again now that it has been, so the next one is worth
            // saying too.
            self.blank_told = false;
            self.blank_missed = 0;
            eprintln!("mapped the screen the driver owns: {}x{} of {}x{}, row {row}, {pages} pages, {len} bytes, {}", var.xres, var.yres, var.xres_virtual, var.yres_virtual, if self.flip { "flipping between pages" } else { "drawing in the one page" });
        }
    }

    impl Drop for FbSurface {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.map.cast(), self.len) };
        }
    }

    impl Surface for FbSurface {
        fn size(&self) -> (u32, u32) {
            (self.w, self.h)
        }

        /// A frame is written into the page not showing and pointed at next,
        /// which the driver shows at the blank after the frame before it; the
        /// buffer is written through its mapping, so no copy is made of the
        /// frame as a whole.
        fn present(&mut self, canvas: &Canvas) -> Result<()> {
            if (canvas.w, canvas.h) != (self.w, self.h) {
                return Err(anyhow!(
                    "canvas {}x{} does not match the display {}x{}",
                    canvas.w,
                    canvas.h,
                    self.w,
                    self.h
                ));
            }
            if self.power == Power::Off {
                self.wake();
                self.power = Power::On;
            }
            self.settle()?;
            let row = self.w as usize * 4;
            let base = if self.flip {
                self.back as usize * self.h as usize * self.pitch
            } else {
                0
            };
            for y in 0..self.h as usize {
                let src = &canvas.data[y * row..(y + 1) * row];
                let out = unsafe {
                    std::slice::from_raw_parts_mut(self.map.add(base + y * self.pitch), row)
                };
                match self.order {
                    Order::Rgba => out.copy_from_slice(src),
                    Order::Bgra => {
                        for (o, s) in out
                            .as_chunks_mut::<4>()
                            .0
                            .iter_mut()
                            .zip(src.as_chunks::<4>().0)
                        {
                            *o = [s[2], s[1], s[0], s[3]];
                        }
                    }
                }
            }
            if !self.flip {
                return Ok(());
            }
            // The same three fields the recovery that works on this phone
            // writes on every flip, and nothing else: virtual rows for two
            // pages, the offset naming the page to show, and the depth the
            // surface draws in. `activate` is left exactly as the driver
            // reported it, because that flag decides how deep the kernel goes
            // with a mode, and the value read here is not one this surface
            // should be choosing; it was the reason my own writes counted
            // finished frames while the display engine still held no buffer.
            let mut v = self.var;
            v.yres_virtual = self.h * 2;
            v.yoffset = self.back * self.h;
            v.bits_per_pixel = 32;
            ioctl(self.file.as_raw_fd(), PUT_VSCREENINFO, &mut v).context("show the page")?;
            if !self.told {
                eprintln!(
                    "flipping with FBIOPUT_VSCREENINFO at the blank, page {} shown",
                    self.back
                );
                self.told = true;
                // A frame is in memory and pointed at now, so this is where the
                // boot loader's picture is replaced.
                self.take_over("after the first frame");
            }
            self.frames += 1;
            // The driver only recomputes its rate once a target number of
            // frames has passed, so an early reading of zero means nothing:
            // sample on both sides of that count.
            if self.frames == 30 || self.frames == 150 {
                // The driver's own count of frames it finished is the proof of
                // a flip that needs no eyes: zero here means the panel never
                // looked at the frame, whatever these calls answered.
                let fps = std::fs::read_to_string("/sys/class/graphics/fb0/measured_fps")
                    .unwrap_or_default()
                    .replace('\n', "");
                eprintln!("{fps} frames a second after {} of them", self.frames);
            }
            self.flipping = true;
            self.back = (self.back + 1) % self.pages;
            Ok(())
        }

        /// Wait for the blank that shows the frame pointed at last. The
        /// kernel's own `FBIOWAITRETRANSMIT` is not part of `fb.h` and so is
        /// not asked for here: where the driver gives a `vsync_event` file
        /// that can be waited on, that is waited on, and where it gives none
        /// the frame is taken to be shown, which costs a torn frame and
        /// nothing else.
        fn settle(&mut self) -> Result<()> {
            if !self.flipping {
                return Ok(());
            }
            self.flipping = false;
            let Some(at) = self.vsync.as_ref() else {
                return Ok(());
            };
            // **A screen whose blanks have stopped is not waited for any
            // more.** The wait exists to keep a frame from being shown half
            // written; it is worth a frame's time, not a tenth of a second
            // every time. Three in a row is a screen that is not blanking,
            // and from there the frame is taken to be shown when it is
            // written — the same as on a driver that offers no blanks at
            // all, and the tearing that costs is the whole of what is lost.
            if self.blank_missed >= BLANKS_MISSED {
                return Ok(());
            }
            let mut file =
                std::fs::File::open(at).with_context(|| format!("open {}", at.display()))?;
            let mut poll = [libc::pollfd {
                fd: file.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            }];
            let r = unsafe { libc::poll(poll.as_mut_ptr(), 1, 100) };
            if r > 0 {
                let mut blank = [0u8; 32];
                let _ = file.read(&mut blank);
                self.blank_missed = 0;
            } else {
                self.blank_missed = self.blank_missed.saturating_add(1);
                if !self.blank_told && self.blank_missed >= BLANKS_MISSED {
                    self.blank_told = true;
                    eprintln!(
                        "no blank came from {} in 100 ms, {BLANKS_MISSED} times over; frames are shown as they are written from here",
                        at.display()
                    );
                }
            }
            Ok(())
        }
    }
}

/// The screen to draw on: KMS where the kernel exposes it, as the phones
/// running Android 16 and 17 do, and the fbdev beside it where they do not,
/// as the older Qualcomm ones leave the panel lit.
#[cfg(target_os = "android")]
pub enum Display {
    Kms(kms::KmsSurface),
    Fb(fb::FbSurface),
}

#[cfg(target_os = "android")]
impl Display {
    pub fn open() -> Result<Display> {
        if std::path::Path::new("/dev/dri/card0").exists() {
            return Ok(Display::Kms(kms::KmsSurface::open("/dev/dri/card0")?));
        }
        for path in ["/dev/graphics/fb0", "/dev/fb0"] {
            if std::path::Path::new(path).exists() {
                return Ok(Display::Fb(fb::FbSurface::open(path)?));
            }
        }
        Err(anyhow::anyhow!(
            "there is no /dev/dri/card0 and no framebuffer device to draw on"
        ))
    }

    pub fn describe(&self) -> &str {
        match self {
            Display::Kms(s) => s.describe(),
            Display::Fb(s) => s.describe(),
        }
    }

    pub fn is_on(&self) -> bool {
        match self {
            Display::Kms(s) => s.is_on(),
            Display::Fb(s) => s.is_on(),
        }
    }

    pub fn is_off(&self) -> bool {
        match self {
            Display::Kms(s) => s.is_off(),
            Display::Fb(s) => s.is_off(),
        }
    }

    /// Let the panel rest, ready to light again at once, with the display
    /// processor stopped or the backlight down.
    pub fn rest(&mut self) -> Result<()> {
        match self {
            Display::Kms(s) => s.rest(),
            Display::Fb(s) => s.rest(),
        }
    }

    /// Turn the display off: the panel stops drawing power. The next frame
    /// presented turns it on again.
    pub fn turn_off(&mut self) -> Result<()> {
        match self {
            Display::Kms(s) => s.turn_off(),
            Display::Fb(s) => s.turn_off(),
        }
    }

    /// Switch a panel that came on again in its preferred mode to its
    /// fastest.
    pub fn speed_up(&mut self) -> Result<()> {
        match self {
            Display::Kms(s) => s.speed_up(),
            Display::Fb(s) => s.speed_up(),
        }
    }
}

#[cfg(target_os = "android")]
impl Surface for Display {
    fn size(&self) -> (u32, u32) {
        match self {
            Display::Kms(s) => s.size(),
            Display::Fb(s) => s.size(),
        }
    }

    fn present(&mut self, canvas: &Canvas) -> Result<()> {
        match self {
            Display::Kms(s) => s.present(canvas),
            Display::Fb(s) => s.present(canvas),
        }
    }

    fn settle(&mut self) -> Result<()> {
        match self {
            Display::Kms(s) => s.settle(),
            Display::Fb(s) => s.settle(),
        }
    }
}
