use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use skyward_ui::{Canvas, Fonts, Rgba};
use std::fs::File;
use std::path::Path;

/// Probe file for `--match`: text regions cut from a device screenshot.
#[derive(Deserialize)]
struct Probes {
    reference: String,
    /// Pixels per dp of the screenshot.
    px_per_dp: f32,
    probe: Vec<Probe>,
}

#[derive(Deserialize)]
struct Probe {
    text: String,
    /// x, y, w, h of a region holding only this text.
    crop: [u32; 4],
    bg: [u8; 3],
    ink: [u8; 3],
    /// Size range to search, in dp.
    size: [f32; 2],
}

/// Ink measured the same way on the screenshot and on candidates: coverage
/// normalised between background and ink colour, its total, and the box of
/// pixels at least half covered.
#[derive(Clone, Copy)]
struct Ink {
    total: f32,
    w: f32,
    h: f32,
}

fn luma(r: u8, g: u8, b: u8) -> f32 {
    0.299 * r as f32 + 0.587 * g as f32 + 0.114 * b as f32
}

fn measure(
    px: impl Fn(u32, u32) -> (u8, u8, u8),
    w: u32,
    h: u32,
    bg: [u8; 3],
    ink: [u8; 3],
) -> Ink {
    let (lb, li) = (luma(bg[0], bg[1], bg[2]), luma(ink[0], ink[1], ink[2]));
    let (mut total, mut x0, mut y0, mut x1, mut y1) = (0.0, u32::MAX, u32::MAX, 0, 0);
    for y in 0..h {
        for x in 0..w {
            let (r, g, b) = px(x, y);
            let c = ((lb - luma(r, g, b)) / (lb - li)).clamp(0.0, 1.0);
            total += c;
            if c >= 0.5 {
                (x0, y0, x1, y1) = (x0.min(x), y0.min(y), x1.max(x), y1.max(y));
            }
        }
    }
    let (w, h) = if x0 == u32::MAX {
        (0.0, 0.0)
    } else {
        ((x1 - x0 + 1) as f32, (y1 - y0 + 1) as f32)
    };
    Ink { total, w, h }
}

fn load_rgb(path: &Path) -> Result<(u32, u32, usize, Vec<u8>)> {
    let decoder =
        png::Decoder::new(File::open(path).with_context(|| format!("open {}", path.display()))?);
    let mut reader = decoder.read_info()?;
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf)?;
    if info.bit_depth != png::BitDepth::Eight {
        return Err(anyhow!("{}: expected 8-bit samples", path.display()));
    }
    Ok((info.width, info.height, info.color_type.samples(), buf))
}

/// For every probe, search size and weight so that rendered text matches the
/// screenshot's ink width, height and total coverage; print the best fits.
pub fn run(fonts: &Fonts, probes: &Path) -> Result<()> {
    let text =
        std::fs::read_to_string(probes).with_context(|| format!("read {}", probes.display()))?;
    let p: Probes = toml::from_str(&text).context("parse probes")?;
    let (rw, rh, ch, data) = load_rgb(Path::new(&p.reference))?;
    let weights: Vec<f32> = (0..=40).map(|i| 300.0 + 10.0 * i as f32).collect();
    let faces = weights
        .iter()
        .map(|&w| fonts.face(w))
        .collect::<Result<Vec<_>>>()?;
    let ruler = Canvas::new(1, 1);
    for pr in &p.probe {
        let [cx, cy, cw, chh] = pr.crop;
        if cx + cw > rw || cy + chh > rh {
            return Err(anyhow!("crop {:?} outside {}x{}", pr.crop, rw, rh));
        }
        let at = |x: u32, y: u32| {
            let i = (((cy + y) * rw + cx + x) as usize) * ch;
            (data[i], data[i + 1], data[i + 2])
        };
        let want = measure(at, cw, chh, pr.bg, pr.ink);
        let (bg, ink) = (
            Rgba::rgb(pr.bg[0], pr.bg[1], pr.bg[2]),
            Rgba::rgb(pr.ink[0], pr.ink[1], pr.ink[2]),
        );
        let mut fits = Vec::new();
        let steps = ((pr.size[1] - pr.size[0]) / 0.1).round() as i32;
        for s in 0..=steps {
            let dp = pr.size[0] + 0.1 * s as f32;
            let px = dp * p.px_per_dp;
            for (face, &wt) in faces.iter().zip(&weights) {
                let cw2 = (ruler.text_width(face, &pr.text, px) + px) as u32;
                let chh2 = (px * 2.0) as u32;
                let mut c = Canvas::new(cw2, chh2);
                c.clear(bg);
                c.text(face, &pr.text, px * 0.5, px * 1.4, px, ink, None);
                let got = measure(
                    |x, y| {
                        let i = ((y * cw2 + x) * 4) as usize;
                        (c.data[i], c.data[i + 1], c.data[i + 2])
                    },
                    cw2,
                    chh2,
                    pr.bg,
                    pr.ink,
                );
                let e = ((got.w - want.w) / want.w).powi(2)
                    + ((got.h - want.h) / want.h).powi(2)
                    + ((got.total - want.total) / want.total).powi(2);
                fits.push((e, dp, wt, got));
            }
        }
        fits.sort_by(|a, b| a.0.total_cmp(&b.0));
        println!(
            "{:<16} want {:>4}x{:<4} ink {:>7.0}",
            pr.text, want.w, want.h, want.total
        );
        for (e, dp, wt, got) in fits.iter().take(3) {
            println!(
                "    {dp:>5.1} dp  wght {wt:>3.0}   {:>4}x{:<4} ink {:>7.0}  err {:.5}",
                got.w, got.h, got.total, e
            );
        }
    }
    Ok(())
}
