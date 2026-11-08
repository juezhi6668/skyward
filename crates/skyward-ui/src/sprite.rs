use crate::canvas::Canvas;
use crate::color::Rgba;

/// Ink of one colour kept as coverage, 0 to 255 a pixel, so it can be laid
/// over the screen faded, blurred or shrunk: the titles that dissolve as
/// they leave.
#[derive(Clone, Debug, PartialEq)]
pub struct Sprite {
    pub w: u32,
    pub h: u32,
    pub cov: Vec<u8>,
    /// Where its top-left corner sits, in the coordinates it was drawn in;
    /// always on whole pixels.
    pub x: f32,
    pub y: f32,
}

impl Sprite {
    /// What `draw` inks on a `w`×`h` canvas whose top-left corner is at
    /// (`x`, `y`), taken down to whole pixels; `draw` works in those outer
    /// coordinates, offset by the two numbers it is given.
    pub fn capture(
        x: f32,
        y: f32,
        w: u32,
        h: u32,
        draw: impl FnOnce(&mut Canvas, f32, f32),
    ) -> Sprite {
        let (x, y) = (x.floor(), y.floor());
        let mut c = Canvas::new(w, h);
        draw(&mut c, -x, -y);
        let cov = c.data.as_chunks::<4>().0.iter().map(|p| p[3]).collect();
        Sprite { w, h, cov, x, y }
    }

    /// The sprite blurred by about `radius` pixels: three box passes each
    /// way, together close to a Gaussian of half that deviation. Each box
    /// takes the mean of `2 half + 1` pixels, rounded, beyond the edges
    /// counting as empty; the means of every sum are worked out once, and
    /// the passes down the sprite run along whole rows at a time.
    pub fn blurred(&self, radius: f32) -> Sprite {
        let half = (radius / 2.0).round() as usize;
        if half == 0 {
            return self.clone();
        }
        let (w, h) = (self.w as usize, self.h as usize);
        let width = 2 * half + 1;
        let mean: Vec<u8> = (0..=255 * width)
            .map(|s| ((s + width / 2) / width) as u8)
            .collect();
        let mut a = self.cov.clone();
        let mut b = vec![0u8; a.len()];
        let mut sums = vec![0u32; w];
        for _ in 0..3 {
            // Along each row.
            for (src, dst) in a.chunks_exact(w).zip(b.chunks_exact_mut(w)) {
                let at = |i: usize| src.get(i).map_or(0, |&v| v as u32);
                let mut sum: u32 = (0..=half).map(at).sum();
                for (i, d) in dst.iter_mut().enumerate() {
                    *d = mean[sum as usize];
                    sum = sum + at(i + half + 1) - i.checked_sub(half).map_or(0, at);
                }
            }
            // Down each column: a running sum per column, moved down a row
            // at a time.
            sums.fill(0);
            for row in b.chunks_exact(w).take(half + 1) {
                sums.iter_mut().zip(row).for_each(|(s, &v)| *s += v as u32);
            }
            for y in 0..h {
                a[y * w..(y + 1) * w]
                    .iter_mut()
                    .zip(&sums)
                    .for_each(|(d, &s)| *d = mean[s as usize]);
                if let Some(row) = b.get((y + half + 1) * w..(y + half + 2) * w) {
                    sums.iter_mut().zip(row).for_each(|(s, &v)| *s += v as u32);
                }
                if let Some(up) = y.checked_sub(half) {
                    sums.iter_mut()
                        .zip(&b[up * w..(up + 1) * w])
                        .for_each(|(s, &v)| *s -= v as u32);
                }
            }
        }
        Sprite { cov: a, ..*self }
    }

    /// Lay the sprite moved by (`dx`, `dy`), rounded to whole pixels, in
    /// `color` at `alpha` of its strength, over an opaque canvas.
    pub fn draw(&self, c: &mut Canvas, dx: f32, dy: f32, color: Rgba, alpha: f32) {
        assert!(
            c.whole(),
            "a sprite is drawn on a canvas holding all its rows"
        );
        if alpha <= 0.0 {
            return;
        }
        let (ox, oy) = ((self.x + dx).round() as i32, (self.y + dy).round() as i32);
        let (w, cw) = (self.w as i32, c.w as i32);
        // Strength 0 to 256, so mixing divides by a shift.
        let strength = (alpha * color.a as f32 / 255.0 * 256.0).round() as u32;
        let ink = [color.r as u32, color.g as u32, color.b as u32];
        let (x0, x1) = ((-ox).max(0), (cw - ox).min(w));
        for sy in 0..self.h as i32 {
            let py = oy + sy;
            if py < 0 || py >= c.h as i32 || x0 >= x1 {
                continue;
            }
            let src = &self.cov[(sy * w + x0) as usize..(sy * w + x1) as usize];
            let start = ((py * cw + ox + x0) * 4) as usize;
            let dst = &mut c.data[start..start + src.len() * 4];
            for (&cov, px) in src.iter().zip(dst.as_chunks_mut::<4>().0) {
                if cov == 0 {
                    continue;
                }
                let cov = cov as u32 + (cov as u32 >> 7);
                let k = (cov * strength) >> 8;
                for ch in 0..3 {
                    px[ch] = ((ink[ch] * k + px[ch] as u32 * (256 - k) + 128) >> 8) as u8;
                }
            }
        }
    }

    /// The sprite shrunk or grown by `scale` about its centre, moved by
    /// (`dx`, `dy`), in `color` at `alpha` of its strength, over an opaque
    /// canvas.
    pub fn draw_scaled(
        &self,
        c: &mut Canvas,
        dx: f32,
        dy: f32,
        scale: f32,
        color: Rgba,
        alpha: f32,
    ) {
        if scale == 1.0 {
            self.draw(c, dx, dy, color, alpha);
            return;
        }
        assert!(
            c.whole(),
            "a sprite is drawn on a canvas holding all its rows"
        );
        let Some((x0, y0, x1, y1)) = self.bounds(dx, dy, scale, c.w as usize, c.h as usize) else {
            return;
        };
        if alpha <= 0.0 {
            return;
        }
        let strength = (alpha * color.a as f32 / 255.0 * 256.0).round() as u32;
        let ink = [color.r as u32, color.g as u32, color.b as u32];
        let row = c.w as usize * 4;
        let mut cov = vec![0u8; x1 - x0];
        for y in y0..y1 {
            self.cover_row(dx, dy, scale, y, x0, &mut cov);
            let dst = &mut c.data[y * row + x0 * 4..y * row + x1 * 4];
            for (&v, px) in cov.iter().zip(dst.as_chunks_mut::<4>().0) {
                let k = ((v as u32 + (v as u32 >> 7)) * strength) >> 8;
                for ch in 0..3 {
                    px[ch] = ((ink[ch] * k + px[ch] as u32 * (256 - k) + 128) >> 8) as u8;
                }
            }
        }
    }

    /// The screen pixels, columns `x0..x1` of rows `y0..y1`, that the
    /// sprite grown by `scale` about its centre and moved by (`dx`, `dy`)
    /// touches on a `w`×`h` screen; none when it lies off the screen.
    pub fn bounds(
        &self,
        dx: f32,
        dy: f32,
        scale: f32,
        w: usize,
        h: usize,
    ) -> Option<(usize, usize, usize, usize)> {
        let (sw, sh) = (self.w as f32 * scale, self.h as f32 * scale);
        let (cx, cy) = (
            self.x + dx + self.w as f32 / 2.0,
            self.y + dy + self.h as f32 / 2.0,
        );
        let clip = |v: f32, max: usize| v.clamp(0.0, max as f32) as usize;
        let (x0, x1) = (
            clip((cx - sw / 2.0).floor(), w),
            clip((cx + sw / 2.0).ceil(), w),
        );
        let (y0, y1) = (
            clip((cy - sh / 2.0).floor(), h),
            clip((cy + sh / 2.0).ceil(), h),
        );
        (x0 < x1 && y0 < y1).then_some((x0, y0, x1, y1))
    }

    /// Coverage, 0 to 255, of the screen pixels from column `x0` on along
    /// row `y`, one per entry of `out`, with the sprite placed as for
    /// [`Sprite::bounds`]: each screen pixel's centre is mapped back into
    /// the sprite and read between its four nearest pixels.
    pub fn cover_row(&self, dx: f32, dy: f32, scale: f32, y: usize, x0: usize, out: &mut [u8]) {
        let (w, h) = (self.w as usize, self.h as usize);
        let (left, top) = (self.x + dx, self.y + dy);
        if scale == 1.0 && left.fract() == 0.0 && top.fract() == 0.0 {
            // Pixels line up: copy the sprite's row, empty past its ends.
            out.fill(0);
            let sy = y as i64 - top as i64;
            if (0..h as i64).contains(&sy) {
                let src = &self.cov[sy as usize * w..(sy as usize + 1) * w];
                // The sprite column under out[0], and the part of `out` the
                // sprite reaches.
                let from = x0 as i64 - left as i64;
                let a = (-from).clamp(0, out.len() as i64) as usize;
                let b = (w as i64 - from).clamp(a as i64, out.len() as i64) as usize;
                out[a..b]
                    .copy_from_slice(&src[(from + a as i64) as usize..(from + b as i64) as usize]);
            }
            return;
        }
        const ONE: f32 = 65536.0;
        let (cx, cy) = (left + w as f32 / 2.0, top + h as f32 / 2.0);
        let sy = (y as f32 + 0.5 - cy) / scale + h as f32 / 2.0 - 0.5;
        let iy = sy.floor();
        let fy = ((sy - iy) * 256.0) as u32;
        let line = |r: f32| {
            (r >= 0.0 && r < h as f32).then(|| &self.cov[r as usize * w..(r as usize + 1) * w])
        };
        let (upper, lower) = (line(iy), line(iy + 1.0));
        let at = |l: Option<&[u8]>, ix: i32| {
            l.and_then(|l| usize::try_from(ix).ok().and_then(|i| l.get(i)))
                .map_or(0, |&v| v as u32)
        };
        // Sprite column, in 16.16 fixed point, of each screen pixel's centre.
        let mut sx = (((x0 as f32 + 0.5 - cx) / scale + w as f32 / 2.0 - 0.5) * ONE) as i32;
        let step = (ONE / scale) as i32;
        for o in out.iter_mut() {
            let (ix, fx) = (sx >> 16, ((sx & 0xffff) >> 8) as u32);
            let mix = |l| at(l, ix) * (256 - fx) + at(l, ix + 1) * fx;
            *o = ((mix(upper) * (256 - fy) + mix(lower) * fy + 32768) >> 16) as u8;
            sx += step;
        }
    }
}

/// A sprite and its blurred versions, each made the first time it is
/// asked for.
pub struct Blurs {
    sharp: Sprite,
    blurred: Vec<Option<Sprite>>,
}

impl Blurs {
    pub fn new(sharp: Sprite) -> Blurs {
        Blurs {
            sharp,
            blurred: Vec::new(),
        }
    }

    /// The sprite blurred by about `radius` pixels, to the nearest box
    /// size.
    pub fn get(&mut self, radius: f32) -> &Sprite {
        let half = (radius / 2.0).round().max(0.0) as usize;
        if half == 0 {
            return &self.sharp;
        }
        if self.blurred.len() <= half {
            self.blurred.resize(half + 1, None);
        }
        let sharp = &self.sharp;
        self.blurred[half].get_or_insert_with(|| sharp.blurred(half as f32 * 2.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dot() -> Sprite {
        Sprite::capture(10.0, 20.0, 40, 40, |c, dx, dy| {
            c.fill_rect(25.0 + dx, 35.0 + dy, 10.0, 10.0, Rgba::rgb(0, 0, 0))
        })
    }

    fn white(w: u32, h: u32) -> Canvas {
        let mut c = Canvas::new(w, h);
        c.clear(Rgba::rgb(255, 255, 255));
        c
    }

    #[test]
    fn capture_keeps_coverage_where_it_was_drawn() {
        let s = dot();
        assert_eq!(s.cov[15 * 40 + 15], 255);
        assert_eq!(s.cov[5 * 40 + 5], 0);
    }

    #[test]
    fn capture_starts_on_a_whole_pixel() {
        let s = Sprite::capture(10.6, 20.2, 4, 4, |_, _, _| {});
        assert_eq!((s.x, s.y), (10.0, 20.0));
    }

    #[test]
    fn blurring_spreads_ink_and_keeps_its_amount() {
        let s = dot();
        let b = s.blurred(8.0);
        let total = |s: &Sprite| s.cov.iter().map(|&v| v as u32).sum::<u32>();
        assert!(b.cov[15 * 40 + 15] < 255, "the middle thins");
        assert!(b.cov[15 * 40 + 9] > 0, "ink reaches past the edge");
        let (a, c) = (total(&s) as f32, total(&b) as f32);
        assert!((a - c).abs() / a < 0.05, "{a} {c}");
    }

    #[test]
    fn blurs_are_made_once_and_kept() {
        let mut blurs = Blurs::new(dot());
        assert_eq!(blurs.get(0.4), &dot(), "too little to blur");
        let first = blurs.get(8.0).clone();
        assert_eq!(&first, blurs.get(8.3), "the same box size");
        assert_eq!(first, dot().blurred(8.0));
    }

    #[test]
    fn drawing_places_scales_and_fades() {
        let s = dot();
        let red = |c: &Canvas, x: usize, y: usize| c.data[(y * 80 + x) * 4 + 1];
        let mut c = white(80, 80);
        s.draw(&mut c, 0.0, 0.0, Rgba::rgb(255, 0, 0), 0.5);
        assert_eq!(red(&c, 30, 40), 128, "half faded at its place");
        assert_eq!(red(&c, 20, 40), 255);
        let mut c = white(80, 80);
        s.draw_scaled(&mut c, 0.0, 0.0, 0.5, Rgba::rgb(255, 0, 0), 1.0);
        assert_eq!(red(&c, 30, 40), 0, "the centre stays");
        assert_eq!(red(&c, 26, 40), 255, "the edge pulls in");
    }
}
