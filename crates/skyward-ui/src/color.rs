#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgba {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Rgba {
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    pub const fn with_alpha(self, a: u8) -> Self {
        Self { a, ..self }
    }
}

/// Linear blend from `a` (at 0) to `b` (at 1).
pub fn mix(a: Rgba, b: Rgba, t: f32) -> Rgba {
    let t = t.clamp(0.0, 1.0);
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Rgba {
        r: l(a.r, b.r),
        g: l(a.g, b.g),
        b: l(a.b, b.b),
        a: l(a.a, b.a),
    }
}

/// `top` laid over `under`, both straight alpha.
pub fn over(top: Rgba, under: Rgba) -> Rgba {
    let mut px = [under.r, under.g, under.b, under.a];
    blend_over(&mut px, top, 1.0);
    Rgba {
        r: px[0],
        g: px[1],
        b: px[2],
        a: px[3],
    }
}

/// Source-over composite of `src` (with an extra coverage `cov` in 0..=1) onto
/// `dst` (a 4-byte RGBA slice), straight alpha.
pub fn blend_over(dst: &mut [u8], src: Rgba, cov: f32) {
    let a = (src.a as f32 * cov.clamp(0.0, 1.0)).round() as u32;
    blend_px(dst.try_into().expect("a pixel is four bytes"), src, a);
}

/// `src`'s colour laid over the pixel `dst` with strength `a` of 255: its
/// own alpha and how much of the pixel it covers, together.
#[inline]
pub fn blend_px(dst: &mut [u8; 4], src: Rgba, a: u32) {
    if a == 0 {
        return;
    }
    // Wholly laid on, it comes out of the formulas below as itself.
    if a >= 255 {
        *dst = [src.r, src.g, src.b, 255];
        return;
    }
    // Over an opaque pixel, which pages are, the result stays opaque and is
    // a plain mix, worked out in integers.
    if dst[3] == 255 {
        let mix = |s: u8, d: u8| ((s as u32 * a + d as u32 * (255 - a) + 127) / 255) as u8;
        dst[0] = mix(src.r, dst[0]);
        dst[1] = mix(src.g, dst[1]);
        dst[2] = mix(src.b, dst[2]);
        return;
    }
    // Over a clear pixel it is the colour itself, as see-through as laid.
    if dst[3] == 0 {
        *dst = [src.r, src.g, src.b, a as u8];
        return;
    }
    blend_clear(dst, src, a);
}

/// [`blend_px`] over a pixel not wholly opaque, as layers drawn on their
/// own are; kept out of line so the common cases above are drawn in place.
#[inline(never)]
fn blend_clear(dst: &mut [u8; 4], src: Rgba, a: u32) {
    let sa = a as f32 / 255.0;
    let da = dst[3] as f32 / 255.0;
    let out_a = sa + da * (1.0 - sa);
    if out_a <= 0.0 {
        dst.copy_from_slice(&[0, 0, 0, 0]);
        return;
    }
    let ch = |s: u8, d: u8| {
        let s = s as f32 / 255.0;
        let d = d as f32 / 255.0;
        let v = (s * sa + d * da * (1.0 - sa)) / out_a;
        (v * 255.0).round().clamp(0.0, 255.0) as u8
    };
    dst[0] = ch(src.r, dst[0]);
    dst[1] = ch(src.g, dst[1]);
    dst[2] = ch(src.b, dst[2]);
    dst[3] = (out_a * 255.0).round().clamp(0.0, 255.0) as u8;
}
