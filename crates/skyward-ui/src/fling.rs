/// How far back the speed at release looks.
const HORIZON_MS: u64 = 100;
/// A finger that rested this long before lifting has no speed left.
const REST_MS: u64 = 40;

/// Recent finger positions of a drag, to tell how fast it moved when the
/// finger lifted.
#[derive(Debug, Default)]
pub struct Tracker {
    samples: Vec<(u64, f32)>,
}

impl Tracker {
    pub fn clear(&mut self) {
        self.samples.clear();
    }

    pub fn add(&mut self, at: u64, y: f32) {
        // A finger moving again after a rest starts a new measure.
        if self
            .samples
            .last()
            .is_some_and(|&(t, _)| at.saturating_sub(t) > REST_MS)
        {
            self.samples.clear();
        }
        self.samples.retain(|&(t, _)| t + HORIZON_MS >= at);
        self.samples.push((at, y));
    }

    /// Pixels per second along y for a lift at `at`: the slope at the last
    /// sample of the parabola fitted to the last 100 ms of samples by least
    /// squares, so a finger speeding up is measured at its lift; zero when
    /// the finger rested before lifting.
    pub fn velocity(&self, at: u64) -> f32 {
        let Some(&(last, _)) = self.samples.last() else {
            return 0.0;
        };
        if at.saturating_sub(last) > REST_MS {
            return 0.0;
        }
        // Seconds before the last sample, and positions.
        let points = || {
            self.samples
                .iter()
                .map(move |&(t, y)| ((t as f64 - last as f64) / 1000.0, f64::from(y)))
        };
        let n = self.samples.len() as f64;
        let (mut mt, mut mq, mut my) = (0.0, 0.0, 0.0);
        for (t, y) in points() {
            mt += t / n;
            mq += t * t / n;
            my += y / n;
        }
        let (mut stt, mut stq, mut sqq, mut sty, mut sqy) = (0.0, 0.0, 0.0, 0.0, 0.0);
        for (t, y) in points() {
            let (dt, dq, dy) = (t - mt, t * t - mq, y - my);
            stt += dt * dt;
            stq += dt * dq;
            sqq += dq * dq;
            sty += dt * dy;
            sqy += dq * dy;
        }
        // A curve needs more distinct times than its degree: two give a
        // line, three or more a parabola.
        let times = 1 + self.samples.windows(2).filter(|w| w[1].0 != w[0].0).count();
        let slope = match times {
            1 => 0.0,
            2 => sty / stt,
            _ => (sty * sqq - sqy * stq) / (stt * sqq - stq * stq),
        };
        slope as f32
    }
}

const FRICTION: f32 = 0.015;
const INFLEXION: f32 = 0.35;
/// ln(0.78) / ln(0.9).
const DECELERATION_RATE: f32 = 2.358_201_7;

/// The page gliding on after a flick and slowing to a stop. The speed at
/// release sets the distance and the time: friction 0.015 against gravity,
/// 9.81 m/s², brought to the screen's pixels per inch.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fling {
    start: u64,
    from: f32,
    distance: f32,
    duration: f32,
}

impl Fling {
    /// A glide starting at `from` at time `start` for a release at
    /// `velocity` pixels per second (signed, in scroll direction) on a
    /// screen of `ppi` pixels per inch.
    pub fn new(start: u64, from: f32, velocity: f32, ppi: f32) -> Fling {
        let physical = 9.806_65 * 39.37 * ppi * 0.84;
        let l = (INFLEXION * velocity.abs() / (FRICTION * physical)).ln();
        let duration = 1000.0 * (l / (DECELERATION_RATE - 1.0)).exp();
        let distance =
            FRICTION * physical * (DECELERATION_RATE / (DECELERATION_RATE - 1.0) * l).exp();
        Fling {
            start,
            from,
            distance: distance.copysign(velocity),
            duration,
        }
    }

    /// Where the glide is at `now`, and whether it has come to rest.
    pub fn at(&self, now: u64) -> (f32, bool) {
        let t = (now.saturating_sub(self.start) as f32 / self.duration).min(1.0);
        (self.from + self.distance * ease(t), t >= 1.0)
    }

    /// How fast the glide moves at `now`, in pixels per second, signed
    /// like its distance.
    pub fn velocity(&self, now: u64) -> f32 {
        (self.at(now + 1).0 - self.at(now).0) * 1000.0
    }
}

/// The share of the glide's distance covered at share `t` of its time: a
/// cubic curve whose time handles sit at 0.175 and 0.35 and whose distance
/// handles sit at 0.5 and 1, solved for its parameter by bisection.
fn ease(t: f32) -> f32 {
    const P1: f32 = 0.5 * INFLEXION;
    const P2: f32 = INFLEXION;
    let (mut lo, mut hi) = (0.0f32, 1.0f32);
    let mut s = t;
    for _ in 0..32 {
        s = (lo + hi) / 2.0;
        let x = 3.0 * s * (1.0 - s) * ((1.0 - s) * P1 + s * P2) + s * s * s;
        if (x - t).abs() < 1e-5 {
            break;
        }
        if x > t {
            hi = s;
        } else {
            lo = s;
        }
    }
    3.0 * s * (1.0 - s) * ((1.0 - s) * 0.5 + s) + s * s * s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_steady_drag_measures_its_speed() {
        let mut t = Tracker::default();
        for i in 0..10 {
            t.add(i * 8, 2000.0 - 16.0 * i as f32);
        }
        let v = t.velocity(75);
        assert!((v + 2000.0).abs() < 1.0, "{v}");
    }

    #[test]
    fn a_speeding_finger_is_measured_at_the_lift() {
        let mut t = Tracker::default();
        // y = 2000 - 0.1 t², t in ms: at 72 ms the finger moves 14.4 px/ms.
        for i in 0..10u64 {
            let ms = i * 8;
            t.add(ms, 2000.0 - 0.1 * (ms * ms) as f32);
        }
        let v = t.velocity(80);
        assert!((v + 14_400.0).abs() < 1.0, "{v}");
    }

    #[test]
    fn a_pause_starts_a_new_measure() {
        let mut t = Tracker::default();
        t.add(0, 3000.0);
        t.add(8, 2000.0);
        // Resting 50 ms, then moving slowly.
        for i in 0..4u64 {
            t.add(58 + i * 8, 2000.0 - 8.0 * i as f32);
        }
        let v = t.velocity(90);
        assert!((v + 1000.0).abs() < 1.0, "{v}");
    }

    #[test]
    fn a_finger_resting_before_lifting_has_no_speed() {
        let mut t = Tracker::default();
        for i in 0..10 {
            t.add(i * 8, 2000.0 - 16.0 * i as f32);
        }
        assert_eq!(t.velocity(72 + 60), 0.0);
    }

    #[test]
    fn the_curve_starts_fast_and_settles() {
        assert!(ease(0.0).abs() < 1e-3);
        assert!((ease(1.0) - 1.0).abs() < 1e-3);
        let mut last = 0.0;
        for i in 1..=20 {
            let d = ease(i as f32 / 20.0);
            assert!(d >= last, "the glide never turns back");
            last = d;
        }
        assert!(
            ease(0.25) > 0.5,
            "half the distance goes in the first quarter"
        );
    }

    #[test]
    fn a_faster_flick_glides_further_and_longer() {
        let slow = Fling::new(0, 0.0, 2000.0, 560.0);
        let fast = Fling::new(0, 0.0, 8000.0, 560.0);
        assert!(fast.distance > slow.distance && fast.duration > slow.duration);
        let up = Fling::new(0, 1000.0, -3000.0, 560.0);
        assert!(
            up.at(100).0 < 1000.0,
            "a glide follows the sign of the speed"
        );
        assert_eq!(up.at(100_000), (1000.0 + up.distance, true));
    }
}
