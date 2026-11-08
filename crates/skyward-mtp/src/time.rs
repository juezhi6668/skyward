//! Times as MTP writes them: "YYYYMMDDThhmmss" on a zone's clock; the
//! computer's may add tenths of a second, and a zone or offset of their own.

use jiff::civil::DateTime;
use jiff::tz::TimeZone;
use jiff::Timestamp;

/// A Unix time on the clock of `zone`. A time before 1970, as a damaged
/// file's can be, is written as 1970 began; one past the calendar, as its
/// end.
pub fn format(unix: i64, zone: &TimeZone) -> String {
    let at = Timestamp::from_second(unix.clamp(0, Timestamp::MAX.as_second()))
        .expect("a time within the calendar");
    let t = at.to_zoned(zone.clone()).datetime();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// A time from the computer, on the clock of `zone` unless it gives a zone
/// of its own; `None` where it is no time.
pub fn parse(s: &str, zone: &TimeZone) -> Option<i64> {
    if let Ok(at) = s.parse::<Timestamp>() {
        return Some(at.as_second());
    }
    let civil = s.parse::<DateTime>().ok()?;
    Some(civil.to_zoned(zone.clone()).ok()?.timestamp().as_second())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-21 12:15:00 UTC.
    const AT: i64 = 1_792_584_900;

    fn shanghai() -> TimeZone {
        TimeZone::get("Asia/Shanghai").unwrap()
    }

    #[test]
    fn times_are_written_on_the_zone_s_clock() {
        assert_eq!(format(AT, &shanghai()), "20261021T201500");
        assert_eq!(format(AT, &TimeZone::UTC), "20261021T121500");
        assert_eq!(format(0, &TimeZone::UTC), "19700101T000000");
        assert_eq!(format(-5, &TimeZone::UTC), "19700101T000000", "before 1970");
        assert_eq!(format(i64::MAX, &shanghai()), "99991231T060000");
    }

    #[test]
    fn the_computer_s_times_are_read_on_the_zone_s_clock_or_their_own() {
        let zone = shanghai();
        assert_eq!(parse("20261021T201500", &zone), Some(AT));
        assert_eq!(
            parse("20261021T201500.5", &zone),
            Some(AT),
            "tenths of a second"
        );
        assert_eq!(parse("20261021T121500Z", &zone), Some(AT));
        assert_eq!(parse("20261021T201500+0800", &TimeZone::UTC), Some(AT));
        assert_eq!(parse("", &zone), None);
        assert_eq!(parse("yesterday", &zone), None);
    }
}
