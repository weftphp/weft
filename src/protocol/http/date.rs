//! HTTP dates (RFC 9110 §5.6.7): always generated in IMF-fixdate form, e.g.
//! `Sun, 06 Nov 1994 08:49:37 GMT`, and parsed in any of the three historical forms.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn month_lengths(year: i64) -> [i64; 12] {
    let feb = if is_leap(year) { 29 } else { 28 };
    [31, feb, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
}

/// Splits days since 1970-01-01 into (year, month 1-12, day 1-31).
fn civil_from_days(mut days: i64) -> (i64, usize, i64) {
    let mut year = 1970;
    loop {
        let len = if is_leap(year) { 366 } else { 365 };
        if days < len {
            break;
        }
        days -= len;
        year += 1;
    }
    for (month, len) in month_lengths(year).into_iter().enumerate() {
        if days < len {
            return (year, month + 1, days + 1);
        }
        days -= len;
    }
    unreachable!("a year's months cover all of its days")
}

fn days_from_civil(year: i64, month: usize, day: i64) -> Option<i64> {
    if year < 1970 || !(1..=12).contains(&month) {
        return None;
    }
    let lengths = month_lengths(year);
    if !(1..=lengths[month - 1]).contains(&day) {
        return None;
    }
    let mut days: i64 = (1970..year)
        .map(|y| if is_leap(y) { 366 } else { 365 })
        .sum();
    days += lengths[..month - 1].iter().sum::<i64>();
    Some(days + day - 1)
}

/// Formats `time` as an IMF-fixdate. Times before 1970 are clamped to the epoch.
pub fn format(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        day,
        MONTHS[month - 1],
        year,
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

fn month_number(name: &str) -> Option<usize> {
    MONTHS.iter().position(|m| *m == name).map(|i| i + 1)
}

fn parse_clock(clock: &str) -> Option<i64> {
    let mut parts = clock.split(':').map(|p| p.parse::<i64>().ok());
    let (h, m, s) = (parts.next()??, parts.next()??, parts.next()??);
    if parts.next().is_some() || h > 23 || m > 59 || s > 60 {
        return None;
    }
    Some(h * 3600 + m * 60 + s)
}

/// Parses an HTTP date in IMF-fixdate, RFC 850 or asctime form.
pub fn parse(text: &str) -> Option<SystemTime> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    let (day, month, year, clock) = match fields.as_slice() {
        // Sun, 06 Nov 1994 08:49:37 GMT
        [_, day, month, year, clock, "GMT"] => (*day, *month, year.parse().ok()?, *clock),
        // Sunday, 06-Nov-94 08:49:37 GMT
        [_, date, clock, "GMT"] => {
            let mut parts = date.split('-');
            let (day, month, yy) = (parts.next()?, parts.next()?, parts.next()?);
            let yy: i64 = yy.parse().ok()?;
            // Two-digit years: pick the century that is not more than 50 years ahead.
            let year = if yy >= 70 { 1900 + yy } else { 2000 + yy };
            (day, month, year, *clock)
        }
        // Sun Nov  6 08:49:37 1994
        [_, month, day, clock, year] => (*day, *month, year.parse().ok()?, *clock),
        _ => return None,
    };
    let days = days_from_civil(year, month_number(month)?, day.parse().ok()?)?;
    let secs = days * 86_400 + parse_clock(clock)?;
    Some(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_rfc_example() {
        // RFC 9110's example instant.
        let t = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(format(t), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(format(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        let leap_day = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(format(leap_day), "Tue, 29 Feb 2000 00:00:00 GMT");
    }

    #[test]
    fn parses_all_three_forms() {
        let expected = Some(UNIX_EPOCH + Duration::from_secs(784_111_777));
        assert_eq!(parse("Sun, 06 Nov 1994 08:49:37 GMT"), expected);
        assert_eq!(parse("Sunday, 06-Nov-94 08:49:37 GMT"), expected);
        assert_eq!(parse("Sun Nov  6 08:49:37 1994"), expected);
        assert_eq!(parse("Sun, 31 Feb 1994 08:49:37 GMT"), None);
        assert_eq!(parse("yesterday"), None);
    }

    #[test]
    fn roundtrip_over_many_days() {
        for day in (0..40_000u64).step_by(37) {
            let t = UNIX_EPOCH + Duration::from_secs(day * 86_400 + 45_296);
            assert_eq!(parse(&format(t)), Some(t));
        }
    }
}
