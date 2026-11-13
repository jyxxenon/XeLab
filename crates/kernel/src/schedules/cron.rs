use crate::error::{Error, Result};
use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Utc};
use chrono_tz::Tz;

// Every Gregorian month/day/weekday combination repeats in 400 years.
const SEARCH_DAYS: usize = 146_097 + 2;
const MONTH_DAYS: [u32; 12] = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

#[derive(Debug)]
pub(super) struct Cron {
    zone: Tz,
    minutes_of_day: Vec<u32>,
    day: Field,
    month: Field,
    weekday: Field,
}

#[derive(Debug)]
struct Field {
    values: u64,
    wildcard: bool,
}

impl Field {
    fn parse(text: &str, minimum: u32, maximum: u32) -> Result<Self> {
        let invalid = || Error::invalid("Invalid cron field");
        let mut values = 0;
        for item in text.split(',') {
            let (base, step) = match item.split_once('/') {
                Some((base, step)) => (
                    base,
                    Some(
                        decimal(step)
                            .filter(|&value| value != 0)
                            .ok_or_else(invalid)?,
                    ),
                ),
                None => (item, None),
            };
            let (first, last) = if base == "*" {
                (minimum, maximum)
            } else if let Some((first, last)) = base.split_once('-') {
                (
                    decimal(first).ok_or_else(invalid)?,
                    decimal(last).ok_or_else(invalid)?,
                )
            } else if step.is_none() {
                let value = decimal(base).ok_or_else(invalid)?;
                (value, value)
            } else {
                return Err(invalid());
            };
            if first < minimum || last > maximum || first > last {
                return Err(invalid());
            }
            for value in (first..=last).step_by(step.unwrap_or(1) as usize) {
                values |= 1 << value;
            }
        }
        Ok(Self {
            values,
            wildcard: text == "*",
        })
    }

    fn contains(&self, value: u32) -> bool {
        self.values & (1 << value) != 0
    }
}

fn decimal(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

impl Cron {
    pub(super) fn parse(expression: &str, zone: &str) -> Result<Self> {
        if expression.len() > 128 {
            return Err(Error::invalid("Cron expression exceeds 128 characters"));
        }
        let fields: Vec<_> = expression.split_ascii_whitespace().collect();
        let [minute, hour, day, month, weekday] = fields.as_slice() else {
            return Err(Error::invalid("Cron requires five fields"));
        };
        let minute = Field::parse(minute, 0, 59)?;
        let hour = Field::parse(hour, 0, 23)?;
        let day = Field::parse(day, 1, 31)?;
        let month = Field::parse(month, 1, 12)?;
        let weekday = Field::parse(weekday, 0, 6)?;
        let zone = zone
            .parse()
            .map_err(|_| Error::invalid("Schedule timezone must be an IANA name"))?;

        if !day.wildcard && weekday.wildcard {
            let first_day = day.values.trailing_zeros();
            if !(1..=12)
                .any(|value| month.contains(value) && first_day <= MONTH_DAYS[value as usize - 1])
            {
                return Err(Error::invalid("Cron has no matching calendar day"));
            }
        }

        let mut minutes_of_day = Vec::new();
        for h in (0..24).filter(|&value| hour.contains(value)) {
            minutes_of_day.extend(
                (0..60)
                    .filter(|&value| minute.contains(value))
                    .map(|m| h * 60 + m),
            );
        }
        Ok(Self {
            zone,
            minutes_of_day,
            day,
            month,
            weekday,
        })
    }

    pub(super) fn next_after(&self, instant: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.find(instant, true)
    }

    pub(super) fn previous_at_or_before(&self, instant: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.find(instant, false)
    }

    fn matches_day(&self, date: NaiveDate) -> bool {
        if !self.month.contains(date.month()) {
            return false;
        }
        let day = self.day.contains(date.day());
        let weekday = self.weekday.contains(date.weekday().num_days_from_sunday());
        if self.day.wildcard || self.weekday.wildcard {
            day && weekday
        } else {
            day || weekday
        }
    }

    fn find(&self, anchor: DateTime<Utc>, forward: bool) -> Option<DateTime<Utc>> {
        let utc_date = anchor.date_naive();
        // A UTC offset has magnitude less than one day. Search local dates on
        // both sides of the UTC boundary, then order eligible instants in UTC.
        // This also handles a rollback across local midnight.
        let mut date = if forward {
            utc_date.pred_opt().unwrap_or(utc_date)
        } else {
            utc_date.succ_opt().unwrap_or(utc_date)
        };
        let mut best: Option<DateTime<Utc>> = None;
        for _ in 0..SEARCH_DAYS {
            if let Some(found) = best {
                let found_date = found.date_naive();
                let beyond = if forward {
                    date.pred_opt().is_some_and(|day| day > found_date)
                } else {
                    date.succ_opt().is_some_and(|day| day < found_date)
                };
                if beyond {
                    break;
                }
            }
            if self.matches_day(date) {
                for &minute in &self.minutes_of_day {
                    let local = date.and_hms_opt(minute / 60, minute % 60, 0)?;
                    // A gap has no instant. A fold contributes only its first.
                    let Some(instant) = self.zone.from_local_datetime(&local).earliest() else {
                        continue;
                    };
                    let instant = instant.with_timezone(&Utc);
                    let better = if forward {
                        instant > anchor && best.is_none_or(|found| instant < found)
                    } else {
                        instant <= anchor && best.is_none_or(|found| instant > found)
                    };
                    if better {
                        best = Some(instant);
                    }
                }
            }
            let adjacent = if forward {
                date.succ_opt()
            } else {
                date.pred_opt()
            };
            let Some(adjacent) = adjacent else {
                break;
            };
            date = adjacent;
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn rejects_invalid_fields_and_timezones() {
        for expression in [
            "",
            "* * * *",
            "0 0 * * * 2026",
            "60 0 * * *",
            "0 24 * * *",
            "0 0 0 * *",
            "0 0 * 13 *",
            "0 0 * * 7",
            "0 0 * JAN MON",
            "0 0 L * *",
            "0 0 15W * *",
            "0 0 * * 1#2",
            "*/0 * * * *",
            "5/2 * * * *",
            "20-10 * * * *",
            "*/2/3 * * * *",
            "1,,2 * * * *",
            "+1 * * * *",
            "１ * * * *",
        ] {
            assert!(Cron::parse(expression, "UTC").is_err(), "{expression}");
        }
        for timezone in ["", "Mars/Olympus", "+08:00", "Asia/Shanghai "] {
            assert!(Cron::parse("* * * * *", timezone).is_err(), "{timezone}");
        }
    }

    #[test]
    fn combines_lists_ranges_and_steps_in_local_time() {
        let cron = Cron::parse("0,10-35/10,30 8-12/2 * 2 1-5", "Asia/Shanghai").unwrap();
        assert_eq!(
            cron.next_after(utc("2026-02-02T00:20:00Z")),
            Some(utc("2026-02-02T00:30:00Z"))
        );
        assert_eq!(
            cron.next_after(utc("2026-02-02T00:30:00Z")),
            Some(utc("2026-02-02T02:00:00Z"))
        );
        assert_eq!(
            cron.previous_at_or_before(utc("2026-02-02T02:00:00Z")),
            Some(utc("2026-02-02T02:00:00Z"))
        );
        assert_eq!(
            cron.previous_at_or_before(utc("2026-02-02T01:59:59.999Z")),
            Some(utc("2026-02-02T00:30:00Z"))
        );

        let cron = Cron::parse("*/15 * * * *", "UTC").unwrap();
        assert_eq!(
            cron.next_after(utc("2026-02-02T23:59:00Z")),
            Some(utc("2026-02-03T00:00:00Z"))
        );
    }

    #[test]
    fn uses_or_only_when_both_day_fields_are_restricted() {
        let anchor = utc("2026-01-10T00:00:00Z");
        let tuesday = utc("2026-01-13T09:00:00Z");
        let friday = utc("2026-01-16T09:00:00Z");
        let either = Cron::parse("0 9 13 * 5", "UTC").unwrap();
        assert_eq!(either.next_after(anchor), Some(tuesday));
        assert_eq!(either.next_after(tuesday), Some(friday));
        assert_eq!(
            Cron::parse("0 9 * * 5", "UTC").unwrap().next_after(anchor),
            Some(friday)
        );
        assert_eq!(
            Cron::parse("0 9 13 * *", "UTC")
                .unwrap()
                .next_after(tuesday),
            Some(utc("2026-02-13T09:00:00Z"))
        );
    }

    #[test]
    fn validates_recurrence_and_crosses_a_non_leap_century() {
        assert!(Cron::parse("0 0 30 2 *", "UTC").is_err());
        assert!(Cron::parse("0 0 31 4,6,9,11 *", "UTC").is_err());
        assert!(Cron::parse("0 0 31 2 1", "UTC").is_ok());

        let cron = Cron::parse("0 0 29 2 *", "UTC").unwrap();
        let first = utc("2096-02-29T00:00:00Z");
        let second = utc("2104-02-29T00:00:00Z");
        assert_eq!(cron.next_after(first), Some(second));
        assert_eq!(cron.previous_at_or_before(second), Some(second));
        assert_eq!(
            cron.previous_at_or_before(utc("2104-02-28T23:59:59Z")),
            Some(first)
        );
    }

    #[test]
    fn skips_gaps_and_uses_only_the_first_fold() {
        let gap = Cron::parse("30 2 * * *", "America/New_York").unwrap();
        let before_gap = utc("2026-03-07T07:30:00Z");
        let after_gap = utc("2026-03-09T06:30:00Z");
        assert_eq!(gap.next_after(before_gap), Some(after_gap));
        assert_eq!(
            gap.previous_at_or_before(utc("2026-03-08T12:00:00Z")),
            Some(before_gap)
        );

        let fold = Cron::parse("30 1 * * *", "America/New_York").unwrap();
        let first = utc("2026-11-01T05:30:00Z");
        let repeat = utc("2026-11-01T06:30:00Z");
        assert_eq!(fold.next_after(first), Some(utc("2026-11-02T06:30:00Z")));
        assert_eq!(fold.previous_at_or_before(repeat), Some(first));
    }

    #[test]
    fn resolves_previous_instant_when_a_fold_crosses_midnight() {
        let cron = Cron::parse("0 0 * * *", "America/Goose_Bay").unwrap();
        let first_midnight = utc("1988-10-30T02:00:00Z");
        let repeat = utc("1988-10-30T04:00:00Z");
        assert_eq!(
            cron.previous_at_or_before(utc("1988-10-30T03:00:00Z")),
            Some(first_midnight)
        );
        assert_eq!(cron.previous_at_or_before(repeat), Some(first_midnight));
        assert_eq!(
            cron.next_after(first_midnight),
            Some(utc("1988-10-31T04:00:00Z"))
        );
    }
}
