// SPDX-License-Identifier: MIT OR Apache-2.0
//! Shared since/until date filtering for lore email queries.

use chrono::{DateTime, Utc};

/// A parsed since/until date range for lore queries.
///
/// The range applies in two stages.  predicate() yields a
/// date_timestamp predicate for only_if(), so the range bounds the
/// candidate set before any FTS or scan limit applies.  A stored
/// date_timestamp of 0 means the timestamp is unknown: the indexer
/// stores 0 when an email's Date header fails RFC 2822 parsing, and
/// the schema migration backfills 0 into every row that predates the
/// column.  The predicate therefore keeps timestamp-0 rows, and
/// matches() settles each of them by parsing its RFC 2822 date
/// string.
pub(crate) struct LoreDateFilter {
    has_timestamp_column: bool,
    predicate: Option<String>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
}

impl LoreDateFilter {
    pub(crate) fn new(
        has_timestamp_column: bool,
        since_date: Option<&str>,
        until_date: Option<&str>,
    ) -> Self {
        let since = since_date
            .and_then(|d| DateTime::parse_from_rfc2822(d).ok())
            .map(|dt| dt.with_timezone(&Utc));
        let until = until_date
            .and_then(|d| DateTime::parse_from_rfc2822(d).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let predicate = if has_timestamp_column {
            let bounds = match (since, until) {
                (Some(s), Some(u)) => Some(format!(
                    "date_timestamp >= {} AND date_timestamp <= {}",
                    s.timestamp(),
                    u.timestamp()
                )),
                (Some(s), None) => Some(format!("date_timestamp >= {}", s.timestamp())),
                (None, Some(u)) => Some(format!("date_timestamp <= {}", u.timestamp())),
                (None, None) => None,
            };
            bounds.map(|b| format!("(date_timestamp = 0 OR ({}))", b))
        } else {
            None
        };

        Self {
            has_timestamp_column,
            predicate,
            since,
            until,
        }
    }

    /// Database-level predicate for only_if().  None when no bound
    /// was given or the table lacks the date_timestamp column.
    pub(crate) fn predicate(&self) -> Option<&str> {
        self.predicate.as_deref()
    }

    /// Whether any date bound was requested.
    pub(crate) fn is_active(&self) -> bool {
        self.since.is_some() || self.until.is_some()
    }

    /// Columns a query must select, beyond what it already fetches,
    /// for matches() to settle each row.
    pub(crate) fn extra_columns(&self) -> Vec<String> {
        if !self.is_active() {
            Vec::new()
        } else if self.has_timestamp_column {
            vec!["date".to_string(), "date_timestamp".to_string()]
        } else {
            vec!["date".to_string()]
        }
    }

    /// Row-level date check.  A nonzero date_timestamp is compared
    /// numerically; a zero or absent one falls back to parsing the
    /// RFC 2822 date string.  A row whose date cannot be determined
    /// at all is dropped and counted in bad_dates.
    pub(crate) fn matches(
        &self,
        date_timestamp: Option<i64>,
        date: &str,
        bad_dates: &mut usize,
    ) -> bool {
        if !self.is_active() {
            return true;
        }
        if let Some(ts) = date_timestamp {
            if ts != 0 {
                return !self.since.is_some_and(|s| ts < s.timestamp())
                    && !self.until.is_some_and(|u| ts > u.timestamp());
            }
        }
        match DateTime::parse_from_rfc2822(date) {
            Ok(dt) => {
                let dt = dt.with_timezone(&Utc);
                !self.since.is_some_and(|s| dt < s) && !self.until.is_some_and(|u| dt > u)
            }
            Err(_) => {
                *bad_dates += 1;
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LoreDateFilter;

    const SINCE: &str = "Mon, 1 Jan 2024 00:00:00 +0000";
    const UNTIL: &str = "Wed, 1 Jan 2025 00:00:00 +0000";

    #[test]
    fn predicate_keeps_unknown_timestamps() {
        let f = LoreDateFilter::new(true, Some(SINCE), Some(UNTIL));
        let p = f.predicate().unwrap();
        assert!(p.starts_with("(date_timestamp = 0 OR ("));
        assert!(p.contains("date_timestamp >= 1704067200"));
        assert!(p.contains("date_timestamp <= 1735689600"));
    }

    #[test]
    fn no_predicate_without_column_or_bounds() {
        assert!(LoreDateFilter::new(false, Some(SINCE), None)
            .predicate()
            .is_none());
        assert!(LoreDateFilter::new(true, None, None).predicate().is_none());
        assert!(!LoreDateFilter::new(true, None, None).is_active());
    }

    #[test]
    fn matches_compares_nonzero_timestamps_numerically() {
        let f = LoreDateFilter::new(true, Some(SINCE), Some(UNTIL));
        let mut bad = 0;
        assert!(f.matches(Some(1720000000), "ignored", &mut bad));
        assert!(!f.matches(Some(1700000000), "ignored", &mut bad));
        assert_eq!(bad, 0);
    }

    #[test]
    fn matches_parses_the_date_string_for_zero_timestamps() {
        let f = LoreDateFilter::new(true, Some(SINCE), None);
        let mut bad = 0;
        assert!(f.matches(Some(0), "Sat, 1 Jun 2024 12:00:00 +0000", &mut bad));
        assert!(!f.matches(Some(0), "Thu, 1 Jun 2023 12:00:00 +0000", &mut bad));
        assert_eq!(bad, 0);
    }

    #[test]
    fn unparseable_dates_are_dropped_and_counted() {
        let f = LoreDateFilter::new(true, None, Some(UNTIL));
        let mut bad = 0;
        assert!(!f.matches(Some(0), "not a date", &mut bad));
        assert!(!f.matches(None, "", &mut bad));
        assert_eq!(bad, 2);
    }
}
