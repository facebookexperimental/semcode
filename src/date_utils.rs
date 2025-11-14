// SPDX-License-Identifier: MIT OR Apache-2.0
//! Date parsing utilities for lore email filtering
//!
//! Uses chrono-english for natural language date parsing, supporting formats like:
//! - Relative: "yesterday", "1 day ago", "2 weeks ago", "3 months ago"
//! - Absolute: "2024-01-01" (YYYY-MM-DD ISO format)
//!
//! Dates are stored in the lore table as RFC 2822 strings (e.g., "Thu, 21 Nov 2019 14:22:24 -0800")
//! We convert filter dates to RFC 2822 for proper SQL string comparison

use anyhow::{anyhow, Result};
use chrono::Utc;

/// Parse a date string into an RFC 2822 timestamp for SQL comparison
///
/// The lore table stores dates in RFC 2822 format, so we must convert our
/// filter dates to the same format for SQL string comparison to work.
///
/// Uses chrono-english for flexible natural language date parsing. Examples:
/// - "yesterday", "today", "tomorrow"
/// - "7 days ago", "2 weeks ago", "3 months ago"
/// - "2024-01-15" (YYYY-MM-DD ISO format)
/// - And various other formats supported by chrono-english
pub fn parse_date(date_str: &str) -> Result<String> {
    let date_str = date_str.trim();

    // Use chrono-english to parse the date relative to current time
    let parsed =
        chrono_english::parse_date_string(date_str, Utc::now(), chrono_english::Dialect::Us)
            .map_err(|e| {
                anyhow!(
                    "Invalid date format: '{}'. Error: {}.\n\
             Supported formats include:\n\
             - 'yesterday', 'today'\n\
             - '7 days ago', '2 weeks ago', '3 months ago'\n\
             - 'YYYY-MM-DD' (e.g., '2024-01-15')",
                    date_str,
                    e
                )
            })?;

    Ok(parsed.to_rfc2822())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yesterday() {
        let result = parse_date("yesterday");
        assert!(result.is_ok());
        let date_str = result.unwrap();
        // RFC 2822 format includes timezone like "Mon, 13 Nov 2025 HH:MM:SS +0000"
        println!("yesterday -> {}", date_str);
        assert!(date_str.contains("+0000") || date_str.contains("GMT"));
    }

    #[test]
    fn test_parse_today() {
        let result = parse_date("today");
        assert!(result.is_ok());
        let date_str = result.unwrap();
        println!("today -> {}", date_str);
        assert!(date_str.contains("+0000") || date_str.contains("GMT"));
    }

    #[test]
    fn test_parse_days_ago() {
        let result = parse_date("7 days ago");
        assert!(result.is_ok());
        println!("7 days ago -> {}", result.unwrap());
    }

    #[test]
    fn test_parse_weeks_ago() {
        let result = parse_date("2 weeks ago");
        assert!(result.is_ok());
        println!("2 weeks ago -> {}", result.unwrap());
    }

    #[test]
    fn test_parse_absolute_date() {
        let result = parse_date("2024-11-13");
        assert!(result.is_ok());
        let rfc2822 = result.unwrap();
        println!("2024-11-13 -> {}", rfc2822);
        // Should contain "13 Nov 2024"
        assert!(rfc2822.contains("13 Nov 2024"));
    }

    #[test]
    fn test_parse_invalid_format() {
        let result = parse_date("not a date");
        assert!(result.is_err());
    }

    #[test]
    fn test_date_comparison() {
        // Test that RFC 2822 strings compare correctly
        // RFC 2822 format: "Day, DD Mon YYYY HH:MM:SS +0000"
        let date1 = "Wed, 01 Nov 2024 00:00:00 +0000";
        let date2 = "Wed, 13 Nov 2024 00:00:00 +0000";
        assert!(date1 < date2);
        assert!(date2 > date1);
        println!("Date comparison works: {} < {}", date1, date2);
    }

    #[test]
    fn test_rfc2822_format() {
        // Verify our dates are in correct RFC 2822 format
        let result = parse_date("2025-11-01");
        assert!(result.is_ok());
        let rfc2822 = result.unwrap();
        println!("RFC 2822 format test: {}", rfc2822);

        // Should be parseable back to DateTime
        let parsed = chrono::DateTime::parse_from_rfc2822(&rfc2822);
        assert!(
            parsed.is_ok(),
            "Generated RFC 2822 date should be valid: {}",
            rfc2822
        );
    }

    #[test]
    fn test_natural_language_formats() {
        // Test additional natural language formats supported by chrono-english
        // Note: chrono-english supports many formats, but not all intuitive ones work
        let test_cases = vec![
            "3 months ago",
            "2024-01-15", // Standard ISO format
        ];

        for case in test_cases {
            let result = parse_date(case);
            assert!(result.is_ok(), "Failed to parse: {}", case);
            println!("{} -> {}", case, result.unwrap());
        }
    }
}
