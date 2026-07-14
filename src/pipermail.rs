// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pipermail (Mailman 2) mailing list archive support
//!
//! Downloads the monthly mbox archives published by a pipermail archive
//! index page (e.g. https://lists.denx.de/pipermail/u-boot/) and splits
//! them into individual email messages for lore indexing.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// File written into each archive directory recording the base URL,
/// so that `--pipermail` without arguments can refresh the archive.
pub const URL_FILE: &str = "archive.url";

/// File written into each archive directory recording the
/// `--pipermail-since` cutoff as "YYYY-MM", so refreshes keep honouring it.
pub const SINCE_FILE: &str = "archive.since";

const MONTH_NAMES: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// A monthly mbox archive published on a pipermail index page
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveFile {
    pub file_name: String,
    pub year: u32,
    pub month: u32,
}

impl ArchiveFile {
    pub fn key(&self) -> (u32, u32) {
        (self.year, self.month)
    }
}

/// Parse an archive file stem like "2026-February" into (year, month)
pub fn month_key(stem: &str) -> Option<(u32, u32)> {
    let (year, month_name) = stem.split_once('-')?;
    let year = year.parse::<u32>().ok()?;
    let month = MONTH_NAMES.iter().position(|m| *m == month_name)? as u32 + 1;
    Some((year, month))
}

/// Strip the ".txt" or ".txt.gz" suffix from an archive file name
fn archive_file_stem(file_name: &str) -> Option<&str> {
    file_name
        .strip_suffix(".txt.gz")
        .or_else(|| file_name.strip_suffix(".txt"))
}

/// Extract the monthly mbox files linked from a pipermail index page.
/// Prefers the gzipped variant when both are listed. Results are sorted
/// chronologically (oldest first).
pub fn discover_archive_files(index_html: &str) -> Vec<ArchiveFile> {
    static HREF_RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = HREF_RE.get_or_init(|| {
        regex::Regex::new(r#"(?i)href="(\d{4}-[A-Za-z]+\.txt(?:\.gz)?)""#).unwrap()
    });

    let mut by_month: std::collections::HashMap<(u32, u32), ArchiveFile> =
        std::collections::HashMap::new();

    for cap in re.captures_iter(index_html) {
        let file_name = cap[1].to_string();
        let Some(stem) = archive_file_stem(&file_name) else {
            continue;
        };
        let Some((year, month)) = month_key(stem) else {
            continue;
        };
        let entry = ArchiveFile {
            file_name: file_name.clone(),
            year,
            month,
        };
        by_month
            .entry((year, month))
            .and_modify(|existing| {
                if file_name.ends_with(".gz") && !existing.file_name.ends_with(".gz") {
                    *existing = entry.clone();
                }
            })
            .or_insert(entry);
    }

    let mut files: Vec<ArchiveFile> = by_month.into_values().collect();
    files.sort_by_key(|f| f.key());
    files
}

/// List locally downloaded monthly mbox files, sorted chronologically
pub fn list_local_mbox_files(dir: &Path) -> Result<Vec<(ArchiveFile, PathBuf)>> {
    let mut files = Vec::new();

    if !dir.exists() {
        return Ok(files);
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = archive_file_stem(file_name) else {
            continue;
        };
        let Some((year, month)) = month_key(stem) else {
            continue;
        };
        files.push((
            ArchiveFile {
                file_name: file_name.to_string(),
                year,
                month,
            },
            path,
        ));
    }

    files.sort_by_key(|(f, _)| f.key());
    Ok(files)
}

/// Parse a user-supplied date ("2025-07-01", "1 year ago") into a
/// (year, month) archive cutoff
pub fn since_month(date_str: &str) -> Result<(u32, u32)> {
    use chrono::Datelike;

    let parsed = chrono_english::parse_date_string(
        date_str.trim(),
        chrono::Utc::now(),
        chrono_english::Dialect::Us,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "Invalid date '{}': {}. Use 'YYYY-MM-DD' or relative dates like '1 year ago'",
            date_str,
            e
        )
    })?;

    Ok((parsed.year() as u32, parsed.month()))
}

/// Decide which remote files need downloading: months missing locally,
/// plus the newest local month (it keeps growing until the next month
/// starts). Everything is bounded by `since` when given, otherwise by the
/// oldest month already downloaded, so a `--pipermail-since` cutoff
/// persists across refreshes.
pub fn files_to_download(
    remote: &[ArchiveFile],
    dir: &Path,
    since: Option<(u32, u32)>,
) -> Result<Vec<ArchiveFile>> {
    let local = list_local_mbox_files(dir)?;
    let local_keys: std::collections::HashSet<(u32, u32)> =
        local.iter().map(|(f, _)| f.key()).collect();
    let newest_local = local.iter().map(|(f, _)| f.key()).max();
    let horizon = since.or_else(|| local.iter().map(|(f, _)| f.key()).min());

    Ok(remote
        .iter()
        .filter(|f| {
            if horizon.is_some_and(|h| f.key() < h) {
                return false;
            }
            !local_keys.contains(&f.key()) || newest_local == Some(f.key())
        })
        .cloned()
        .collect())
}

/// Ensure the archive base URL ends with a trailing slash
pub fn normalize_base_url(base_url: &str) -> String {
    let mut url = base_url.trim().to_string();
    if !url.ends_with('/') {
        url.push('/');
    }
    url
}

/// Derive the local storage directory for a pipermail archive:
/// `<db_path>/pipermail/<host>/<list>`
pub fn archive_storage_dir(db_path: &str, base_url: &str) -> Result<PathBuf> {
    let without_scheme = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .ok_or_else(|| anyhow::anyhow!("Archive URL must start with http:// or https://"))?;

    let mut segments = without_scheme.split('/').filter(|s| !s.is_empty());
    let host = segments
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid archive URL: {}", base_url))?;
    let list = segments
        .next_back()
        .ok_or_else(|| anyhow::anyhow!("Archive URL has no list name: {}", base_url))?;

    if host.contains("..") || list.contains("..") {
        return Err(anyhow::anyhow!("Invalid archive URL: {}", base_url));
    }

    Ok(PathBuf::from(db_path)
        .join("pipermail")
        .join(host)
        .join(list))
}

/// Record the base URL of an archive so it can be refreshed later
pub fn save_archive_url(dir: &Path, base_url: &str) -> Result<()> {
    std::fs::write(dir.join(URL_FILE), format!("{}\n", base_url))
        .with_context(|| format!("Failed to write {}", dir.join(URL_FILE).display()))
}

/// Record the cutoff month so refreshes keep honouring it
pub fn save_archive_since(dir: &Path, since: (u32, u32)) -> Result<()> {
    let path = dir.join(SINCE_FILE);
    std::fs::write(&path, format!("{}-{:02}\n", since.0, since.1))
        .with_context(|| format!("Failed to write {}", path.display()))
}

/// Load a previously recorded cutoff month, if any
pub fn load_archive_since(dir: &Path) -> Option<(u32, u32)> {
    let content = std::fs::read_to_string(dir.join(SINCE_FILE)).ok()?;
    let (year, month) = content.trim().split_once('-')?;
    let year = year.parse::<u32>().ok()?;
    let month = month.parse::<u32>().ok()?;
    (1..=12).contains(&month).then_some((year, month))
}

/// Discover previously downloaded archives under `<db_path>/pipermail/`.
/// Returns (archive directory, base URL) pairs.
pub fn discover_saved_archives(db_path: &str) -> Result<Vec<(PathBuf, String)>> {
    let base = PathBuf::from(db_path).join("pipermail");
    let mut archives = Vec::new();

    fn walk(dir: &Path, archives: &mut Vec<(PathBuf, String)>) -> Result<()> {
        let url_file = dir.join(URL_FILE);
        if url_file.is_file() {
            let url = std::fs::read_to_string(&url_file)?.trim().to_string();
            if !url.is_empty() {
                archives.push((dir.to_path_buf(), url));
            }
            return Ok(());
        }
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, archives)?;
            }
        }
        Ok(())
    }

    if base.is_dir() {
        walk(&base, &mut archives)?;
    }

    archives.sort();
    Ok(archives)
}

/// Fetch the archive index page for a pipermail list (blocking)
pub fn fetch_index_page(base_url: &str) -> Result<String> {
    let response = reqwest::blocking::get(base_url)
        .with_context(|| format!("Failed to fetch archive index {}", base_url))?;
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch archive index {}: HTTP {}",
            base_url,
            response.status()
        ));
    }
    Ok(response.text()?)
}

/// Download a monthly mbox file to the given destination (blocking).
/// Writes to a temporary file first so interrupted downloads are not
/// mistaken for complete archives.
pub fn download_file(url: &str, dest: &Path) -> Result<()> {
    let response =
        reqwest::blocking::get(url).with_context(|| format!("Failed to download {}", url))?;
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to download {}: HTTP {}",
            url,
            response.status()
        ));
    }
    let bytes = response.bytes()?;

    let tmp = dest.with_extension("part");
    std::fs::write(&tmp, &bytes).with_context(|| format!("Failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

/// Read a downloaded mbox file, transparently decompressing gzip.
/// Invalid UTF-8 sequences are replaced rather than rejected since old
/// archives commonly contain legacy 8-bit encodings.
pub fn read_mbox_file(path: &Path) -> Result<String> {
    use std::io::Read;

    let raw = std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let bytes = if path.extension().and_then(|e| e.to_str()) == Some("gz") {
        let mut decoder = flate2::read::GzDecoder::new(&raw[..]);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .with_context(|| format!("Failed to decompress {}", path.display()))?;
        decompressed
    } else {
        raw
    };

    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Match a pipermail mbox message separator. Pipermail does not escape
/// body lines starting with "From ", so the match requires the full
/// From_ line shape (envelope address followed by an asctime date) to
/// avoid splitting on inline patches ("From <sha> Mon Sep 17 ...") or
/// prose. The address is usually obfuscated as "user at domain" but a
/// plain address is also accepted.
fn is_mbox_separator(line: &str) -> bool {
    static SEPARATOR_RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = SEPARATOR_RE.get_or_init(|| {
        regex::Regex::new(
            r"^From (\S+ at \S+|\S+@\S+) +[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} +\d{1,2}:\d{2}:\d{2} \d{4}$",
        )
        .unwrap()
    });
    re.is_match(line)
}

/// Split a pipermail mbox archive into individual messages. A message
/// starts at a From_ separator line preceded by a blank line (or the
/// start of the file); the separator line itself is not included in the
/// returned message text.
pub fn split_mbox(content: &str) -> Vec<String> {
    let mut messages = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut in_message = false;
    let mut prev_blank = true;

    for line in content.lines() {
        if prev_blank && is_mbox_separator(line) {
            if in_message && !current.is_empty() {
                messages.push(current.join("\n"));
            }
            current.clear();
            in_message = true;
        } else if in_message {
            current.push(line);
        }
        prev_blank = line.is_empty();
    }

    if in_message && !current.is_empty() {
        messages.push(current.join("\n"));
    }

    messages
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_month_key() {
        assert_eq!(month_key("2026-February"), Some((2026, 2)));
        assert_eq!(month_key("1999-December"), Some((1999, 12)));
        assert_eq!(month_key("2026-Foo"), None);
        assert_eq!(month_key("February"), None);
    }

    #[test]
    fn test_discover_archive_files() {
        let html = r#"
            <td><A href="2026-July.txt.gz">[ Gzip'd Text 1 MB ]</a></td>
            <td><A href="2026-June.txt.gz">[ Gzip'd Text 4 MB ]</a></td>
            <td><A href="2025-December.txt">[ Text 5 MB ]</a></td>
            <td><A href="2025-December.txt.gz">[ Gzip'd Text 2 MB ]</a></td>
            <td><A href="index.html">thread</a></td>
        "#;
        let files = discover_archive_files(html);
        let names: Vec<&str> = files.iter().map(|f| f.file_name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "2025-December.txt.gz",
                "2026-June.txt.gz",
                "2026-July.txt.gz"
            ]
        );
    }

    #[test]
    fn test_split_mbox() {
        let mbox = "\
From alice at example.org  Sun Feb  1 00:38:12 2026
From: alice at example.org (Alice)
Subject: [PATCH] first

Please apply.

From 1234abcd5678ef90aaaa Mon Sep 17 00:00:00 2001
From: Alice <alice@example.org>
Subject: inline patch

From what I know, this line is prose and not a separator.

From bob at example.org  Mon Feb  2 12:00:00 2026
From: bob at example.org (Bob)
Subject: Re: [PATCH] first

Looks good.
";
        let messages = split_mbox(mbox);
        assert_eq!(messages.len(), 2);
        assert!(messages[0].starts_with("From: alice at example.org"));
        assert!(messages[0].contains("From what I know"));
        assert!(messages[0].contains("From 1234abcd5678ef90aaaa"));
        assert!(messages[1].starts_with("From: bob at example.org"));
        assert!(messages[1].ends_with("Looks good."));
    }

    #[test]
    fn test_since_month() {
        assert_eq!(since_month("2025-07-15").unwrap(), (2025, 7));
        assert_eq!(since_month("2024-01-01").unwrap(), (2024, 1));
        assert!(since_month("1 year ago").is_ok());
        assert!(since_month("not a date").is_err());
    }

    #[test]
    fn test_files_to_download() {
        let remote: Vec<ArchiveFile> = [(2025, 11), (2025, 12), (2026, 1), (2026, 2)]
            .iter()
            .map(|&(year, month)| ArchiveFile {
                file_name: format!("{}-{}.txt.gz", year, MONTH_NAMES[month as usize - 1]),
                year,
                month,
            })
            .collect();

        let dir = TempDir::new().unwrap();

        // Fresh directory, no cutoff: everything is downloaded
        let all = files_to_download(&remote, dir.path(), None).unwrap();
        assert_eq!(all.len(), 4);

        // Fresh directory with cutoff: only months at or after the cutoff
        let since = files_to_download(&remote, dir.path(), Some((2026, 1))).unwrap();
        let keys: Vec<(u32, u32)> = since.iter().map(|f| f.key()).collect();
        assert_eq!(keys, vec![(2026, 1), (2026, 2)]);

        // Existing since-limited download: refresh re-fetches the newest
        // local month and anything newer, but not older missing months
        std::fs::write(dir.path().join("2026-January.txt.gz"), "x").unwrap();
        let refresh = files_to_download(&remote, dir.path(), None).unwrap();
        let keys: Vec<(u32, u32)> = refresh.iter().map(|f| f.key()).collect();
        assert_eq!(keys, vec![(2026, 1), (2026, 2)]);

        // Explicit earlier cutoff extends the backfill
        let extend = files_to_download(&remote, dir.path(), Some((2025, 12))).unwrap();
        let keys: Vec<(u32, u32)> = extend.iter().map(|f| f.key()).collect();
        assert_eq!(keys, vec![(2025, 12), (2026, 1), (2026, 2)]);

        // A gap inside the local range is backfilled on refresh
        std::fs::write(dir.path().join("2025-November.txt.gz"), "x").unwrap();
        let gap = files_to_download(&remote, dir.path(), None).unwrap();
        let keys: Vec<(u32, u32)> = gap.iter().map(|f| f.key()).collect();
        assert_eq!(keys, vec![(2025, 12), (2026, 1), (2026, 2)]);
    }

    #[test]
    fn test_save_load_archive_since() {
        let dir = TempDir::new().unwrap();
        assert_eq!(load_archive_since(dir.path()), None);
        save_archive_since(dir.path(), (2025, 7)).unwrap();
        assert_eq!(load_archive_since(dir.path()), Some((2025, 7)));
    }

    #[test]
    fn test_files_to_download_stale_partial_download() {
        // An aborted unbounded run left only old months on disk. A rerun
        // with a cutoff must fetch just the months at or after the cutoff,
        // not everything after the newest stale month.
        let remote: Vec<ArchiveFile> = [(2025, 11), (2025, 12), (2026, 1), (2026, 2)]
            .iter()
            .map(|&(year, month)| ArchiveFile {
                file_name: format!("{}-{}.txt.gz", year, MONTH_NAMES[month as usize - 1]),
                year,
                month,
            })
            .collect();

        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("2025-November.txt.gz"), "x").unwrap();

        let files = files_to_download(&remote, dir.path(), Some((2026, 1))).unwrap();
        let keys: Vec<(u32, u32)> = files.iter().map(|f| f.key()).collect();
        assert_eq!(keys, vec![(2026, 1), (2026, 2)]);
    }

    #[test]
    fn test_archive_storage_dir() {
        let dir =
            archive_storage_dir("/tmp/db", "https://lists.denx.de/pipermail/u-boot/").unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/db/pipermail/lists.denx.de/u-boot"));
        assert!(archive_storage_dir("/tmp/db", "ftp://foo/bar/").is_err());
    }
}
