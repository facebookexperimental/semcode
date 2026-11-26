// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `--result-json` report. The contract is in docs/index-result.md.

use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Serialize, Debug)]
pub struct Report {
    pub version: u32,
    pub branches: Vec<BranchReport>,
}

impl Report {
    pub fn branches(branches: Vec<BranchReport>) -> Self {
        Self {
            version: 1,
            branches,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct BranchReport {
    pub name: String,
    pub outcome: Outcome,
    /// The tip the database records for this name after the run.
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Indexed,
    Current,
    Failed,
}

/// Where a report goes. Preparing it removes any report an earlier run
/// left at the path and checks that a file can be created beside it, so
/// an unusable destination fails the run before indexing starts and a
/// stale report never outlives the run that replaced it.
pub struct ReportSink {
    path: PathBuf,
}

impl ReportSink {
    pub fn prepare(path: &Path) -> Result<Self> {
        let raw = path.to_string_lossy();
        if path.file_name().is_none()
            || raw.ends_with(std::path::is_separator)
            || raw.ends_with("/.")
        {
            anyhow::bail!("report path {} does not name a file", path.display());
        }
        let path = std::path::absolute(path)
            .with_context(|| format!("cannot resolve report path {}", path.display()))?;
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("cannot remove old report {}", path.display()))
            }
        }
        let sink = Self { path };
        // Probe that the directory takes a new file; dropping it deletes it.
        sink.temp_file()?;
        Ok(sink)
    }

    fn parent(&self) -> &Path {
        // prepare only accepts paths that name a file, so there is a parent.
        self.path.parent().unwrap_or(Path::new("/"))
    }

    fn temp_file(&self) -> Result<tempfile::NamedTempFile> {
        let mut builder = tempfile::Builder::new();
        builder.prefix(".semcode-result-");
        // Ordinary file permissions under the umask, not the private 0600
        // a temporary file gets by default: the report is meant to be read.
        #[cfg(unix)]
        builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o666));
        builder
            .tempfile_in(self.parent())
            .with_context(|| format!("cannot create report in {}", self.parent().display()))
    }

    /// Write the report beside the destination and rename it into place.
    pub fn publish(self, report: &Report) -> Result<()> {
        let mut temp = self.temp_file()?;
        serde_json::to_writer_pretty(&mut temp, report)?;
        temp.write_all(b"\n")?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path)
            .map_err(|e| e.error)
            .with_context(|| format!("cannot publish report {}", self.path.display()))?;
        // Make the rename itself durable.
        #[cfg(unix)]
        std::fs::File::open(self.parent())
            .and_then(|dir| dir.sync_all())
            .with_context(|| format!("cannot sync {}", self.parent().display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_the_v1_shape() {
        let report = Report::branches(vec![
            BranchReport {
                name: "main".into(),
                outcome: Outcome::Indexed,
                commit: Some("a".repeat(40)),
                error: None,
            },
            BranchReport {
                name: "nope".into(),
                outcome: Outcome::Failed,
                commit: None,
                error: Some("missing".into()),
            },
        ]);
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "version": 1,
                "branches": [
                    { "name": "main", "outcome": "indexed", "commit": "a".repeat(40) },
                    { "name": "nope", "outcome": "failed", "commit": null, "error": "missing" }
                ]
            })
        );
    }

    #[test]
    fn prepare_removes_a_stale_report_and_publish_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("result.json");
        std::fs::write(&path, "stale").unwrap();
        let sink = ReportSink::prepare(&path).unwrap();
        assert!(!path.exists(), "a stale report must not survive prepare");
        sink.publish(&Report::branches(Vec::new())).unwrap();
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written, serde_json::json!({ "version": 1, "branches": [] }));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn prepare_rejects_unusable_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("taken")).unwrap();
        for path in [
            "missing/result.json",
            "result.json/",
            "taken",
            "taken/.",
            "..",
        ] {
            assert!(
                ReportSink::prepare(&dir.path().join(path)).is_err(),
                "{path} must be refused"
            );
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_report_gets_ordinary_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let umask = status
            .lines()
            .find_map(|l| l.strip_prefix("Umask:"))
            .map(|m| u32::from_str_radix(m.trim(), 8).unwrap())
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("result.json");
        ReportSink::prepare(&path)
            .unwrap()
            .publish(&Report::branches(Vec::new()))
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o666 & !umask);
    }
}
