//! Pack consolidation for the lore archives under `<db_dir>/lore/`.
//!
//! Each fetch of a public-inbox archive writes the objects it received
//! into a new pack, and nothing removes those packs again. gitoxide
//! implements no repack, and unlike `git fetch` it does not hand off to
//! `git gc --auto` once the refs are updated. A daily refresh therefore
//! leaves one more pack behind every day, and every object lookup fans
//! out across all of their indices.
//!
//! Rolling every pack into one on each fetch trades that for a rewrite
//! of the whole archive, which on a large list costs minutes and a full
//! copy of a multi-hundred-megabyte pack. This module follows git's
//! geometric repacking instead: the packs are held in a size
//! progression where each holds at least twice the objects of
//! everything below it, and only the packs that break the progression
//! are combined. A routine refresh rolls up the handful of small packs
//! that recent fetches left and leaves the base pack alone.

use anyhow::{Context, Result};
use gix::odb::pack;
use std::path::{Path, PathBuf};
use tracing::info;

/// Each retained pack holds at least this many times the objects of
/// everything below it. Matches the default of `git repack --geometric`.
const GEOMETRIC_FACTOR: u64 = 2;

/// What a rollup replaced, for the caller to report.
pub struct RepackStats {
    pub packs_before: usize,
    pub packs_rolled_up: usize,
    pub objects_written: u64,
}

struct PackIndex {
    path: PathBuf,
    file: pack::index::File,
}

/// Roll up the packs of the repository at `repo_path` that break the
/// geometric size progression, once it holds more than `threshold`
/// packs.
///
/// Returns `Ok(None)` when the repository is under the threshold or
/// already forms a progression, leaving it untouched.
pub fn repack_if_needed(repo_path: &Path, threshold: usize) -> Result<Option<RepackStats>> {
    let repo = gix::open(repo_path).with_context(|| format!("opening {}", repo_path.display()))?;
    let object_hash = repo.object_hash();
    let pack_dir = repo.objects.store_ref().path().join("pack");

    let indices = collect_pack_indices(&pack_dir, object_hash)?;
    let packs_before = indices.len();
    if packs_before <= threshold {
        return Ok(None);
    }

    let counts: Vec<u64> = indices
        .iter()
        .map(|i| u64::from(i.file.num_objects()))
        .collect();
    let rollup = geometric_split(&counts, GEOMETRIC_FACTOR);
    if rollup < 2 {
        return Ok(None);
    }

    let to_roll = &indices[..rollup];
    info!(
        "Repacking {} of {} packs in {}",
        rollup,
        packs_before,
        repo_path.display()
    );

    // Every object of the packs about to be replaced, so the
    // replacement stands alone once they are gone.
    let mut ids = Vec::new();
    for index in to_roll {
        ids.extend(index.file.iter().map(|entry| entry.oid));
    }

    // The repository's handle wraps the object database in a proxy that
    // records writes for the in-memory overlay, and only the database
    // underneath it can serve pack entries.
    let mut odb = repo.objects.clone().into_inner();

    // Counting records the pack id of each object and the entry writer
    // resolves those ids afterwards. Both outlive the packs this
    // function goes on to delete, so the handle has to keep every pack
    // mapped rather than unloading one that leaves the directory.
    odb.prevent_pack_unload();

    let (object_counts, _) = pack::data::output::count::objects(
        odb.clone(),
        Box::new(ids.into_iter().map(Ok)),
        &gix::progress::Discard,
        &gix::interrupt::IS_INTERRUPTED,
        pack::data::output::count::objects::Options::default(),
    )?;

    let objects_written = object_counts.len() as u64;
    let chunks = pack::data::output::entry::iter_from_counts(
        object_counts,
        odb,
        Box::new(gix::progress::Discard),
        pack::data::output::entry::iter_from_counts::Options {
            // A thin pack is only valid in transit. Deltas whose base
            // sits in a retained pack are recompressed as base objects
            // so the result is a pack at rest.
            allow_thin_pack: false,
            ..Default::default()
        },
    );

    let mut staged = tempfile::NamedTempFile::new_in(&pack_dir)
        .with_context(|| format!("creating a staging pack in {}", pack_dir.display()))?;
    // The worker threads return their chunks in whatever order they
    // finish, and a delta entry names its base by the position that
    // base takes in the whole sequence.
    let mut writer = pack::data::output::bytes::FromEntriesIter::new(
        gix::features::parallel::InOrderIter::from(chunks),
        &mut staged,
        objects_written as u32,
        pack::data::Version::V2,
        object_hash,
    );
    for step in writer.by_ref() {
        step?;
    }

    let mut reader = std::io::BufReader::new(staged.reopen()?);
    let written = pack::Bundle::write_to_directory(
        &mut reader,
        Some(&pack_dir),
        &mut gix::progress::Discard,
        &gix::interrupt::IS_INTERRUPTED,
        None::<gix::odb::Handle>,
        pack::bundle::write::Options {
            object_hash,
            ..Default::default()
        },
    )?;

    // write_to_directory() creates the .keep before it moves the new
    // pack into place, which protects it across the window the old
    // packs are removed in. Drop the old packs first, then release it.
    for index in to_roll {
        remove_pack_files(&index.path, &written);
    }
    remove_multi_pack_index(&pack_dir);
    if let Some(keep) = &written.keep_path {
        std::fs::remove_file(keep).with_context(|| format!("releasing {}", keep.display()))?;
    }

    Ok(Some(RepackStats {
        packs_before,
        packs_rolled_up: rollup,
        objects_written,
    }))
}

/// Count of packs, smallest first, that must be combined for the rest
/// to form a geometric progression of ratio `factor`.
///
/// `counts` holds the object count of each pack, sorted ascending.
/// Returns 0 when the packs already form a progression.
fn geometric_split(counts: &[u64], factor: u64) -> usize {
    let mut split = 0;
    let mut below = 0u64;

    for (i, &count) in counts.iter().enumerate() {
        // A pack smaller than the tail beneath it cannot stand on its
        // own, so it joins the rollup along with everything under it.
        if i > 0 && count < factor.saturating_mul(below) {
            split = i;
        }
        below = below.saturating_add(count);
    }

    if split == 0 {
        0
    } else {
        split + 1
    }
}

/// How long a `.keep` file holds its pack out of a rollup.
///
/// git and gix both create the file once a fetched pack is complete
/// and remove it as soon as the refs that bind it are updated, so a
/// live hold lasts seconds. One that outlives this window was left by
/// a writer that died before releasing it, and would otherwise hold
/// the pack out of every rollup to come.
const KEEP_HOLD: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Whether the `.keep` at `keep` still holds its pack.
fn keep_is_held(keep: &Path) -> bool {
    let Ok(modified) = std::fs::metadata(keep).and_then(|m| m.modified()) else {
        return false;
    };
    match modified.elapsed() {
        Ok(age) => age < KEEP_HOLD,
        Err(_) => true,
    }
}

/// Open every pack index in `pack_dir`, smallest pack first.
///
/// An index without its pack is left out, as the object database
/// leaves it out: its objects cannot be served. A pack a concurrent
/// git has not finished writing is left out as well, and so is a pack
/// a fresh `.keep` file still holds, see [`KEEP_HOLD`].
fn collect_pack_indices(pack_dir: &Path, object_hash: gix::hash::Kind) -> Result<Vec<PackIndex>> {
    let mut indices = Vec::new();

    let entries = match std::fs::read_dir(pack_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(indices),
        Err(e) => return Err(e).with_context(|| format!("reading {}", pack_dir.display())),
    };

    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("idx") {
            continue;
        }
        // git names a finished index pack-<hash>.idx and one still
        // being written .tmp-<pid>-pack-<hash>.idx. Rolling up the
        // unfinished pack would delete it under the fetch writing it.
        let finished = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("pack-"));
        if !finished || !path.with_extension("pack").is_file() {
            continue;
        }
        if keep_is_held(&path.with_extension("keep")) {
            continue;
        }
        let file = pack::index::File::at(&path, object_hash)
            .with_context(|| format!("opening {}", path.display()))?;
        indices.push(PackIndex { path, file });
    }

    indices.sort_by_key(|index| index.file.num_objects());
    Ok(indices)
}

/// Remove the files of the pack named by the index at `idx_path`.
///
/// A failure is reported and the rollup carries on. Every object of
/// this pack is already in `written`, so a pack left behind costs disk
/// and one more index to search. A stale `.keep` goes with the pack it
/// held.
fn remove_pack_files(idx_path: &Path, written: &pack::bundle::write::Outcome) {
    for extension in ["idx", "pack", "rev", "mtimes", "bitmap", "keep"] {
        let path = idx_path.with_extension(extension);
        if Some(&path) == written.index_path.as_ref() || Some(&path) == written.data_path.as_ref() {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("Failed to remove {}: {}", path.display(), e),
        }
    }
}

/// Remove the multi-pack-index of `pack_dir`.
///
/// The index still names the packs a rollup replaced, and git reports
/// each of them as a failed load until the file is rebuilt. git repack
/// drops it the same way when it combines packs. The bitmap and
/// reverse index derived from it go too, as does the directory of an
/// incremental chain. The lockfile of a git writing a new one is left
/// to that git.
fn remove_multi_pack_index(pack_dir: &Path) {
    let entries = match std::fs::read_dir(pack_dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!("Failed to read {}: {}", pack_dir.display(), e);
            return;
        }
    };

    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let removed = if name == "multi-pack-index.d" {
            std::fs::remove_dir_all(&path)
        } else if name == "multi-pack-index" || name.starts_with("multi-pack-index-") {
            std::fs::remove_file(&path)
        } else {
            continue;
        };
        match removed {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("Failed to remove {}: {}", path.display(), e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_progression_is_left_alone() {
        assert_eq!(geometric_split(&[1, 10, 100], 2), 0);
        assert_eq!(geometric_split(&[1, 2, 8], 2), 0);
    }

    #[test]
    fn equal_packs_all_roll_up() {
        assert_eq!(geometric_split(&[10, 10, 10], 2), 3);
    }

    #[test]
    fn a_base_pack_outgrows_the_rollup() {
        // The shape a lore archive takes: one clone plus a run of small
        // incremental fetches.
        assert_eq!(geometric_split(&[1, 1, 1, 1, 100_000], 2), 4);
    }

    #[test]
    fn too_few_packs_to_split() {
        assert_eq!(geometric_split(&[], 2), 0);
        assert_eq!(geometric_split(&[5], 2), 0);
    }

    #[test]
    fn one_violator_pulls_in_everything_below_it() {
        assert_eq!(geometric_split(&[1, 4, 5, 1000], 2), 3);
    }

    /// Run a git command in a directory, panic on failure.
    fn git(repo: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            // git commit hands off to gc --auto, which detaches and
            // rewrites the pack directory while the test reads it.
            .args([
                "-c",
                "gc.auto=0",
                "-c",
                "gc.autoDetach=false",
                "-c",
                "maintenance.auto=false",
            ])
            .args(args)
            .current_dir(repo)
            // Do not inherit developer's git configuration.
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .expect("git command failed to execute");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn count_packs(repo: &Path) -> usize {
        std::fs::read_dir(repo.join(".git/objects/pack"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("idx"))
            .count()
    }

    /// Build a repository holding one pack per commit, the shape
    /// repeated fetches leave behind.
    fn packs_per_commit(repo_path: &Path, commits: usize) {
        git(repo_path, &["init", "-q", "-b", "main", "."]);
        for i in 0..commits {
            std::fs::write(repo_path.join("m"), format!("message {i}\n")).unwrap();
            git(repo_path, &["add", "m"]);
            git(repo_path, &["commit", "-q", "-m", &format!("commit {i}")]);
            git(repo_path, &["repack", "-d", "-q"]);
        }
    }

    /// The path of one pack index in `repo_path`.
    fn some_pack_index(repo_path: &Path) -> PathBuf {
        std::fs::read_dir(repo_path.join(".git/objects/pack"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| p.extension().and_then(|e| e.to_str()) == Some("idx"))
            .expect("the fixture packed something")
    }

    #[test]
    fn a_rollup_preserves_every_object() {
        let tmpdir = tempfile::tempdir().unwrap();
        let repo_path = tmpdir.path().to_path_buf();
        packs_per_commit(&repo_path, 8);
        let packs_before = count_packs(&repo_path);
        assert!(packs_before > 2, "fixture produced {packs_before} packs");

        let repo = gix::open(&repo_path).unwrap();
        let pack_dir = repo.objects.store_ref().path().join("pack");
        let before: Vec<gix::ObjectId> = collect_pack_indices(&pack_dir, repo.object_hash())
            .unwrap()
            .iter()
            .flat_map(|index| index.file.iter().map(|e| e.oid).collect::<Vec<_>>())
            .collect();
        assert!(!before.is_empty());

        let stats = repack_if_needed(&repo_path, 2)
            .unwrap()
            .expect("packs above the threshold roll up");
        assert_eq!(stats.packs_before, packs_before);
        assert!(count_packs(&repo_path) < packs_before);

        let repo = gix::open(&repo_path).unwrap();
        for oid in &before {
            assert!(
                repo.find_object(*oid).is_ok(),
                "{oid} did not survive the rollup"
            );
        }
    }

    #[test]
    fn a_repository_under_the_threshold_is_left_alone() {
        let tmpdir = tempfile::tempdir().unwrap();
        let repo_path = tmpdir.path().to_path_buf();
        packs_per_commit(&repo_path, 1);

        assert!(repack_if_needed(&repo_path, 20).unwrap().is_none());
        assert_eq!(count_packs(&repo_path), 1);
    }

    #[test]
    fn an_in_flight_pack_is_left_alone() {
        let tmpdir = tempfile::tempdir().unwrap();
        let repo_path = tmpdir.path().to_path_buf();
        packs_per_commit(&repo_path, 8);

        // What a fetch writing a pack alongside the rollup leaves in
        // the directory.
        let idx = some_pack_index(&repo_path);
        let tmp = idx.with_file_name(".tmp-1234-pack-cafe.idx");
        std::fs::copy(&idx, &tmp).unwrap();
        std::fs::copy(idx.with_extension("pack"), tmp.with_extension("pack")).unwrap();

        repack_if_needed(&repo_path, 2)
            .unwrap()
            .expect("packs above the threshold roll up");

        assert!(tmp.exists(), "the in-flight index was rolled up");
        assert!(
            tmp.with_extension("pack").exists(),
            "the in-flight pack was rolled up"
        );
    }

    #[test]
    fn a_held_pack_is_left_alone() {
        let tmpdir = tempfile::tempdir().unwrap();
        let repo_path = tmpdir.path().to_path_buf();
        packs_per_commit(&repo_path, 8);

        // A fetch that has written its pack and is updating the refs.
        let idx = some_pack_index(&repo_path);
        let keep = idx.with_extension("keep");
        std::fs::write(&keep, b"").unwrap();

        repack_if_needed(&repo_path, 2)
            .unwrap()
            .expect("packs above the threshold roll up");

        assert!(idx.exists(), "the held pack was rolled up");
        assert!(keep.exists(), "the hold was released");
    }

    #[test]
    fn a_stale_hold_is_released() {
        let tmpdir = tempfile::tempdir().unwrap();
        let repo_path = tmpdir.path().to_path_buf();
        packs_per_commit(&repo_path, 8);

        // A fetch that died before it released its pack.
        let idx = some_pack_index(&repo_path);
        let keep = idx.with_extension("keep");
        let file = std::fs::File::create(&keep).unwrap();
        file.set_modified(std::time::SystemTime::now() - 2 * KEEP_HOLD)
            .unwrap();

        repack_if_needed(&repo_path, 2)
            .unwrap()
            .expect("packs above the threshold roll up");

        assert!(!idx.exists(), "the stale hold kept its pack out");
        assert!(!keep.exists(), "the stale hold survived");
    }

    #[test]
    fn an_index_without_its_pack_is_left_alone() {
        let tmpdir = tempfile::tempdir().unwrap();
        let repo_path = tmpdir.path().to_path_buf();
        packs_per_commit(&repo_path, 8);

        // What an interrupted writer leaves behind: objects the index
        // names but nothing can serve.
        let idx = some_pack_index(&repo_path);
        std::fs::remove_file(idx.with_extension("pack")).unwrap();

        repack_if_needed(&repo_path, 2)
            .unwrap()
            .expect("packs above the threshold roll up");

        assert!(idx.exists(), "the orphan index was rolled up");
    }

    #[test]
    fn a_rollup_drops_the_multi_pack_index() {
        let tmpdir = tempfile::tempdir().unwrap();
        let repo_path = tmpdir.path().to_path_buf();
        packs_per_commit(&repo_path, 8);
        git(&repo_path, &["multi-pack-index", "write"]);

        let midx = repo_path.join(".git/objects/pack/multi-pack-index");
        assert!(midx.exists(), "the fixture wrote no multi-pack-index");

        repack_if_needed(&repo_path, 2)
            .unwrap()
            .expect("packs above the threshold roll up");

        assert!(!midx.exists(), "the stale multi-pack-index survived");
    }
}
