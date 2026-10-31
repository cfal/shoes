use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use tokio::sync::mpsc;

#[derive(Clone, Default)]
pub(crate) struct EventFilter {
    stamps: Arc<Mutex<HashMap<PathBuf, Option<FileStamp>>>>,
}

impl EventFilter {
    fn seed(&self, files: &HashSet<PathBuf>) {
        let mut stamps = self.stamps.lock();
        for path in files {
            stamps
                .entry(path.clone())
                .or_insert_with(|| FileStamp::read(path));
        }
    }

    fn registered(&self, files: &HashSet<PathBuf>) {
        self.stamps.lock().retain(|path, _| files.contains(path));
    }

    fn notify<'a>(&self, paths: impl Iterator<Item = &'a PathBuf>, tx: &mpsc::Sender<()>) {
        let mut stamps = self.stamps.lock();
        let mut changed = false;
        for path in paths {
            let current = FileStamp::read(path);
            if let Some(previous) = stamps.get_mut(path) {
                changed |= current.is_none() || *previous != current;
                *previous = current;
            } else {
                // Retired callbacks must not recreate pruned entries.
                changed = true;
            }
        }
        if changed {
            let _ = tx.try_send(());
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    device: u64,
    inode: u64,
    mode: u32,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileStamp {
    #[cfg(unix)]
    fn read(path: &Path) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path).ok()?;
        if !metadata.is_file() {
            return None;
        }
        let stamp = Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        stamp
            .reliable((
                i64::try_from(now.as_secs()).ok()?,
                i64::from(now.subsec_nanos()),
            ))
            .then_some(stamp)
    }

    #[cfg(not(unix))]
    fn read(_path: &Path) -> Option<Self> {
        None
    }

    #[cfg(any(unix, test))]
    fn reliable(&self, now: (i64, i64)) -> bool {
        // Coarse or future timestamps cannot distinguish a replay from a real rewrite.
        (self.modified.1 % 1_000_000 != 0 || self.changed.1 % 1_000_000 != 0)
            && self.modified <= now
            && self.changed <= now
    }
}

pub(crate) fn watch<P: AsRef<Path>>(
    paths: &[P],
    tx: mpsc::Sender<()>,
) -> io::Result<RecommendedWatcher> {
    watch_excluding(paths, tx, None, None)
}

pub(crate) fn watch_excluding<P: AsRef<Path>>(
    paths: &[P],
    tx: mpsc::Sender<()>,
    excluded: Option<&Path>,
    filter: Option<&EventFilter>,
) -> io::Result<RecommendedWatcher> {
    let mut files = HashSet::new();
    let mut required_directories = HashSet::new();
    for path in paths {
        let path = std::path::absolute(path)?;
        if let Some(parent) = path.parent() {
            required_directories.insert(parent.to_path_buf());
        }
        if let Ok(canonical) = std::fs::canonicalize(&path) {
            if let Some(parent) = canonical.parent() {
                required_directories.insert(parent.to_path_buf());
            }
            files.insert(canonical);
        }
        files.insert(path.clone());
        if let Err(error) = resolve_watch_path(&path, &mut files, &mut 0) {
            log::warn!(
                "Could not resolve watch path {}: {error}; retaining lexical and discovered paths for recovery",
                path.display()
            );
        }
    }
    let excluded = excluded.map(std::path::absolute).transpose()?;
    let resolved = excluded
        .as_ref()
        .map(|root| root.canonicalize().unwrap_or_else(|_| root.clone()));
    let included = |path: &Path| {
        !excluded.as_ref().is_some_and(|root| path.starts_with(root))
            && !resolved.as_ref().is_some_and(|root| path.starts_with(root))
    };
    files.retain(|path| included(path));
    let required_directories: HashSet<_> = required_directories
        .iter()
        .map(|path| watch_directory(path))
        .collect();
    let directories: HashSet<_> = files
        .iter()
        .filter_map(|path| path.parent()?.ancestors().find(|parent| parent.is_dir()))
        .map(watch_directory)
        .collect();
    let direct_files: HashSet<_> = files
        .iter()
        .filter_map(|path| std::fs::canonicalize(path).ok())
        .filter(|path| included(path))
        .filter(|path| path.is_file())
        .collect();
    files.extend(direct_files.iter().cloned());
    // Preserve prior observations across rebuilds, including failed registrations:
    // the caller may still read these paths before retrying the watch.
    // Registration and watcher destruction must run without the callback's lock.
    if let Some(filter) = filter {
        filter.seed(&files);
    }
    let files = Arc::new(files);
    let event_files = files.clone();
    let event_filter = filter.cloned();
    let mut watcher =
        notify::recommended_watcher(move |result: notify::Result<notify::Event>| match result {
            Ok(event)
                if matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                ) && event.paths.iter().any(|path| event_files.contains(path)) =>
            {
                if let Some(filter) = &event_filter {
                    filter.notify(
                        event
                            .paths
                            .iter()
                            .filter(|path| event_files.contains(*path)),
                        &tx,
                    );
                } else {
                    let _ = tx.try_send(());
                }
            }
            Err(error) => log::warn!("File watcher failed: {error}"),
            _ => {}
        })
        .map_err(io::Error::other)?;
    register_paths(
        |path| watcher.watch(path, RecursiveMode::NonRecursive),
        &directories,
        &required_directories,
        &direct_files,
    )?;
    if let Some(filter) = filter {
        filter.registered(&files);
    }
    Ok(watcher)
}

fn register_paths(
    mut register: impl FnMut(&Path) -> notify::Result<()>,
    directories: &HashSet<PathBuf>,
    required_directories: &HashSet<PathBuf>,
    direct_files: &HashSet<PathBuf>,
) -> io::Result<()> {
    for directory in directories {
        if let Err(error) = register(directory) {
            if is_stream_failure(&error) {
                return Err(io::Error::other(error));
            }
            if required_directories.contains(directory) {
                if !matches!(&error.kind, notify::ErrorKind::Io(error) if error.kind() == io::ErrorKind::PermissionDenied)
                {
                    return Err(io::Error::other(error));
                }
                log::warn!(
                    "Could not watch directory {}: {error}; using file watches, atomic replacements may be missed",
                    directory.display()
                );
            } else {
                log::warn!(
                    "Could not watch intermediate directory {}: {error}",
                    directory.display()
                );
            }
        }
    }
    for file in direct_files {
        if let Err(error) = register(file) {
            if is_stream_failure(&error) {
                return Err(io::Error::other(error));
            }
            let missing = match &error.kind {
                notify::ErrorKind::PathNotFound => true,
                notify::ErrorKind::Io(error) => error.kind() == io::ErrorKind::NotFound,
                _ => false,
            };
            if !missing {
                log::warn!("Could not watch file {}: {error}", file.display());
            }
        }
    }
    Ok(())
}

fn is_stream_failure(error: &notify::Error) -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    // FSEvents restarts the entire stream for each path; a failed restart loses all watches.
    match &error.kind {
        notify::ErrorKind::Generic(_) => true,
        notify::ErrorKind::Io(error) => !matches!(
            error.kind(),
            io::ErrorKind::NotFound
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::NotADirectory
        ),
        _ => false,
    }
}

fn watch_directory(path: &Path) -> PathBuf {
    // inotify keeps one event path per inode; register directory aliases only once.
    #[cfg(unix)]
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    path.to_path_buf()
}

fn resolve_watch_path(
    path: &Path,
    files: &mut HashSet<PathBuf>,
    symlinks: &mut usize,
) -> io::Result<PathBuf> {
    let mut resolved = PathBuf::new();
    for component in path.components() {
        if component == Component::ParentDir {
            resolved.pop();
            continue;
        }
        resolved.push(component);
        match std::fs::symlink_metadata(&resolved) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                *symlinks += 1;
                if *symlinks > 40 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "too many file symlinks",
                    ));
                }
                let target = resolved
                    .parent()
                    .unwrap()
                    .join(std::fs::read_link(&resolved)?);
                if cfg!(target_os = "macos") && resolved.parent() == Some(Path::new("/")) {
                    // System-volume links cannot be retargeted; tracking them subscribes
                    // FSEvents to the entire filesystem even with NonRecursive watches.
                    resolved = resolve_watch_path(&target, &mut HashSet::new(), symlinks)?;
                } else {
                    files.insert(resolved.clone());
                    resolved = resolve_watch_path(&target, files, symlinks)?;
                }
            }
            // Retain missing components so creating a target or its parent triggers another reload.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                files.insert(resolved.clone());
            }
            Err(error) => return Err(error),
            Ok(_) => {}
        }
    }
    files.insert(resolved.clone());
    Ok(resolved)
}

/// Wait for a quiet period after the first filesystem event has been received.
pub(crate) async fn debounce(changes: &mut mpsc::Receiver<()>, delay: Duration) {
    loop {
        tokio::select! {
            biased;
            event = changes.recv() => {
                if event.is_none() {
                    return;
                }
            },
            _ = tokio::time::sleep(delay) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn new_config_watches_ignore_delayed_creation_events() {
        for _ in 0..64 {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("config.yaml");
            std::fs::write(&path, "config").unwrap();
            let filter = EventFilter::default();
            let (tx, mut changes) = mpsc::channel(1);
            let _watcher =
                watch_excluding(std::slice::from_ref(&path), tx, None, Some(&filter)).unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(50), changes.recv())
                    .await
                    .is_err()
            );
            std::fs::write(&path, "config").unwrap();
            tokio::time::timeout(Duration::from_secs(2), changes.recv())
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn event_filter_requires_precise_nonfuture_timestamps() {
        let mut stamp = FileStamp {
            device: 1,
            inode: 2,
            mode: 0o100600,
            size: 6,
            modified: (10, 123),
            changed: (10, 456),
        };
        assert!(stamp.reliable((11, 0)));
        assert!(!stamp.reliable((10, 200)));
        assert!(!stamp.reliable((9, 0)));
        stamp.modified.1 = 1_000_000;
        stamp.changed.1 = 2_000_000;
        assert!(!stamp.reliable((11, 0)));
        stamp.changed.1 += 1;
        assert!(stamp.reliable((11, 0)));
    }

    #[cfg(unix)]
    #[test]
    fn event_filter_preserves_changes_across_rebuilds_and_coalesces_all_paths() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        for path in [&first, &second] {
            std::fs::write(path, "before").unwrap();
            assert!(FileStamp::read(path).is_some());
        }
        let files = HashSet::from([first.clone(), second.clone()]);
        let filter = EventFilter::default();
        filter.seed(&files);
        filter.registered(&files);
        let before = filter.stamps.lock().clone();
        let (tx, mut changes) = mpsc::channel(1);
        filter.notify(files.iter(), &tx);
        assert!(changes.try_recv().is_err());

        std::fs::write(&first, "after").unwrap();
        std::fs::write(&second, "after").unwrap();
        filter.seed(&files);
        filter.registered(&files);
        assert_eq!(*filter.stamps.lock(), before);
        tx.try_send(()).unwrap();
        filter.notify(files.iter(), &tx);
        changes.try_recv().unwrap();
        filter.notify(files.iter(), &tx);
        assert!(changes.try_recv().is_err());

        std::fs::File::open(&first)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + Duration::new(10, 123))
            .unwrap();
        filter.notify(files.iter(), &tx);
        changes.try_recv().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn event_filter_registration_failure_and_retired_callbacks_preserve_state() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        std::fs::write(&first, "first").unwrap();
        std::fs::write(&second, "second").unwrap();
        let filter = EventFilter::default();
        let original = HashSet::from([first.clone()]);
        filter.seed(&original);
        let before = filter.stamps.lock()[&first];
        let candidate = HashSet::from([second.clone()]);
        filter.seed(&candidate);
        // A failed registration leaves the candidate read outside watcher coverage.
        assert_eq!(filter.stamps.lock().len(), 2);
        assert_eq!(filter.stamps.lock()[&first], before);

        assert_eq!(std::fs::read_to_string(&second).unwrap(), "second");
        std::fs::write(&second, "edited after the candidate read").unwrap();
        filter.seed(&candidate);
        filter.registered(&candidate);
        let (tx, mut changes) = mpsc::channel(1);
        filter.notify(candidate.iter(), &tx);
        changes
            .try_recv()
            .expect("the edit must survive a failed registration");
        filter.notify(original.iter(), &tx);
        changes.try_recv().unwrap();
        assert!(!filter.stamps.lock().contains_key(&first));
        assert_eq!(filter.stamps.lock().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn event_filter_forwards_uncertain_paths_and_keeps_channels_independent() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        let missing = directory.path().join("missing");
        std::fs::write(&target, "before").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let files = HashSet::from([target.clone(), link.clone(), missing.clone()]);
        let normal = EventFilter::default();
        let recovery = EventFilter::default();
        normal.seed(&files);
        recovery.seed(&files);
        let (tx, mut changes) = mpsc::channel(1);
        for path in [&link, &missing] {
            for _ in 0..2 {
                normal.notify(std::iter::once(path), &tx);
                changes.try_recv().unwrap();
            }
        }
        std::fs::write(&target, "after").unwrap();
        recovery.notify(std::iter::once(&target), &tx);
        changes.try_recv().unwrap();
        normal.notify(std::iter::once(&target), &tx);
        changes.try_recv().unwrap();
        std::fs::remove_file(&target).unwrap();
        normal.notify(std::iter::once(&target), &tx);
        changes.try_recv().unwrap();
        std::fs::write(&target, "after").unwrap();
        normal.notify(std::iter::once(&target), &tx);
        changes.try_recv().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stream_failure_is_fatal_for_every_registration_kind() {
        let directory = PathBuf::from("directory");
        let file = directory.join("config.yaml");
        let failures: [fn() -> notify::Error; 2] = [
            || notify::Error::generic("unable to start FSEvent stream"),
            || notify::Error::io(io::ErrorKind::WouldBlock.into()),
        ];
        for failure in failures {
            for required in [false, true] {
                let directories = HashSet::from([directory.clone()]);
                let required_directories = if required {
                    directories.clone()
                } else {
                    HashSet::new()
                };
                assert!(
                    register_paths(
                        |_| Err(failure()),
                        &directories,
                        &required_directories,
                        &HashSet::new(),
                    )
                    .is_err()
                );
            }
            let mut registered = Vec::new();
            assert!(
                register_paths(
                    |path| {
                        registered.push(path.to_path_buf());
                        if path == file { Err(failure()) } else { Ok(()) }
                    },
                    &HashSet::from([directory.clone()]),
                    &HashSet::from([directory.clone()]),
                    &HashSet::from([file.clone()]),
                )
                .is_err()
            );
            assert_eq!(registered, [directory.clone(), file.clone()]);
        }
    }

    #[test]
    fn path_local_watch_failures_retain_recovery_fallbacks() {
        let directory = PathBuf::from("directory");
        let file = directory.join("config.yaml");
        register_paths(
            |path| {
                let kind = if path == file {
                    io::ErrorKind::NotFound
                } else {
                    io::ErrorKind::PermissionDenied
                };
                Err(notify::Error::io(kind.into()))
            },
            &HashSet::from([directory.clone()]),
            &HashSet::from([directory]),
            &HashSet::from([file.clone()]),
        )
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn debounce_waits_for_quiet_after_the_last_event() {
        let (tx, mut changes) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            debounce(&mut changes, Duration::from_secs(3)).await;
        });
        tokio::task::yield_now().await;
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(!task.is_finished());
            tx.send(()).await.unwrap();
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        task.await.unwrap();
    }

    #[tokio::test]
    async fn debounce_stops_when_the_event_channel_closes() {
        let (tx, mut changes) = mpsc::channel(1);
        drop(tx);
        tokio::time::timeout(
            Duration::from_secs(1),
            debounce(&mut changes, Duration::from_secs(3)),
        )
        .await
        .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn directory_aliases_preserve_missing_target_notifications() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let target = root.join("target");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, root.join("alias")).unwrap();
        let existing = root.join("alias/existing.yaml");
        std::fs::write(&existing, "existing").unwrap();
        let missing = target.join("missing.yaml");
        let (tx, mut events) = mpsc::channel(1);
        let _watcher = watch(
            &[
                existing.to_str().unwrap().to_owned(),
                missing.to_str().unwrap().to_owned(),
            ],
            tx,
        )
        .unwrap();
        std::fs::write(&missing, "created").unwrap();
        tokio::time::timeout(Duration::from_secs(3), events.recv())
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn system_symlinks_do_not_add_root_directory_watches() {
        let mut files = HashSet::new();
        resolve_watch_path(Path::new("/var/db/config.yaml"), &mut files, &mut 0).unwrap();
        assert!(files.contains(Path::new("/private/var/db/config.yaml")));
        assert!(!files.contains(Path::new("/var")));
        assert!(!files.contains(Path::new("/private/var")));
    }

    #[cfg(unix)]
    #[test]
    fn watch_paths_include_missing_targets_and_symlinked_parents() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("targets")).unwrap();
        std::os::unix::fs::symlink("targets", root.join("alias")).unwrap();
        std::os::unix::fs::symlink("alias/missing/config.yaml", root.join("config.yaml")).unwrap();
        let mut files = HashSet::new();
        resolve_watch_path(&root.join("config.yaml"), &mut files, &mut 0).unwrap();
        for path in [
            "config.yaml",
            "alias",
            "targets/missing",
            "targets/missing/config.yaml",
        ] {
            assert!(files.contains(&root.join(path)), "missing {path}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn watch_paths_reject_symlink_cycles() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yaml");
        std::os::unix::fs::symlink("config.yaml", &path).unwrap();
        assert_eq!(
            resolve_watch_path(&path, &mut HashSet::new(), &mut 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
