use std::collections::HashSet;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

pub(crate) fn watch<P: AsRef<Path>>(
    paths: &[P],
    tx: mpsc::Sender<()>,
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
        .filter(|path| path.is_file())
        .collect();
    files.extend(direct_files.iter().cloned());
    let mut watcher =
        notify::recommended_watcher(move |result: notify::Result<notify::Event>| match result {
            Ok(event)
                if matches!(
                    event.kind,
                    EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                ) && event.paths.iter().any(|path| files.contains(path)) =>
            {
                let _ = tx.try_send(());
            }
            Err(error) => log::warn!("File watcher failed: {error}"),
            _ => {}
        })
        .map_err(io::Error::other)?;
    for directory in directories {
        if let Err(error) = watcher.watch(&directory, RecursiveMode::NonRecursive) {
            if required_directories.contains(&directory) {
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
        if let Err(error) = watcher.watch(&file, RecursiveMode::NonRecursive) {
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
    Ok(watcher)
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
