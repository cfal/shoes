use std::{env, path::Path, process::Command};

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("--no-optional-locks")
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn watch_git_path(name: &str) -> bool {
    if let Some(path) = git(&["rev-parse", "--git-path", name]) {
        let path = path.trim();
        if Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
            return true;
        }
    }
    false
}

fn checkout_revision() -> Option<String> {
    // Archives nested inside another repository must not inherit its revision.
    if !Path::new(".git").exists() {
        return None;
    }
    if Path::new(".git").is_file() {
        println!("cargo:rerun-if-changed=.git");
    }
    // Git resolves both linked-worktree metadata and shared refs.
    watch_git_path("HEAD");
    watch_git_path("index");
    if !watch_git_path("reftable")
        && let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"])
        && !watch_git_path(branch.trim())
    {
        // A packed branch can acquire a loose ref on the next commit.
        watch_git_path("packed-refs");
        watch_git_path("refs/heads");
    }
    for path in git(&["ls-files", "-z"])?
        .split('\0')
        .filter(|p| !p.is_empty())
    {
        if Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let hash = git(&["rev-parse", "--verify", "HEAD"])?;
    let status = git(&["status", "--porcelain", "--untracked-files=no"])?;
    let dirty = if status.is_empty() { "" } else { ".dirty" };
    Some(format!("{}{dirty}", hash.trim()))
}

fn input(name: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed={name}");
    env::var(name).ok().filter(|value| !value.is_empty())
}

fn main() {
    env::set_current_dir(env::var_os("CARGO_MANIFEST_DIR").unwrap()).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    let release_tag = input("SHOES_RELEASE_TAG");
    let supplied_revision = input("SHOES_BUILD_REVISION");
    let checkout = checkout_revision();
    let revision = supplied_revision.as_ref().or(checkout.as_ref());
    if let Some(revision) = revision {
        let hash = revision.strip_suffix(".dirty").unwrap_or(revision);
        assert!(
            (12..=64).contains(&hash.len()) && hash.bytes().all(|b| b.is_ascii_hexdigit()),
            "SHOES_BUILD_REVISION must be a 12-64 digit Git hash, optionally followed by .dirty"
        );
    }
    let dirty = [revision, checkout.as_ref()]
        .into_iter()
        .flatten()
        .any(|revision| revision.ends_with(".dirty"));
    let package_version = env::var("CARGO_PKG_VERSION").unwrap();
    let version = if let Some(tag) = release_tag {
        assert_eq!(
            tag,
            format!("v{package_version}"),
            "Release tag does not match package version"
        );
        assert!(!dirty, "Official releases require a clean checkout");
        package_version
    } else {
        let suffix = match revision {
            Some(revision) => format!("g{}", revision[..12].to_ascii_lowercase()),
            None => "unknown".to_owned(),
        };
        let dirty = if dirty { ".dirty" } else { "" };
        format!("{package_version}+{suffix}{dirty}")
    };
    let compiler = Command::new(env::var_os("RUSTC").unwrap())
        .arg("--version")
        .output()
        .expect("Cannot query Rust compiler version");
    assert!(
        compiler.status.success(),
        "Cannot query Rust compiler version"
    );
    let compiler = String::from_utf8(compiler.stdout).unwrap();
    println!("cargo:rustc-env=SHOES_VERSION={version}");
    println!(
        "cargo:rustc-env=SHOES_TARGET={}",
        env::var("TARGET").unwrap()
    );
    println!("cargo:rustc-env=SHOES_COMPILER={}", compiler.trim());
}
