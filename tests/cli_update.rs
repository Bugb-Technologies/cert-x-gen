//! `cxg update` against the install layouts it must handle.
//!
//! Each test copies the built binary into a temp root and runs it through the
//! layout under test, from a working directory elsewhere in that root. That
//! is the condition the relative-symlink failure needed: Homebrew links
//! `bin/cxg -> ../Cellar/cxg/<version>/bin/cxg`, and the old updater resolved
//! that target against the working directory.
//!
//! The package-manager tests are offline: the refusal is decided before any
//! release lookup, and the proxy is pointed at a closed port so that a lookup
//! would fail rather than quietly succeed. The tests that download a real
//! release run only with `CXG_LIVE_UPDATE_TEST=1`.
//!
//! Unix-only, since the layouts are symlinks.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A release that exists and carries `SHA256SUMS`, for the live tests.
const LIVE_TAG: &str = "v1.6.0";

/// Copy the built binary to `root/<rel>`, creating its directories.
fn install_copy(root: &Path, rel: &str) -> PathBuf {
    let dest = root.join(rel);
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_cxg"), &dest).unwrap();
    dest
}

/// Link `root/<link>` to the relative `target`, as Homebrew does.
fn relative_link(root: &Path, link: &str, target: &str) -> PathBuf {
    let link = root.join(link);
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    symlink(target, &link).unwrap();
    link
}

/// Run `exe update <args>` from `root/elsewhere`, with a temp home. An
/// `offline` run points every proxy variable at a closed port.
fn run_update(
    root: &Path,
    exe: &Path,
    args: &[&str],
    envs: &[(&str, &Path)],
    offline: bool,
) -> Output {
    let cwd = root.join("elsewhere");
    fs::create_dir_all(&cwd).unwrap();
    let mut cmd = Command::new(exe);
    cmd.arg("update")
        .args(args)
        .current_dir(&cwd)
        .env("HOME", root.join("home"))
        .env("CARGO_HOME", root.join("no-cargo-home"));
    if offline {
        for key in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            cmd.env(key, "http://127.0.0.1:9");
        }
    }
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn a_homebrew_install_is_pointed_at_brew_and_left_untouched() {
    let root = tempfile::tempdir().unwrap();
    let real = install_copy(root.path(), "brew/Cellar/cxg/1.5.0/bin/cxg");
    let link = relative_link(root.path(), "brew/bin/cxg", "../Cellar/cxg/1.5.0/bin/cxg");
    let before = fs::read(&real).unwrap();

    let out = run_update(root.path(), &link, &["--yes"], &[], true);

    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "stderr: {stderr}");
    assert!(stderr.contains("managed by Homebrew"), "stderr: {stderr}");
    assert!(stderr.contains("brew upgrade cxg"), "stderr: {stderr}");
    assert_eq!(fs::read(&real).unwrap(), before, "the Cellar file changed");
    assert!(fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn a_cargo_install_is_pointed_at_cargo_install_and_left_untouched() {
    let root = tempfile::tempdir().unwrap();
    let exe = install_copy(root.path(), "cargo/bin/cxg");
    let before = fs::read(&exe).unwrap();

    let cargo_home = root.path().join("cargo");
    let out = run_update(
        root.path(),
        &exe,
        &["--yes"],
        &[("CARGO_HOME", &cargo_home)],
        true,
    );

    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "stderr: {stderr}");
    assert!(
        stderr.contains("cargo install cert-x-gen --force"),
        "stderr: {stderr}"
    );
    assert_eq!(fs::read(&exe).unwrap(), before, "the cargo binary changed");
}

/// Install `LIVE_TAG` through `link` and check it landed in `real`.
fn assert_live_update_through(root: &Path, link: &Path, real: &Path, extra: &[&str]) {
    let before = fs::read(real).unwrap();
    let mut args = vec!["--yes", "--version", LIVE_TAG];
    args.extend_from_slice(extra);
    let out = run_update(root, link, &args, &[], false);

    let stdout = text(&out.stdout);
    assert!(
        out.status.success(),
        "stdout: {stdout}\nstderr: {}",
        text(&out.stderr)
    );
    assert!(stdout.contains("Verified against SHA256SUMS"), "{stdout}");
    assert!(
        stdout.contains(&format!("Updated cxg to {LIVE_TAG}")),
        "{stdout}"
    );
    assert_ne!(
        fs::read(real).unwrap(),
        before,
        "the binary was not replaced"
    );
    assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());

    let version = Command::new(link).arg("--version").output().unwrap();
    assert_eq!(
        text(&version.stdout).trim(),
        format!("cxg {}", LIVE_TAG.trim_start_matches('v'))
    );
}

fn live_enabled() -> bool {
    let on = std::env::var("CXG_LIVE_UPDATE_TEST").as_deref() == Ok("1");
    if !on {
        eprintln!("skipped: set CXG_LIVE_UPDATE_TEST=1 to download a real release");
    }
    on
}

#[test]
fn live_update_through_a_relative_symlink_replaces_the_link_target() {
    if !live_enabled() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let real = install_copy(root.path(), "opt/cxg/bin/cxg");
    let link = relative_link(root.path(), "bin/cxg", "../opt/cxg/bin/cxg");
    assert_live_update_through(root.path(), &link, &real, &[]);
}

#[test]
fn live_forced_update_of_a_homebrew_layout_replaces_the_cellar_file() {
    if !live_enabled() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let real = install_copy(root.path(), "brew/Cellar/cxg/1.5.0/bin/cxg");
    let link = relative_link(root.path(), "brew/bin/cxg", "../Cellar/cxg/1.5.0/bin/cxg");
    assert_live_update_through(root.path(), &link, &real, &["--force"]);
}
