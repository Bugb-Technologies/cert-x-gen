//! Keep CLI startup within a small native main-thread stack budget.
#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

#[test]
fn help_status_and_update_fit_a_one_mib_main_stack() {
    let home = TempDir::new().unwrap();
    for args in [
        vec!["--help"],
        vec!["scan", "--help"],
        vec!["pentest", "--help"],
        vec!["pentest", "auth", "--help"],
        vec!["pentest", "status", "--json"],
        vec!["pentest", "update", "--json"],
    ] {
        let output = cli_with_stack(home.path(), &args, 1024);
        assert!(output.status.success(), "{args:?}: {output:?}");
    }
}

// This budget is smaller than the command builder needs on Unix, so the test
// detects accidentally moving parsing or runtime creation back to the main thread.
#[test]
fn cli_thread_handles_tiny_main_stack_and_preserves_exit_codes() {
    let home = TempDir::new().unwrap();
    for (args, code) in [
        (vec!["--help"], 0),
        (vec!["pentest", "status", "--json"], 0),
        (vec!["pentest", "update", "--json"], 0),
        (vec!["--unknown-option"], 2),
        (vec!["pentest", "capabilities"], 1),
    ] {
        let output = cli_with_stack(home.path(), &args, 256);
        assert_eq!(output.status.code(), Some(code), "{args:?}: {output:?}");
    }
}

fn cli_with_stack(home: &Path, args: &[&str], stack_kib: u32) -> Output {
    Command::new("bash")
        .args([
            "-c",
            &format!("ulimit -c 0; ulimit -s {stack_kib}; exec \"$@\""),
            "cxg-stack-test",
        ])
        .arg(env!("CARGO_BIN_EXE_cxg"))
        .args(args)
        .current_dir(home)
        .env("CERT_X_GEN_HOME", home)
        .env("HOME", home)
        .env("CXG_NO_BANNER", "1")
        .env("CXG_PYTHON", home.join("missing-python"))
        .env_remove("CXG_SOURCE")
        .output()
        .expect("run cxg with constrained stack")
}
