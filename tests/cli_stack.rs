//! Keep CLI startup within a small native main-thread stack budget.
#![cfg(unix)]

use std::process::Command;
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
        let output = Command::new("bash")
            .args([
                "-c",
                "ulimit -c 0; ulimit -s 1024; exec \"$@\"",
                "cxg-stack-test",
            ])
            .arg(env!("CARGO_BIN_EXE_cxg"))
            .args(&args)
            .current_dir(home.path())
            .env("CERT_X_GEN_HOME", home.path())
            .env("HOME", home.path())
            .env("CXG_NO_BANNER", "1")
            .env_remove("CXG_SOURCE")
            .output()
            .expect("run cxg with constrained stack");
        assert!(output.status.success(), "{args:?}: {output:?}");
    }
}
