//! Public testing workflows must be discoverable from the built executable alone.
use std::process::Command;

fn help(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_cxg"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("run cxg help");
    assert!(output.status.success(), "{args:?}: {output:?}");
    assert!(output.stderr.is_empty(), "{args:?}: {output:?}");
    // Ignore clap's terminal-width wrapping, preserving the actual words and syntax.
    String::from_utf8(output.stdout)
        .expect("UTF-8 help")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn contains_all(args: &[&str], expected: &[&str]) {
    let output = help(args);
    for text in expected {
        assert!(
            output.contains(text),
            "{args:?} missing {text:?}:\n{output}"
        );
    }
}

#[test]
fn root_help_introduces_cli_and_tauri_workflows() {
    contains_all(
        &["--help"],
        &[
            "cli://<binary>",
            "CLI Security Baseline",
            "cxg template update",
            "cxg pentest run --target-type tauri --codebase ./app-repo",
            "--tauri-prove",
            "no live webview",
        ],
    );
}

#[test]
fn scan_help_explains_cli_setup_inputs_and_verdict_limits() {
    contains_all(
        &["scan", "--help"],
        &[
            "cli://<binary>",
            "absolute executable path",
            "CLI Security Baseline",
            "https://github.com/Bugb-Technologies/cert-x-gen-templates/tree/main/templates/cli-baseline",
            "cxg template update",
            "--template-dir ~/.cert-x-gen/templates/official/templates/cli-baseline",
            "--arg --format --arg json",
            "--stdin-file ./case.bin --input ./corpus",
            "--target-env ASAN_OPTIONS=abort_on_error=1",
            "CERT_X_GEN_ARGV",
            "CERT_X_GEN_STDIN_FILE",
            "CERT_X_GEN_INPUT_DIR",
            "CERT_X_GEN_TARGET_ENV",
            "selected template must consume",
            "@oracles",
            "property",
            "--require-instrumentation",
            "oracle-unavailable(...)",
            "A skipped check provides no refutation",
            "Scanning does not build the target",
            "--instrumented-manifest <PATH>",
        ],
    );
}

#[test]
fn pentest_help_distinguishes_target_requirements_and_tauri_proof() {
    contains_all(
        &["pentest", "--help"],
        &[
            "web: live browser probes; --codebase and --target required, --auth optional",
            "electron: live desktop probes; also requires --app-cmd or --app-binary",
            "GuardLink",
            "whitebox/findings.sarif",
            "no --target, --auth or launch command needed",
            "enumerated_not_live_probed",
            "empty findings list does not establish safety",
            "--tauri-prove --tauri-prove-timeout 1200",
            "cxg scan --scope cli://<binary>",
        ],
    );
    contains_all(
        &["pentest", "run", "--help"],
        &[
            "cxg pentest install",
            "guardlink sarif . -p my-app -o whitebox/findings.sarif",
            "cxg pentest run --target-type tauri --codebase ./app-repo",
            "no --target, --auth or app launch command is needed",
            "legacy py pipeline rejects Tauri",
            "enumerated_not_live_probed",
            "No command is confirmed or refuted unless `--tauri-prove`",
            "--tauri-prove --tauri-prove-timeout 1200",
            "Rust toolchain",
            "MockRuntime",
            "cargo test",
            "path traversal",
            "renderer-controlled authorization arguments",
            "refutation covers only attempted arguments",
            "full setup or capability configuration",
            "tauri_skipped_commands",
            "build failures do not establish safety",
        ],
    );
}

#[test]
fn related_help_explains_auth_capabilities_and_template_discovery() {
    contains_all(
        &["pentest", "auth", "--help"],
        &[
            "Capture supports web and Electron only",
            "Tauri source maps and in-process proofs need no captured profile",
            "select tauri on `cxg pentest run` instead",
        ],
    );
    contains_all(
        &["pentest", "capabilities", "--help"],
        &[
            "no target contact",
            "protocol features",
            "not target-type support",
            "cxg pentest capabilities",
        ],
    );
    for args in [
        vec!["template", "--help"],
        vec!["template", "list", "--help"],
        vec!["template", "search", "--help"],
        vec!["search", "--help"],
    ] {
        contains_all(
            &args,
            &["CLI Security Baseline", "cxg template update", "--tags cli"],
        );
    }
    contains_all(
        &["template", "update", "--help"],
        &[
            "https://github.com/Bugb-Technologies/cert-x-gen-templates",
            "CLI Security Baseline",
            "~/.cert-x-gen/templates/official/templates/cli-baseline",
        ],
    );
}
