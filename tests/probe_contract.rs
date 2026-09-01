//! End-to-end tests for the probe contract: input delivery, the execution
//! ledger, exit tolerance and the instrumentation preflight.
//!
//! These drive the real `cxg` binary against a **benign synthetic fixture**
//! (`tests/fixtures/probe-contract/toy.sh`). The fixture is not a real
//! vulnerability and is not derived from any advisory: it is a deterministic
//! stand-in whose only job is to give cxg's adjudication something to decide
//! about. What is under test is cxg's plumbing -- does the flag reach the
//! template, is the verdict recorded, is the evidence kept -- not memory-error
//! detection, which is the sanitizer's job.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe-contract")
}

/// Copy the one fixture under a chosen name. The fixture picks its defective /
/// fixed behaviour from its own filename, so `toy_defective.sh` is the twin
/// with the planted defect and any other name is the corrected one.
fn install_target(dir: &Path, name: &str) -> PathBuf {
    let dest = dir.join(name);
    std::fs::copy(fixtures().join("toy.sh"), &dest).expect("copy fixture");
    make_executable(&dest);
    dest
}

/// Install the fixture and append the byte markers a sanitizer-linked build
/// would carry as linker symbols, so the instrumentation preflight sees an
/// instrumented target. `detect_instrumentation` is a byte-level scan, so the
/// markers are all it looks for; a real ELF/Mach-O build carries the same bytes
/// in its symbol table. The detector itself is unit-tested against every
/// marker in src/engine/common.rs.
fn install_instrumented_target(dir: &Path, name: &str) -> PathBuf {
    let dest = install_target(dir, name);
    let mut body = std::fs::read_to_string(&dest).unwrap();
    body.push_str("\n# build markers: __asan_init __asan_report_load1\n");
    std::fs::write(&dest, body).unwrap();
    make_executable(&dest);
    dest
}

fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// One ledger row, as read back out of the result JSON.
#[derive(Debug)]
struct Row {
    status: String,
    findings: u64,
    exit_code: Option<i64>,
    detail: String,
    declared_by_template: bool,
}

struct ScanOutcome {
    findings: usize,
    rows: Vec<Row>,
}

impl ScanOutcome {
    fn single(&self) -> &Row {
        assert_eq!(self.rows.len(), 1, "expected exactly one ledger row: {:?}", self.rows);
        &self.rows[0]
    }
}

/// Run `cxg scan` and read back the execution ledger.
fn scan(dir: &Path, template: &str, extra: &[&str], target: &str) -> ScanOutcome {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cxg"));
    cmd.current_dir(dir)
        .env("CXG_NO_BANNER", "1")
        // Keep the run hermetic: cxg keeps per-user state under its home dir
        // (~/.cert-x-gen/.templates-config.json and friends), and several test
        // processes sharing one home race on it. Point every run at its own.
        .env("HOME", dir)
        .env("CERT_X_GEN_HOME", dir)
        .arg("scan")
        .arg("--disable-update-check")
        .arg("--no-color")
        .args(["--scope", target])
        .args(["--templates", fixtures().join(template).to_str().unwrap()])
        .args(["--output", "result"])
        .args(["--output-format", "json"])
        .args(extra);

    let out = cmd.output().expect("run cxg scan");
    let result_path = dir.join("result.json");
    assert!(
        result_path.exists(),
        "cxg scan produced no result.json\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&result_path).unwrap()).unwrap();
    let rows = doc["executions"]
        .as_array()
        .expect("result JSON carries an `executions` ledger")
        .iter()
        .map(|e| Row {
            status: e["status"].as_str().unwrap().to_string(),
            findings: e["findings"].as_u64().unwrap(),
            exit_code: e["exit_code"].as_i64(),
            detail: e["detail"].as_str().unwrap_or_default().to_string(),
            declared_by_template: e["declared_by_template"].as_bool().unwrap(),
        })
        .collect();

    std::fs::remove_file(&result_path).ok();
    ScanOutcome {
        findings: doc["findings"].as_array().unwrap().len(),
        rows,
    }
}

fn cli_scope(path: &Path) -> String {
    format!("cli://{}", path.display())
}

// ---------------------------------------------------------------------------
// Feature D -- execution result model
// ---------------------------------------------------------------------------

/// The probe provokes a crash, so it exits non-zero. Under
/// `@allow_nonzero_exit` cxg keeps its stdout: the finding, the sanitizer
/// summary and the exit code all survive.
#[test]
fn confirms_and_keeps_the_evidence_when_the_probe_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_target(dir.path(), "toy_defective.sh");

    let out = scan(dir.path(), "cli-probe-contract.sh", &[], &cli_scope(&bin));

    assert_eq!(out.findings, 1);
    let row = out.single();
    assert_eq!(row.status, "confirmed");
    assert_eq!(row.findings, 1);
    assert_eq!(row.exit_code, Some(3), "the template's own exit code is recorded");
    assert!(row.declared_by_template);
    assert!(row.detail.contains("oracle=asan"), "detail was {:?}", row.detail);
}

/// The identical probe logic *without* `@allow_nonzero_exit`: cxg discards the
/// template's stdout on its non-zero exit, so the finding, the report and the
/// exit code are all thrown away and the run is only `errored`. This is the
/// defect D1 fixes, kept as a test so the regression is visible.
#[test]
fn discards_the_evidence_when_the_template_does_not_declare_exit_tolerance() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_target(dir.path(), "toy_defective.sh");

    let out = scan(dir.path(), "cli-probe-legacy.sh", &[], &cli_scope(&bin));

    assert_eq!(out.findings, 0);
    let row = out.single();
    assert_eq!(row.status, "errored");
    assert_eq!(row.findings, 0);
    assert!(!row.declared_by_template);
}

/// The A/B control: the same probe against the corrected twin is a *refutation*
/// -- first-class in the result JSON, with the template's own reason, and with
/// no side-channel run-log needed to tell it from a template that did nothing.
#[test]
fn refutes_on_the_corrected_twin() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_target(dir.path(), "toy_fixed.sh");

    let out = scan(dir.path(), "cli-probe-contract.sh", &[], &cli_scope(&bin));

    assert_eq!(out.findings, 0);
    let row = out.single();
    assert_eq!(row.status, "refuted");
    assert!(row.declared_by_template, "the template declared the refutation");
    assert!(
        row.detail.contains("handled probe input cleanly"),
        "detail was {:?}",
        row.detail
    );
}

/// A template that declines a target reports `skipped` with its own reason, so
/// "zero findings" is never blind. `env-echo.sh` declares no `@target_kinds`,
/// so cxg runs it and the skip is the template's own considered verdict.
#[test]
fn records_a_template_declared_skip_with_its_own_reason() {
    let dir = tempfile::tempdir().unwrap();

    let out = scan(dir.path(), "env-echo.sh", &[], "127.0.0.1");

    let row = out.single();
    assert_eq!(row.status, "skipped");
    assert!(row.declared_by_template, "the template declared this itself");
}

// ---------------------------------------------------------------------------
// Feature B -- structured probe input delivery
// ---------------------------------------------------------------------------

/// The same binary and the same template give opposite verdicts purely from
/// cxg-supplied argv. The probe input is no longer the template author's guess.
#[test]
fn argv_from_the_arg_flag_drives_the_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_target(dir.path(), "toy_defective.sh");
    let scope = cli_scope(&bin);

    let over = scan(
        dir.path(),
        "cli-probe-contract.sh",
        &["--arg", "--label", "--arg", "AAAAAAAAAAAAAAAAAAAA"],
        &scope,
    );
    let row = over.single();
    assert_eq!(row.status, "confirmed");
    assert!(row.detail.contains("input=cxg-argv"), "detail was {:?}", row.detail);

    let safe = scan(
        dir.path(),
        "cli-probe-contract.sh",
        &["--arg", "--label", "--arg", "ok"],
        &scope,
    );
    let row = safe.single();
    assert_eq!(row.status, "refuted");
    assert!(row.detail.contains("input=cxg-argv"), "detail was {:?}", row.detail);
}

/// The same discrimination through the other universal CLI channel.
#[test]
fn stdin_from_the_stdin_file_flag_drives_the_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_target(dir.path(), "toy_defective.sh");
    let scope = cli_scope(&bin);

    let over_path = dir.path().join("over.txt");
    std::fs::write(&over_path, b"AAAAAAAAAAAAAAAAAAAA\n").unwrap();
    let safe_path = dir.path().join("safe.txt");
    std::fs::write(&safe_path, b"ok\n").unwrap();

    let over = scan(
        dir.path(),
        "cli-probe-contract.sh",
        &["--stdin-file", over_path.to_str().unwrap()],
        &scope,
    );
    let row = over.single();
    assert_eq!(row.status, "confirmed");
    assert!(
        row.detail.contains("input=cxg-stdin-file"),
        "detail was {:?}",
        row.detail
    );

    let safe = scan(
        dir.path(),
        "cli-probe-contract.sh",
        &["--stdin-file", safe_path.to_str().unwrap()],
        &scope,
    );
    assert_eq!(safe.single().status, "refuted");
}

/// Every probe variable reaches the template when its flag is passed.
#[test]
fn every_probe_variable_reaches_the_template() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_target(dir.path(), "toy_defective.sh");
    let stdin_file = dir.path().join("case.bin");
    std::fs::write(&stdin_file, b"probe").unwrap();
    let corpus = dir.path().join("corpus");
    std::fs::create_dir(&corpus).unwrap();

    let out = scan(
        dir.path(),
        "env-echo.sh",
        &[
            "--arg",
            "--label",
            "--arg",
            "AAAA",
            "--stdin-file",
            stdin_file.to_str().unwrap(),
            "--input",
            corpus.to_str().unwrap(),
            "--target-env",
            "ASAN_OPTIONS=abort_on_error=1",
        ],
        &cli_scope(&bin),
    );

    let detail = &out.single().detail;
    assert!(detail.contains("CERT_X_GEN_TARGET_KIND=cli"), "{detail}");
    assert!(detail.contains("CERT_X_GEN_ARGV=[--label,AAAA]"), "{detail}");
    assert!(detail.contains("case.bin"), "{detail}");
    assert!(detail.contains("corpus"), "{detail}");
    assert!(
        detail.contains("CERT_X_GEN_TARGET_ENV={ASAN_OPTIONS:abort_on_error=1}"),
        "{detail}"
    );
}

/// The additive claim, end to end: a network target scanned without the probe
/// flags sees none of the new variables, so its template environment is what
/// it always was.
#[test]
fn a_network_target_sees_none_of_the_probe_variables() {
    let dir = tempfile::tempdir().unwrap();

    let out = scan(dir.path(), "env-echo.sh", &[], "https://example.com:8443");

    let detail = &out.single().detail;
    assert!(detail.contains("CERT_X_GEN_TARGET_HOST=example.com"), "{detail}");
    assert!(detail.contains("CERT_X_GEN_TARGET_KIND=https"), "{detail}");
    for name in [
        "CERT_X_GEN_ARGV",
        "CERT_X_GEN_STDIN_FILE",
        "CERT_X_GEN_INPUT_DIR",
        "CERT_X_GEN_TARGET_ENV",
        "CERT_X_GEN_TARGET_INSTRUMENTATION",
    ] {
        assert!(
            detail.contains(&format!("{name}=<unset>")),
            "{name} leaked into a network scan: {detail}"
        );
    }
}

// ---------------------------------------------------------------------------
// Feature E -- instrumentation preflight
// ---------------------------------------------------------------------------

/// The failure mode the whole product must not ship with: a build that cannot
/// reveal the defect runs the probe, sees nothing, and reports a refutation
/// that is indistinguishable from a real one.
#[test]
fn an_uninstrumented_build_reports_a_refutation_it_did_not_earn() {
    let dir = tempfile::tempdir().unwrap();
    // The fixture with the planted defect, but with no instrumentation markers:
    // the stand-in for a stripped build that absorbs the defect silently.
    let bin = install_target(dir.path(), "toy_silent.sh");

    let out = scan(dir.path(), "cli-probe-contract.sh", &[], &cli_scope(&bin));

    let row = out.single();
    assert_eq!(row.status, "refuted");
    assert!(row.detail.contains("handled probe input cleanly"));
}

/// ...and the fix. The same binary and the same probe, under
/// --require-instrumentation, is SKIPPED with a machine-readable reason
/// instead. cxg can now say "I could not have seen it".
#[test]
fn require_instrumentation_turns_that_refutation_into_an_honest_skip() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_target(dir.path(), "toy_silent.sh");

    let out = scan(
        dir.path(),
        "cli-probe-contract.sh",
        &["--require-instrumentation"],
        &cli_scope(&bin),
    );

    let row = out.single();
    assert_eq!(row.status, "skipped");
    assert_eq!(row.detail, "no-instrumentation-detected");
    assert_eq!(row.findings, 0);
    assert_eq!(row.exit_code, None, "nothing ran, so there is no exit code");
    assert!(!row.declared_by_template, "cxg refused, the template never ran");
}

/// The preflight must not block a build that *can* show the defect.
#[test]
fn require_instrumentation_still_runs_an_instrumented_build() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_instrumented_target(dir.path(), "toy_defective.sh");

    let out = scan(
        dir.path(),
        "cli-probe-contract.sh",
        &["--require-instrumentation"],
        &cli_scope(&bin),
    );

    let row = out.single();
    assert_eq!(row.status, "confirmed");
    assert_eq!(row.findings, 1);
}

/// A target that is not there at all gets its own reason, so "skipped" never
/// has to stand for two different failures.
#[test]
fn a_missing_cli_target_is_skipped_as_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no_such_binary");

    let out = scan(
        dir.path(),
        "cli-probe-contract.sh",
        &["--require-instrumentation"],
        &cli_scope(&missing),
    );

    let row = out.single();
    assert_eq!(row.status, "skipped");
    assert_eq!(row.detail, "target-not-found");
}

/// The preflight is off unless asked for, and never gates a network host.
#[test]
fn require_instrumentation_does_not_gate_a_network_target() {
    let dir = tempfile::tempdir().unwrap();

    let out = scan(
        dir.path(),
        "env-echo.sh",
        &["--require-instrumentation"],
        "https://example.com:8443",
    );

    // The template ran (it declared its own skip); cxg did not refuse it.
    assert!(out.single().declared_by_template);
}

/// The template is told what the build can reveal, whether or not the
/// preflight is enabled.
#[test]
fn the_template_is_told_what_instrumentation_the_build_carries() {
    let dir = tempfile::tempdir().unwrap();

    let bare = install_target(dir.path(), "toy_bare.sh");
    let out = scan(dir.path(), "env-echo.sh", &[], &cli_scope(&bare));
    assert!(
        out.single()
            .detail
            .contains("CERT_X_GEN_TARGET_INSTRUMENTATION=none"),
        "{}",
        out.single().detail
    );

    let instrumented = install_instrumented_target(dir.path(), "toy_asan.sh");
    let out = scan(dir.path(), "env-echo.sh", &[], &cli_scope(&instrumented));
    assert!(
        out.single()
            .detail
            .contains("CERT_X_GEN_TARGET_INSTRUMENTATION=asan"),
        "{}",
        out.single().detail
    );
}

// ---------------------------------------------------------------------------
// Feature C -- oracle and target-kind declarations
// ---------------------------------------------------------------------------

/// A template that declares which kinds it handles is not run against another
/// kind at all: the mismatch is recorded, so the "zero findings" is explained.
#[test]
fn a_declared_target_kind_mismatch_is_recorded_rather_than_run() {
    let dir = tempfile::tempdir().unwrap();

    let out = scan(
        dir.path(),
        "cli-probe-asan-only.sh",
        &[],
        "https://example.com:8443",
    );

    let row = out.single();
    assert_eq!(row.status, "skipped");
    assert!(
        row.detail.starts_with("target-kind-mismatch"),
        "detail was {:?}",
        row.detail
    );
    assert!(row.detail.contains("kind=https"), "detail was {:?}", row.detail);
    assert!(
        !row.declared_by_template,
        "cxg refused before the template ran"
    );
}

/// The join between the oracle declaration and the instrumentation preflight:
/// a template whose only oracle is ASan, run against a build with no ASan,
/// under --require-instrumentation, is skipped with the reason.
#[test]
fn an_asan_only_template_is_skipped_when_the_build_has_no_asan() {
    let dir = tempfile::tempdir().unwrap();
    // A build with *some* instrumentation, so the target-level preflight lets
    // it through and the oracle check is what decides.
    let bin = install_target(dir.path(), "toy_defective.sh");
    let mut body = std::fs::read_to_string(&bin).unwrap();
    body.push_str("\n# build markers: __llvm_profile_write_file\n");
    std::fs::write(&bin, body).unwrap();
    make_executable(&bin);

    let out = scan(
        dir.path(),
        "cli-probe-asan-only.sh",
        &["--require-instrumentation"],
        &cli_scope(&bin),
    );

    let row = out.single();
    assert_eq!(row.status, "skipped");
    assert_eq!(row.detail, "oracle-unavailable(asan)");
}

/// ...and the same template on a build that does carry ASan runs normally.
#[test]
fn an_asan_only_template_runs_when_the_build_carries_asan() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_instrumented_target(dir.path(), "toy_defective.sh");

    let out = scan(
        dir.path(),
        "cli-probe-asan-only.sh",
        &["--require-instrumentation"],
        &cli_scope(&bin),
    );

    let row = out.single();
    assert_eq!(row.status, "confirmed");
    assert_eq!(row.findings, 1);
}

/// Oracle gating belongs to the preflight: without the flag, cxg runs the
/// template and reports what it observed.
#[test]
fn oracle_gating_is_off_without_the_preflight_flag() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_target(dir.path(), "toy_defective.sh");

    let out = scan(dir.path(), "cli-probe-asan-only.sh", &[], &cli_scope(&bin));

    // The fixture prints an ASan-shaped report, so this one does confirm --
    // the point is only that cxg did not refuse to run it.
    assert!(out.single().declared_by_template);
}
