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
//!
//! The fixtures are shell scripts and Unix toy binaries, so the whole file is
//! gated to Unix -- on Windows there is no interpreter to run them and every
//! case would fail on the fixture, not on the code under test.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe-contract")
}

/// Copy the one fixture under a chosen name. The fixture picks its defective /
/// fixed behaviour from its own filename, so `toy_defective.sh` is the twin
/// with the planted defect and any other name is the corrected one.
fn install_target(dir: &Path, name: &str) -> PathBuf {
    install_fixture_as(dir, "toy.sh", name)
}

/// Copy any fixture script into `dir` under a chosen name. Several fixtures
/// pick their behaviour from their own filename, so the name is the knob.
fn install_fixture_as(dir: &Path, fixture: &str, name: &str) -> PathBuf {
    let dest = dir.join(name);
    std::fs::copy(fixtures().join(fixture), &dest).expect("copy fixture");
    make_executable(&dest);
    dest
}

/// Compile the C twin of the fixture (`toy_instrumented.c`) into `dir`, with
/// `markers` carried as an ordinary string constant.
///
/// It has to be a *compiled object*: since s14 item 2 the marker scan runs
/// only on ELF/Mach-O/PE, so a shebang script that merely says `__asan_init`
/// reports `none`. A real sanitizer-linked build carries the same bytes in its
/// symbol table; this carries them in `__cstring`, which the byte-level scan
/// reads identically. The detector itself is unit-tested against every marker
/// in src/engine/common.rs.
///
/// `cc` is not an extra dependency: cargo already needs a C toolchain to link
/// the crate under test.
fn install_object_target(dir: &Path, name: &str, markers: &str) -> PathBuf {
    let dest = dir.join(name);
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let out = Command::new(&cc)
        .arg(format!("-DCXG_BUILD_MARKERS=\"{markers}\""))
        .arg("-o")
        .arg(&dest)
        .arg(fixtures().join("toy_instrumented.c"))
        .output()
        .unwrap_or_else(|e| panic!("running {cc} to build the fixture: {e}"));
    assert!(
        out.status.success(),
        "{cc} failed to build the fixture:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    make_executable(&dest);
    dest
}

/// The compiled fixture with the markers a sanitizer-linked build carries, so
/// the instrumentation preflight sees an instrumented target.
fn install_instrumented_target(dir: &Path, name: &str) -> PathBuf {
    install_object_target(dir, name, "__asan_init __asan_report_load1")
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
    target: String,
    target_kind: String,
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
        assert_eq!(
            self.rows.len(),
            1,
            "expected exactly one ledger row: {:?}",
            self.rows
        );
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
            target: e["target"].as_str().unwrap_or_default().to_string(),
            target_kind: e["target_kind"].as_str().unwrap_or_default().to_string(),
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
    assert_eq!(
        row.exit_code,
        Some(3),
        "the template's own exit code is recorded"
    );
    assert!(row.declared_by_template);
    assert!(
        row.detail.contains("oracle=asan"),
        "detail was {:?}",
        row.detail
    );
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
    assert!(
        row.declared_by_template,
        "the template declared the refutation"
    );
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
    assert!(
        row.declared_by_template,
        "the template declared this itself"
    );
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
    assert!(
        row.detail.contains("input=cxg-argv"),
        "detail was {:?}",
        row.detail
    );

    let safe = scan(
        dir.path(),
        "cli-probe-contract.sh",
        &["--arg", "--label", "--arg", "ok"],
        &scope,
    );
    let row = safe.single();
    assert_eq!(row.status, "refuted");
    assert!(
        row.detail.contains("input=cxg-argv"),
        "detail was {:?}",
        row.detail
    );
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
    assert!(
        detail.contains("CERT_X_GEN_ARGV=[--label,AAAA]"),
        "{detail}"
    );
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
    assert!(
        detail.contains("CERT_X_GEN_TARGET_HOST=example.com"),
        "{detail}"
    );
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
    assert!(
        !row.declared_by_template,
        "cxg refused, the template never ran"
    );
}

/// The preflight must not block a build that *can* show the defect.
#[test]
fn require_instrumentation_still_runs_an_instrumented_build() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_instrumented_target(dir.path(), "toy_defective");

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

/// s14 item 2, end to end. A script that merely *mentions* a sanitizer symbol
/// is not an instrumented build: before this fix the marker scan read the
/// comment as a symbol, the preflight passed, and the probe reported a
/// refutation it could not have earned -- a false all-clear, which is the one
/// thing the preflight exists to prevent. This is the exact shape s14 found
/// against a Node CLI bundle (row F5).
#[test]
fn a_script_that_mentions_a_marker_is_not_an_instrumented_build() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_target(dir.path(), "toy_defective.sh");
    let mut body = std::fs::read_to_string(&bin).unwrap();
    body.push_str("\n# Detected symbols include __asan_init and __ubsan_handle_type_mismatch.\n");
    std::fs::write(&bin, body).unwrap();
    make_executable(&bin);

    // What the template is told.
    let echoed = scan(dir.path(), "env-echo.sh", &[], &cli_scope(&bin));
    assert!(
        echoed
            .single()
            .detail
            .contains("CERT_X_GEN_TARGET_INSTRUMENTATION=none"),
        "detail was {:?}",
        echoed.single().detail
    );

    // ...and what the preflight does about it.
    let out = scan(
        dir.path(),
        "cli-probe-contract.sh",
        &["--require-instrumentation"],
        &cli_scope(&bin),
    );
    let row = out.single();
    assert_eq!(row.status, "skipped");
    assert_eq!(row.detail, "no-instrumentation-detected");
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

/// s14 item 1. `--require-instrumentation` used to be decided at *target*
/// level, so a target detecting no instrumentation had **every** template
/// skipped -- including templates whose oracles need nothing from the build.
/// On an interpreted CLI, which can never detect instrumentation, that left
/// the operator a choice between running the flag and testing nothing, or
/// dropping it and accepting unearned refutations from every sanitizer
/// template in the set. A template declaring only build-independent oracles
/// now runs and reaches a real verdict.
#[test]
fn a_build_independent_template_runs_under_require_instrumentation() {
    let dir = tempfile::tempdir().unwrap();
    // No instrumentation, and (being a script) no way to acquire any: the
    // shape of every interpreted CLI target.
    let bin = install_target(dir.path(), "toy_defective.sh");

    let out = scan(
        dir.path(),
        "cli-probe-exit-only.sh",
        &["--require-instrumentation"],
        &cli_scope(&bin),
    );

    let row = out.single();
    assert_eq!(row.status, "confirmed", "detail was {:?}", row.detail);
    assert_eq!(row.findings, 1);
    assert!(
        row.detail.contains("instrumentation=none"),
        "the template still learns the build carries nothing: {:?}",
        row.detail
    );
}

/// ...and the same template earns a refutation, not a skip, when the target
/// handles the probe input cleanly. The verdict is real either way.
#[test]
fn a_build_independent_template_can_refute_under_require_instrumentation() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_target(dir.path(), "toy_silent.sh");

    let out = scan(
        dir.path(),
        "cli-probe-exit-only.sh",
        &["--require-instrumentation"],
        &cli_scope(&bin),
    );

    let row = out.single();
    assert_eq!(row.status, "refuted", "detail was {:?}", row.detail);
    assert_eq!(row.findings, 0);
}

/// The guarantee the fall-through must not weaken: a template that declares a
/// sanitizer oracle is still refused on a build that carries no sanitizer, and
/// still with the target-level reason.
#[test]
fn a_sanitizer_template_is_still_skipped_on_an_uninstrumented_build() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_target(dir.path(), "toy_defective.sh");

    let out = scan(
        dir.path(),
        "cli-probe-asan-only.sh",
        &["--require-instrumentation"],
        &cli_scope(&bin),
    );

    let row = out.single();
    assert_eq!(row.status, "skipped");
    assert_eq!(row.detail, "no-instrumentation-detected");
    assert!(!row.declared_by_template, "cxg refused before it ran");
}

/// A template that declared no oracles at all says nothing about how it
/// decides, so the preflight keeps refusing it: absent is not a promise, and
/// the flag exists precisely to stop cxg guessing. This is what every template
/// written before the annotation existed does.
#[test]
fn an_undeclared_template_is_still_skipped_on_an_uninstrumented_build() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_target(dir.path(), "toy_defective.sh");

    let out = scan(
        dir.path(),
        "env-echo.sh",
        &["--require-instrumentation"],
        &cli_scope(&bin),
    );

    let row = out.single();
    assert_eq!(row.status, "skipped");
    assert_eq!(row.detail, "no-instrumentation-detected");
}

/// The fall-through is only for `no-instrumentation-detected`: a target that
/// is not there at all cannot run anything, whatever a template declares.
#[test]
fn a_missing_target_skips_even_a_build_independent_template() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no_such_binary");

    let out = scan(
        dir.path(),
        "cli-probe-exit-only.sh",
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

    let instrumented = install_instrumented_target(dir.path(), "toy_asan");
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
    assert!(
        row.detail.contains("kind=https"),
        "detail was {:?}",
        row.detail
    );
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
    let bin = install_object_target(dir.path(), "toy_defective", "__llvm_profile_write_file");

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
    let bin = install_instrumented_target(dir.path(), "toy_defective");

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

// ---------------------------------------------------------------------------
// s14 item 4 -- the `exception` oracle
// ---------------------------------------------------------------------------

/// Both real defects s14 found exited **1** with no crash signal, so `signal`
/// was silent and `exit` fired on the correct non-zero exits too. cxg's own
/// `exception` oracle is what tells them apart: it reads the target's output,
/// not its exit status.
#[test]
fn the_exception_oracle_confirms_a_python_traceback() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_fixture_as(dir.path(), "exception-fixture.sh", "app_python.sh");

    let out = scan(dir.path(), "cli-probe-exception.sh", &[], &cli_scope(&bin));

    let row = out.single();
    assert_eq!(row.status, "confirmed", "detail was {:?}", row.detail);
    assert_eq!(row.findings, 1);
    assert_eq!(
        out.findings, 1,
        "the finding reaches the report, not just the ledger"
    );
    assert!(
        row.detail.contains("oracle=exception(python-traceback)"),
        "detail was {:?}",
        row.detail
    );
    assert!(
        row.detail.contains("target-exit=1"),
        "the exception did not need a crash exit: {:?}",
        row.detail
    );
    assert!(
        !row.declared_by_template,
        "cxg adjudicated; the template declared no status"
    );
}

/// The same for a Node unhandled rejection, which is the other shape s14 hit.
#[test]
fn the_exception_oracle_confirms_a_node_unhandled_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_fixture_as(dir.path(), "exception-fixture.sh", "app_node.js");

    let out = scan(dir.path(), "cli-probe-exception.sh", &[], &cli_scope(&bin));

    let row = out.single();
    assert_eq!(row.status, "confirmed", "detail was {:?}", row.detail);
    assert_eq!(row.findings, 1);
    assert!(
        row.detail
            .contains("oracle=exception(node-unhandled-rejection)"),
        "detail was {:?}",
        row.detail
    );
}

/// ...and the discrimination that makes the oracle worth having: a program
/// that reports a problem correctly and exits 1 is **not** confirmed, though
/// the `exit` oracle cannot tell it from the two above.
#[test]
fn a_correct_nonzero_exit_is_not_confirmed_by_the_exception_oracle() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_fixture_as(dir.path(), "exception-fixture.sh", "app_clean.sh");

    let out = scan(dir.path(), "cli-probe-exception.sh", &[], &cli_scope(&bin));

    let row = out.single();
    assert_eq!(row.status, "refuted", "detail was {:?}", row.detail);
    assert_eq!(row.findings, 0);
    assert_eq!(out.findings, 0);
}

/// `exception` needs nothing from the build, so it is one of the oracles that
/// gets an interpreted target tested at all under --require-instrumentation
/// (s14 item 1 and item 4 meeting).
#[test]
fn the_exception_oracle_runs_under_require_instrumentation() {
    let dir = tempfile::tempdir().unwrap();
    let bin = install_fixture_as(dir.path(), "exception-fixture.sh", "app_python.sh");

    let out = scan(
        dir.path(),
        "cli-probe-exception.sh",
        &["--require-instrumentation"],
        &cli_scope(&bin),
    );

    let row = out.single();
    assert_eq!(row.status, "confirmed", "detail was {:?}", row.detail);
    assert!(
        row.detail.contains("python-traceback"),
        "detail was {:?}",
        row.detail
    );
}

// ---------------------------------------------------------------------------
// A2 -- the `cli:` comma exemption, end to end through the real binary
// ---------------------------------------------------------------------------

/// A `cli://` path containing a comma, passed on the *command line*, is one
/// CLI target. The helper-level unit test for this exemption
/// (`expand_scope_entry`) passed while the binary still split the value,
/// because clap's `value_delimiter` cut it before the helper was reached, so
/// this test deliberately drives the built `cxg` binary.
#[test]
fn a_cli_scope_with_a_comma_is_one_cli_target_through_the_binary() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("comma,name");
    std::fs::create_dir(&nested).unwrap();
    let bin = install_target(&nested, "toy_defective.sh");

    let out = scan(dir.path(), "cli-probe-contract.sh", &[], &cli_scope(&bin));

    // One row, not two: no truncated CLI target and no spurious network
    // target synthesised from the tail of the path.
    let row = out.single();
    assert_eq!(row.target_kind, "cli");
    assert!(
        row.target.contains("comma,name"),
        "the comma survived into the target: {:?}",
        row.target
    );
    assert_eq!(row.status, "confirmed");
}

/// The exemption stays narrow: an ordinary comma-separated `--scope` value on
/// the command line is still two targets.
#[test]
fn an_ordinary_comma_scope_is_still_two_targets_through_the_binary() {
    let dir = tempfile::tempdir().unwrap();

    let out = scan(dir.path(), "env-echo.sh", &[], "127.0.0.1,127.0.0.2");

    assert_eq!(out.rows.len(), 2, "rows were {:?}", out.rows);
    let mut targets: Vec<&str> = out.rows.iter().map(|r| r.target.as_str()).collect();
    targets.sort_unstable();
    assert_eq!(targets, vec!["127.0.0.1", "127.0.0.2"]);
}
