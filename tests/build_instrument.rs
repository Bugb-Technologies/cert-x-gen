//! `cxg build --instrument`, proved end to end on a benign synthetic toy.
//!
//! The unit tests in `src/build/` cover the decisions -- build-system
//! detection, capability probing, every skip reason -- against no toolchain at
//! all. This file covers the thing they cannot: that the component really does
//! drive cargo, really does produce an instrumented binary, and that the
//! binary really does turn the shipped CLI Security Baseline's B11 class into
//! a verdict rather than a shrug.
//!
//! **The matrix, and why all three rows are needed.**
//!
//! ```text
//! santoy_defective, built instrumented   -> CONFIRMED   the defect is reachable
//! santoy_fixed,     built instrumented   -> REFUTED     and the class can be refuted
//! santoy_defective, built ORDINARILY     -> SKIPPED     and a build that cannot show it
//!                                                       does not get to refute it
//! ```
//!
//! A class that only ever confirms cannot tell a defect from a tool. A class
//! that only ever refutes has not been shown to detect anything. And the third
//! row is the honest-failure boundary: the *same defective program*, built
//! without a sanitizer, exits 0 on every probe and looks exactly like the
//! fixed twin -- so the only correct answer there is `skipped`.
//!
//! The toy is `tests/fixtures/build-instrument/santoy.rs`: two planted flaws
//! with their corrections beside them. Nothing here reproduces any real defect
//! in any real program.
//!
//! **Toolchain.** `-Zsanitizer` is nightly-only and there is no stable
//! equivalent, so these tests need `rustup` with a nightly toolchain. Where
//! that is missing they print why and pass, rather than failing a build over a
//! dependency the feature honestly has -- the same answer the component itself
//! gives an operator.
//!
//! Unix-only, for the same reason as `tests/cli_baseline_pack.rs`: the
//! templates are `bash`, which Windows cannot exec (`os error 3`).

#![cfg(unix)]

use cert_x_gen::build::{instrument, InstrumentRequest, Manifest};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The B11 template, vendored with the rest of the pack.
const B11: &str = "cli-baseline-b11-memory-safety.sh";

fn pack_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cli-baseline/pack")
}

fn fixture_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/build-instrument")
}

/// Is a nightly toolchain reachable? If not, say so once and let the test pass.
fn nightly_or_explain(what: &str) -> bool {
    let installed = Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l.starts_with("nightly"))
        });
    if !installed {
        eprintln!(
            "SKIPPING {what}: -Zsanitizer is nightly-only and no nightly toolchain is \
             installed. Install it with `rustup toolchain install nightly`. This is the \
             feature's one real dependency and the component skips on it honestly too."
        );
    }
    installed
}

/// Materialise the toy crate into a fresh directory and hand it back.
///
/// The manifest is checked in under a name cargo does not recognise, so the
/// package under test never contains a nested package.
fn materialise_toy(into: &Path) -> PathBuf {
    let project = into.join("santoy");
    std::fs::create_dir_all(project.join("src")).expect("creating the toy source directory");
    std::fs::copy(
        fixture_src().join("cargo-manifest.toml"),
        project.join("Cargo.toml"),
    )
    .expect("copying the toy manifest");
    std::fs::copy(fixture_src().join("santoy.rs"), project.join("src/main.rs"))
        .expect("copying the toy source");
    project
}

/// The toy project, its instrumented build tree, and its ordinary one, built
/// once for every test in this binary.
///
/// Deliberately leaked into the `OnceLock` so the temp directory outlives the
/// tests that read it.
fn toy() -> &'static Toy {
    static TOY: std::sync::OnceLock<Toy> = std::sync::OnceLock::new();
    TOY.get_or_init(|| {
        let dir = tempfile::tempdir().expect("creating the toy build directory");
        let project = materialise_toy(dir.path());
        let instrumented_out = dir.path().join("out-instrumented");
        let plain_out = dir.path().join("out-plain");
        Toy {
            project,
            instrumented_out,
            plain_out,
            _dir: dir,
        }
    })
}

struct Toy {
    project: PathBuf,
    instrumented_out: PathBuf,
    plain_out: PathBuf,
    _dir: tempfile::TempDir,
}

/// Build one twin with ASan through the component under test.
fn build_instrumented(bin: &str) -> Manifest {
    let toy = toy();
    instrument(&InstrumentRequest {
        project: toy.project.clone(),
        bin: Some(bin.to_string()),
        sanitizers: vec!["address".to_string()],
        out_dir: Some(toy.instrumented_out.clone()),
        build_std: false,
    })
}

/// Build one twin the way its own developer would -- an ordinary `cargo build`,
/// no sanitizer, no flags from cxg at all.
fn build_ordinarily(bin: &str) -> PathBuf {
    let toy = toy();
    let built = Command::new("cargo")
        .args(["build", "--bin", bin, "--manifest-path"])
        .arg(toy.project.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&toy.plain_out)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .output()
        .expect("running the ordinary cargo build");
    assert!(
        built.status.success(),
        "the ordinary build of {bin} failed:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );
    toy.plain_out.join("debug").join(bin)
}

/// What one template reported.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    status: String,
    findings: usize,
    detail: String,
}

/// Run a template against a target exactly as `src/engine/shell/mod.rs` does.
fn run_template(template: &str, target: &Path, instrumentation: &str) -> Verdict {
    let output = Command::new("bash")
        .arg(pack_dir().join(template))
        .env("CERT_X_GEN_TARGET_HOST", target)
        .env("CERT_X_GEN_TARGET_KIND", "cli")
        .env("CERT_X_GEN_TARGET_INSTRUMENTATION", instrumentation)
        .output()
        .unwrap_or_else(|e| panic!("running {template}: {e}"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "{template} did not print probe-contract JSON ({e}).\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    Verdict {
        status: json["metadata"]["status"]
            .as_str()
            .unwrap_or("<missing>")
            .to_string(),
        findings: json["findings"].as_array().map(|a| a.len()).unwrap_or(0),
        detail: json["metadata"]["detail"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    }
}

fn expect_instrumented(manifest: &Manifest) -> &cert_x_gen::build::Instrumented {
    match manifest {
        Manifest::Instrumented(built) => built,
        Manifest::Skipped(skipped) => panic!(
            "the instrumented build was skipped: {} {:?}",
            skipped.reason, skipped.build_log_tail
        ),
    }
}

/// **The proof.** Confirm on the flawed twin, refute on the fixed one, skip on
/// the build that could not have shown either.
#[test]
fn the_instrumented_twins_confirm_and_refute_and_an_ordinary_build_skips() {
    if !nightly_or_explain("the instrumented-build proof") {
        return;
    }

    // --- flawed twin, built instrumented: CONFIRMED.
    let flawed = build_instrumented("santoy_defective");
    let flawed = expect_instrumented(&flawed);
    assert!(
        flawed.instrumentation.contains(&"asan".to_string()),
        "the component must not report `instrumented` without reading ASan back out of the \
         artefact: {:?}",
        flawed.instrumentation
    );
    let verdict = run_template(B11, &flawed.binary, &flawed.instrumentation.join(","));
    assert_eq!(
        verdict.status, "confirmed",
        "the flawed twin's planted heap overflow must be confirmed under ASan: {verdict:?}"
    );
    assert_eq!(verdict.findings, 1, "{verdict:?}");
    assert!(
        verdict.detail.contains("AddressSanitizer"),
        "the verdict must rest on a sanitizer report, not an inference: {verdict:?}"
    );

    // --- fixed twin, same build recipe: REFUTED.
    let fixed = build_instrumented("santoy_fixed");
    let fixed = expect_instrumented(&fixed);
    let verdict = run_template(B11, &fixed.binary, &fixed.instrumentation.join(","));
    assert_eq!(
        verdict.status, "refuted",
        "a class that cannot be refuted is a class nobody can trust a green result from: \
         {verdict:?}"
    );
    assert_eq!(verdict.findings, 0, "{verdict:?}");

    // --- the SAME flawed program, built ordinarily: SKIPPED.
    //
    // This is the honest-failure boundary. The defect is still there and still
    // reachable; the build simply cannot show it, so every probe exits 0 and
    // the binary is indistinguishable from its fixed twin. `refuted` here
    // would be a false negative dressed as evidence.
    let plain = build_ordinarily("santoy_defective");
    let detected = cert_x_gen::engine::common::detect_instrumentation(&plain);
    assert!(
        !detected.iter().any(|d| d == "asan"),
        "an ordinary cargo build carries no ASan: {detected:?}"
    );
    let instrumentation = if detected.is_empty() {
        "none".to_string()
    } else {
        detected.join(",")
    };
    let verdict = run_template(B11, &plain, &instrumentation);
    assert_eq!(
        verdict.status, "skipped",
        "an uninstrumented build must not be allowed to refute the memory class: {verdict:?}"
    );
    assert_eq!(verdict.findings, 0, "{verdict:?}");
}

/// The toy has three binary targets and no way to guess which is the CLI under
/// test, so the component names the flag that resolves it instead of picking
/// one. This is the same shape a real Cargo workspace has.
#[test]
fn a_project_with_several_binaries_refuses_to_choose() {
    if !nightly_or_explain("the ambiguous-binary check") {
        return;
    }
    let manifest = instrument(&InstrumentRequest {
        project: toy().project.clone(),
        bin: None,
        sanitizers: vec!["address".to_string()],
        out_dir: Some(toy().instrumented_out.clone()),
        build_std: false,
    });
    let Manifest::Skipped(skipped) = manifest else {
        panic!("three binaries and no --bin must skip");
    };
    assert_eq!(skipped.reason, "binary-target-ambiguous(pass --bin NAME)");
}

/// **Rust has no UBSan.** Asking for it must skip with the reason that says
/// so, on a real toolchain, rather than build something that cannot show what
/// it was asked to show.
#[test]
fn asking_a_rust_project_for_ubsan_skips_with_the_real_reason() {
    if !nightly_or_explain("the UBSan-on-Rust check") {
        return;
    }
    let manifest = instrument(&InstrumentRequest {
        project: toy().project.clone(),
        bin: Some("santoy_defective".to_string()),
        sanitizers: vec!["undefined".to_string()],
        out_dir: Some(toy().instrumented_out.clone()),
        build_std: false,
    });
    let Manifest::Skipped(skipped) = manifest else {
        panic!("there is no -Zsanitizer=undefined; asking for it must skip");
    };
    assert_eq!(skipped.reason, "sanitizer-unsupported-on-target");
    assert!(
        skipped
            .notes
            .iter()
            .any(|n| n.contains("rustc-has-no-ubsan")),
        "the skip must name the real answer rather than imply another platform would have it: \
         {:?}",
        skipped.notes
    );
}

/// **Provenance beats inspection**, on a real artefact: what a scan reads back
/// out of the manifest is what the build actually verified, and it reaches a
/// template through the same environment variable inspection would have used.
#[test]
fn a_manifest_carries_the_build_record_into_a_scan() {
    if !nightly_or_explain("the manifest provenance check") {
        return;
    }
    let manifest = build_instrumented("santoy_fixed");
    let built = expect_instrumented(&manifest);

    // Rust's integer check is a build fact cxg passed, and it is recorded.
    assert!(
        built
            .instrumentation
            .contains(&"rust-overflow-checks".to_string()),
        "cxg passes -C overflow-checks=on on every instrumented Rust build, so the artefact \
         carries the integer check and the manifest records it: {:?}",
        built.instrumentation
    );

    // Round-trip the manifest the way `--instrumented-manifest` does.
    let json = serde_json::to_string(&manifest).expect("serialising the manifest");
    let read_back: Manifest = serde_json::from_str(&json).expect("reading the manifest back");
    let read_back = expect_instrumented(&read_back);
    assert_eq!(read_back.instrumentation, built.instrumentation);

    let mut context = cert_x_gen::types::Context::default();
    context.instrumentation_provenance.insert(
        read_back.binary.to_string_lossy().to_string(),
        read_back.instrumentation.clone(),
    );
    let target = cert_x_gen::types::Target::new(
        read_back.binary.to_string_lossy().to_string(),
        cert_x_gen::types::Protocol::Cli,
    );
    let env = cert_x_gen::engine::common::build_env_vars(&target, &context)
        .expect("building the template environment");
    assert_eq!(
        env.get("CERT_X_GEN_TARGET_INSTRUMENTATION").unwrap(),
        &built.instrumentation.join(",")
    );
}
