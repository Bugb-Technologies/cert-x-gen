//! The CLI Security Baseline pack's honesty guarantee, enforced.
//!
//! Every class in the pack must **confirm on the flawed twin and refute on the
//! fixed twin** of a benign synthetic fixture. A check that cannot be refuted
//! is a check nobody can trust a green result from, so a class that fails
//! either direction fails the build rather than shipping.
//!
//! The fixtures are `tests/fixtures/cli-baseline/`: one source per program,
//! with the twins materialised by `build.sh` into a temp directory here. Which
//! twin a program is comes from its own filename, the same convention as
//! `tests/fixtures/probe-contract/`.
//!
//! The pack itself is vendored alongside them, at
//! `tests/fixtures/cli-baseline/pack/`. The published pack lives in the
//! templates repository; this copy is what the test runs, so the engine
//! repository's suite stays green on its own contents rather than depending on
//! a checkout of another repository.
//!
//! Unix-only. The templates are `bash`, the fixtures are Python and C, and
//! Windows cannot exec a `.sh` (`os error 3`) -- the same reason
//! `tests/probe_contract.rs` is gated.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the vendored copy of the pack's templates lives.
fn pack_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cli-baseline/pack")
}

/// Where the fixture sources live.
fn fixture_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cli-baseline")
}

/// Build the twins once for the whole file and hand back the directory.
///
/// Shared rather than per-test: the compiled twins cost two ASan links each
/// time, and every test here wants the same immutable set of programs. The
/// `TempDir` is deliberately leaked into the `OnceLock` so it outlives every
/// test in the binary.
fn built_fixtures() -> &'static Path {
    static FIXTURES: std::sync::OnceLock<(tempfile::TempDir, PathBuf)> = std::sync::OnceLock::new();

    &FIXTURES
        .get_or_init(|| {
            let dir = tempfile::tempdir().expect("creating a fixture build directory");
            let out = dir.path().to_path_buf();

            let built = Command::new("bash")
                .arg(fixture_src().join("build.sh"))
                .arg(&out)
                .output()
                .expect("running the fixture build script");

            assert!(
                built.status.success(),
                "fixture build failed:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&built.stdout),
                String::from_utf8_lossy(&built.stderr),
            );

            (dir, out)
        })
        .1
}

/// What one template reported: its status, and how many findings it carried.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    status: String,
    findings: usize,
    detail: String,
}

/// Run one template against one target, straight through `bash`, and parse the
/// probe-contract JSON it prints.
///
/// This drives the template exactly as `src/engine/shell/mod.rs` does -- same
/// environment variables, same in-place invocation -- without needing a built
/// `cxg` binary, so the matrix stays a unit of *the pack* rather than a second
/// end-to-end test of the engine.
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

/// The pack, as (template file, fixture family) pairs.
///
/// B11 and B14 are the two classes that need a compiled target, so they run
/// against `memtoy`; everything else runs against `notekeeper`.
const CLASSES: &[(&str, &str)] = &[
    ("cli-baseline-b01-argument-injection.sh", "notekeeper"),
    ("cli-baseline-b02-command-injection.sh", "notekeeper"),
    ("cli-baseline-b03-path-traversal.sh", "notekeeper"),
    ("cli-baseline-b04-archive-traversal.sh", "notekeeper"),
    ("cli-baseline-b05-argv-secrets.sh", "notekeeper"),
    ("cli-baseline-b06-insecure-temp-files.sh", "notekeeper"),
    ("cli-baseline-b07-path-hijack.sh", "notekeeper"),
    ("cli-baseline-b08-terminal-escape.sh", "notekeeper"),
    ("cli-baseline-b09-environment-trust.sh", "notekeeper"),
    (
        "cli-baseline-b10-config-credential-handling.sh",
        "notekeeper",
    ),
    ("cli-baseline-b11-memory-safety.sh", "memtoy"),
    ("cli-baseline-b12-crash-hang.sh", "notekeeper"),
    ("cli-baseline-b13-toctou-symlink-race.sh", "notekeeper"),
    ("cli-baseline-b14-format-string.sh", "memtoy"),
];

fn target_for(dir: &Path, family: &str, twin: &str) -> PathBuf {
    match family {
        "notekeeper" => dir.join(format!("notekeeper_{twin}.py")),
        "memtoy" => dir.join(format!("memtoy_{twin}")),
        other => panic!("unknown fixture family {other}"),
    }
}

/// A compiled fixture reports its real instrumentation; an interpreted one
/// always reports `none`, which is the truth (s15 fix 3).
fn instrumentation_for(family: &str) -> &'static str {
    match family {
        "memtoy" => "asan,debug-info",
        _ => "none",
    }
}

/// **The pack's honesty guarantee.** Every class confirms on the flawed twin
/// and refutes on the fixed one.
///
/// A class that only ever confirms is a class that cannot tell a defect from a
/// tool; a class that only ever refutes has not been shown to detect anything.
/// Both directions, or the class does not ship.
#[test]
fn every_class_confirms_on_the_flawed_twin_and_refutes_on_the_fixed_one() {
    let dir = built_fixtures();

    // Run the classes concurrently. Each template builds its own `mktemp -d`
    // lab, generates its own random nonces and only ever touches paths inside
    // that lab, so no two of them can see each other's canaries -- and the
    // refuting half of the matrix exercises every probe of every class with no
    // early exit, which is a minute and a half of wall clock in sequence.
    let matrix: BTreeMap<&str, (Verdict, Verdict)> = std::thread::scope(|scope| {
        let handles: Vec<_> = CLASSES
            .iter()
            .map(|(template, family)| {
                scope.spawn(move || {
                    let instrumentation = instrumentation_for(family);
                    let flawed = run_template(
                        template,
                        &target_for(dir, family, "defective"),
                        instrumentation,
                    );
                    let fixed =
                        run_template(template, &target_for(dir, family, "fixed"), instrumentation);
                    (*template, (flawed, fixed))
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|h| h.join().expect("a baseline class panicked"))
            .collect()
    });

    let mut failures = Vec::new();
    for (template, (flawed, fixed)) in &matrix {
        if flawed.status != "confirmed" || flawed.findings != 1 {
            failures.push(format!(
                "{template}: flawed twin should be confirmed with 1 finding, got {} with {} -- {}",
                flawed.status, flawed.findings, flawed.detail
            ));
        }
        if fixed.status != "refuted" || fixed.findings != 0 {
            failures.push(format!(
                "{template}: fixed twin should be refuted with 0 findings, got {} with {} -- {}",
                fixed.status, fixed.findings, fixed.detail
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "the confirm/refute matrix has {} failure(s):\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    assert_eq!(matrix.len(), 14, "the baseline is fourteen classes");
}

/// B11 needs a sanitizer to say anything, and says so rather than refuting.
///
/// This is the class the whole Detectability column exists for: an
/// uninstrumented build that silently corrupts memory exits 0 and looks
/// identical to a correct one, so a quiet run there is a false negative
/// indistinguishable from a real refutation.
#[test]
fn the_memory_safety_class_skips_rather_than_refuting_without_instrumentation() {
    let verdict = run_template(
        "cli-baseline-b11-memory-safety.sh",
        &built_fixtures().join("notekeeper_defective.py"),
        "none",
    );

    assert_eq!(
        verdict.status, "skipped",
        "B11 must skip on an uninstrumented build, not refute -- got {verdict:?}"
    );
    assert!(
        verdict.detail.contains("no-instrumentation-detected"),
        "the skip must carry a machine-readable reason, got {:?}",
        verdict.detail
    );
    assert_eq!(verdict.findings, 0);
}

/// The build-independent classes still run on that same uninstrumented build.
///
/// Without this the operator's only choices would be "run the preflight and
/// test nothing" or "drop it and accept unearned refutations" -- the s14 item 1
/// complaint that s15 fixed. The pack has to keep that property true.
#[test]
fn the_build_independent_classes_still_reach_a_verdict_without_instrumentation() {
    let target = built_fixtures().join("notekeeper_defective.py");

    for template in [
        "cli-baseline-b01-argument-injection.sh",
        "cli-baseline-b08-terminal-escape.sh",
        "cli-baseline-b12-crash-hang.sh",
        "cli-baseline-b13-toctou-symlink-race.sh",
    ] {
        let verdict = run_template(template, &target, "none");
        assert_eq!(
            verdict.status, "confirmed",
            "{template} declares only build-independent oracles and must still \
             reach a verdict on an uninstrumented build -- got {verdict:?}"
        );
    }
}

/// Every template refuses a target kind it did not declare.
///
/// cxg gates this from the declaration before the process is spawned, but a
/// baseline pack living in the same registry as thousands of network templates
/// should also refuse from the inside, and templates get run by hand.
#[test]
fn every_template_skips_a_non_cli_target_kind() {
    for (template, _) in CLASSES {
        let output = Command::new("bash")
            .arg(pack_dir().join(template))
            .env("CERT_X_GEN_TARGET_HOST", "127.0.0.1")
            .env("CERT_X_GEN_TARGET_KIND", "https")
            .output()
            .unwrap_or_else(|e| panic!("running {template}: {e}"));

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value =
            serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{template}: {e}"));

        assert_eq!(
            json["metadata"]["status"], "skipped",
            "{template} must skip a non-cli target kind"
        );
    }
}

/// Every template declares the annotations the pack's contract depends on.
///
/// `@target_kinds` is what keeps the pack from misfiring on a network target;
/// `@oracles` is what makes `--require-instrumentation` mean anything; and
/// `@allow_nonzero_exit` is what lets a confirming template exit 3 without its
/// output being discarded.
#[test]
fn every_template_declares_its_contract() {
    for (template, _) in CLASSES {
        let body = std::fs::read_to_string(pack_dir().join(template))
            .unwrap_or_else(|e| panic!("reading {template}: {e}"));

        for annotation in [
            "@target_kinds: cli",
            "@oracles:",
            "@allow_nonzero_exit: true",
        ] {
            assert!(
                body.contains(annotation),
                "{template} is missing `{annotation}`"
            );
        }
        assert!(
            body.contains("cli-baseline.lib"),
            "{template} should source the shared probe library"
        );
    }
}

/// Only B11 declares an oracle it cannot earn on an arbitrary build.
///
/// A template must declare what it actually READS. Declaring a sanitizer
/// oracle a template never consults makes cxg skip a check that would have
/// worked -- `oracles_are_build_independent` treats any build-dependent oracle
/// as making the whole template one -- which is a false negative bought for
/// nothing.
#[test]
fn only_the_memory_safety_class_declares_a_build_dependent_oracle() {
    let build_dependent = ["asan", "ubsan", "msan", "tsan"];
    let mut declaring = Vec::new();

    for (template, _) in CLASSES {
        let body = std::fs::read_to_string(pack_dir().join(template)).unwrap();
        let line = body
            .lines()
            .find(|l| l.starts_with("# @oracles:"))
            .unwrap_or_else(|| panic!("{template} has no @oracles line"));

        if build_dependent.iter().any(|o| line.contains(o)) {
            declaring.push(*template);
        }
    }

    assert_eq!(
        declaring,
        vec!["cli-baseline-b11-memory-safety.sh"],
        "only B11 genuinely depends on instrumentation"
    );
}

/// The shared probe library is not itself loadable as a template.
///
/// It sits in the same directory as the fourteen checks, so if cxg recognised
/// its extension the scan would try to execute the library as a check.
#[test]
fn the_probe_library_is_not_mistaken_for_a_template() {
    let lib = pack_dir().join("cli-baseline.lib");
    assert!(lib.is_file(), "the shared probe library should exist");

    // The two extension allow-lists cxg uses: the scan loader
    // (`src/template/engine.rs`) and the `template validate` walk
    // (`src/main.rs`). Neither lists `lib`.
    let extension = lib.extension().and_then(|e| e.to_str()).unwrap();
    for known in [
        "yaml", "yml", "py", "js", "rs", "c", "cpp", "cc", "cxx", "java", "go", "rb", "pl", "php",
        "sh", "bash",
    ] {
        assert_ne!(
            extension, known,
            "the probe library must not carry a template extension"
        );
    }
}
