//! The cargo (Rust) back end.
//!
//! Rust is the immediate target and the only back end implemented. Four things
//! about the build command are load bearing, and each is a defect if dropped:
//!
//! * **`+nightly`.** `-Zsanitizer` is an unstable flag. There is no stable
//!   path and no `RUSTC_BOOTSTRAP` shortcut worth shipping, so nightly is this
//!   component's one hard dependency -- and a machine without it gets an
//!   actionable skip, not a clean build.
//! * **`--target <host triple>`, even when not cross-compiling.** Without it
//!   `RUSTFLAGS` reaches build scripts and proc-macro crates, which cargo
//!   compiles *and runs on the host* during the build -- so the build itself
//!   ends up executing under the sanitizer. Passing `--target` splits host
//!   artefacts from target artefacts. This is the single cargo quirk most
//!   likely to be missed.
//! * **`-C debuginfo=2`.** A sanitizer report without symbols is a hex
//!   address.
//! * **`--target-dir`, never the project's own.** `RUSTFLAGS` is part of
//!   cargo's fingerprint, so sharing a target directory means a full rebuild
//!   in *both* directions every time the operator alternates between an
//!   instrumented scan and their ordinary `cargo build`.
//!
//! The profile is left at `dev`: `-O` can optimise a planted defect away
//! entirely, and a build that cannot show the defect is the thing this whole
//! component exists to avoid handing to a scan.

use super::{InstrumentRequest, Instrumented, Manifest, Skipped};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Sanitizers cxg is willing to build with, mapped to the label
/// [`crate::engine::common::detect_instrumentation`] reports for each.
///
/// The list is short **because verification is not optional**. cxg refuses to
/// report `instrumented` for something it cannot read back out of the produced
/// binary, so a sanitizer with no marker in `INSTRUMENTATION_MARKERS` -- `cfi`,
/// `safestack`, `realtime` -- is declined up front by name rather than after a
/// build whose result cxg would then have to take on faith.
pub const VERIFIABLE_SANITIZERS: &[(&str, &str)] =
    &[("address", "asan"), ("thread", "tsan"), ("memory", "msan")];

/// What rustc calls UBSan-shaped requests, none of which exist for Rust.
const UBSAN_ALIASES: &[&str] = &["undefined", "ubsan"];

/// The answer to "instrument this Rust project with UBSan".
///
/// Not a platform limitation to route around: `undefined` is not in rustc's
/// `-Zsanitizer` vocabulary on **any** target, on any nightly. Answering with
/// a generic "unsupported on this target" would send an operator looking for a
/// platform that has it, so the note names the real answer instead.
pub const UBSAN_NOTE: &str = "rustc-has-no-ubsan(no -Zsanitizer=undefined exists on any Rust \
                              target; the Rust equivalent for the integer class is \
                              -C overflow-checks=on, which panics -- see the overflow oracle)";

/// The instrumentation label a Rust build carries because of
/// `-C overflow-checks=on`.
///
/// cxg always passes that flag, so a project that turned the check off in
/// `[profile.dev]` still gets it back.
pub const OVERFLOW_CHECKS_LABEL: &str = "rust-overflow-checks";

/// Build `project` with instrumentation, or explain why not.
pub fn instrument(project: &Path, request: &InstrumentRequest) -> Manifest {
    let context = |skipped: Skipped| -> Manifest {
        Manifest::Skipped(Skipped {
            build_system: Some("cargo".to_string()),
            project: Some(project.to_path_buf()),
            ..skipped
        })
    };

    // --- 1. Toolchain preconditions.
    if which("cargo").is_none() {
        return context(Skipped::new("cargo-not-on-path"));
    }
    if which("rustup").is_none() {
        return context(Skipped::new(
            "rustup-not-on-path(needed to select a nightly toolchain)",
        ));
    }
    if !nightly_is_installed() {
        return context(Skipped::new(
            "nightly-toolchain-unavailable(install: rustup toolchain install nightly)",
        ));
    }
    let Some(triple) = host_triple() else {
        return context(Skipped::new("host-triple-unavailable"));
    };

    // --- 2. Sanitizer capability, asked of rustc rather than guessed.
    //
    // It differs by platform -- aarch64-apple-darwin has no MSan and no LSan,
    // x86_64-unknown-linux-gnu has both -- and a component that guessed would
    // end up claiming an MSan verdict on a build that never had one.
    let Some(supported) = supported_sanitizers(&triple) else {
        return context(Skipped {
            target: Some(triple.clone()),
            ..Skipped::new(format!("sanitizer-capability-unknown(target={triple})"))
        });
    };

    let plan = partition_requested(&request.sanitizers, &supported);
    if plan.wanted.is_empty() {
        let reason = plan.empty_reason();
        return context(Skipped {
            target: Some(triple),
            requested: Some(request.sanitizers.join(",")),
            supported: Some(supported.join(",")),
            notes: plan.notes,
            ..Skipped::new(reason)
        });
    }

    // --- 3. What to build.
    let manifest_path = project.join("Cargo.toml");
    let bin = match request.bin.clone() {
        Some(name) => name,
        None => match sole_bin_target(&cargo_metadata(&manifest_path).unwrap_or_default()) {
            Some(name) => name,
            None => {
                return context(Skipped::new("binary-target-ambiguous(pass --bin NAME)"));
            }
        },
    };

    if request.build_std && !rust_src_is_installed() {
        return context(Skipped::new(
            "rust-src-missing(needed by -Zbuild-std; rustup component add rust-src \
             --toolchain nightly)",
        ));
    }

    let target_dir = request
        .out_dir
        .clone()
        .unwrap_or_else(|| project.join("target-instrumented"));
    let rustflags = rustflags(&plan.wanted);

    // --- 4. The build.
    let mut command = Command::new("cargo");
    command
        .arg("+nightly")
        .arg("build")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--bin")
        .arg(&bin)
        .arg("--target")
        .arg(&triple)
        .arg("--target-dir")
        .arg(&target_dir)
        .env("RUSTFLAGS", &rustflags)
        // CARGO_ENCODED_RUSTFLAGS takes precedence over RUSTFLAGS, so a shell
        // that exported it would silently discard every flag above and cargo
        // would build a perfectly ordinary, uninstrumented binary.
        .env_remove("CARGO_ENCODED_RUSTFLAGS");
    if request.build_std {
        command.arg("-Zbuild-std");
    }

    let output = match command.output() {
        Ok(output) => output,
        Err(e) => {
            return context(Skipped {
                rustflags: Some(rustflags),
                ..Skipped::new(format!("instrumented-build-not-runnable({e})"))
            })
        }
    };
    if !output.status.success() {
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string());
        return context(Skipped {
            rustflags: Some(rustflags),
            build_log_tail: Some(log_tail(&output.stdout, &output.stderr)),
            ..Skipped::new(format!("instrumented-build-failed(exit={code})"))
        });
    }

    // `EXE_SUFFIX` rather than a bare name: cargo writes `<bin>.exe` on
    // Windows, and looking for the wrong path there would report
    // `instrumented-binary-not-found` for a build that succeeded.
    let binary = target_dir
        .join(&triple)
        .join("debug")
        .join(format!("{bin}{}", std::env::consts::EXE_SUFFIX));
    if !binary.is_file() {
        return context(Skipped {
            binary: Some(binary.clone()),
            rustflags: Some(rustflags),
            ..Skipped::new(format!(
                "instrumented-binary-not-found({})",
                binary.display()
            ))
        });
    }

    // --- 5. Post-build verification -- the part that makes this honest.
    //
    // Re-read the binary that was just produced with the same symbol-table
    // scan the scan preflight uses, and refuse to say `instrumented` unless
    // what was asked for is actually in there. A build that accepted the flags
    // and dropped them still links and still runs; the only way to know is to
    // look at the artefact.
    let detected = crate::engine::common::detect_instrumentation(&binary);
    if let Some(reason) = verification_gap(&plan.wanted, &detected) {
        return context(Skipped {
            binary: Some(binary),
            rustflags: Some(rustflags),
            notes: plan.notes,
            ..Skipped::new(reason)
        });
    }

    Manifest::Instrumented(Instrumented {
        build_system: "cargo".to_string(),
        toolchain: "nightly".to_string(),
        target: triple,
        bin,
        binary,
        rustflags,
        build_std: request.build_std,
        instrumentation: detected,
        unsupported_requested: plan.unsupported,
        notes: plan.notes,
    })
}

/// How a set of requested sanitizers splits against what the target can do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SanitizerPlan {
    /// Requested, supported by the target, and verifiable in the artefact.
    pub wanted: Vec<String>,
    /// Requested and not available here, including every UBSan alias.
    pub unsupported: Vec<String>,
    /// Requested and supported by rustc, but with no marker cxg can read back
    /// out of the produced binary.
    pub unverifiable: Vec<String>,
    /// Human-readable explanations for the above.
    pub notes: Vec<String>,
}

impl SanitizerPlan {
    /// The skip reason when nothing survived the split.
    ///
    /// The two cases are genuinely different and an operator acts on them
    /// differently: `sanitizer-unsupported-on-target` means "not here, maybe
    /// elsewhere", `sanitizer-not-verifiable` means "cxg will not vouch for
    /// this anywhere", and collapsing them would send someone hunting for a
    /// platform that would not help.
    pub fn empty_reason(&self) -> String {
        if self.unsupported.is_empty() && !self.unverifiable.is_empty() {
            format!("sanitizer-not-verifiable({})", self.unverifiable.join(","))
        } else {
            "sanitizer-unsupported-on-target".to_string()
        }
    }
}

/// Split the requested sanitizers against what this target supports.
pub fn partition_requested(requested: &[String], supported: &[String]) -> SanitizerPlan {
    let mut plan = SanitizerPlan::default();
    let mut saw_ubsan = false;

    for name in requested {
        let name = name.trim().to_lowercase();
        if name.is_empty() {
            continue;
        }
        if UBSAN_ALIASES.contains(&name.as_str()) {
            saw_ubsan = true;
            push_unique(&mut plan.unsupported, "undefined");
            continue;
        }
        if !supported.contains(&name) {
            push_unique(&mut plan.unsupported, &name);
            continue;
        }
        if !VERIFIABLE_SANITIZERS.iter().any(|(s, _)| *s == name) {
            push_unique(&mut plan.unverifiable, &name);
            continue;
        }
        push_unique(&mut plan.wanted, &name);
    }

    if saw_ubsan {
        plan.notes.push(UBSAN_NOTE.to_string());
    }
    if !plan.unverifiable.is_empty() {
        plan.notes.push(format!(
            "cxg-cannot-verify({}): no symbol marker distinguishes this build, and cxg does not \
             report instrumentation it cannot read back out of the artefact",
            plan.unverifiable.join(",")
        ));
    }
    plan
}

fn push_unique(into: &mut Vec<String>, value: &str) {
    if !into.iter().any(|v| v == value) {
        into.push(value.to_string());
    }
}

/// The instrumentation label a sanitizer produces, for the labels cxg can
/// verify.
pub fn label_for(sanitizer: &str) -> Option<&'static str> {
    VERIFIABLE_SANITIZERS
        .iter()
        .find(|(name, _)| *name == sanitizer)
        .map(|(_, label)| *label)
}

/// The `RUSTFLAGS` value for a set of sanitizers.
///
/// `-C overflow-checks=on` is not a sanitizer, but it is Rust's answer to
/// UBSan's integer check and it is set explicitly so a project that turned it
/// off in `[profile.dev]` still gets it.
pub fn rustflags(wanted: &[String]) -> String {
    format!(
        "-Zsanitizer={} -C debuginfo=2 -C force-frame-pointers=yes -C overflow-checks=on",
        wanted.join(",")
    )
}

/// Did the build actually produce what it was asked for?
///
/// Returns the skip reason when it did not. **Every** wanted sanitizer has to
/// be present: a build asked for two and carrying one is not the build the
/// operator is about to draw a conclusion from.
pub fn verification_gap(wanted: &[String], detected: &[String]) -> Option<String> {
    let labels: Vec<&str> = wanted.iter().filter_map(|s| label_for(s)).collect();
    let missing: Vec<&str> = labels
        .iter()
        .copied()
        .filter(|label| !detected.iter().any(|d| d == label))
        .collect();
    if missing.is_empty() {
        return None;
    }
    Some(format!(
        "build-produced-no-instrumentation(wanted={} detected={})",
        labels.join(","),
        if detected.is_empty() {
            "none".to_string()
        } else {
            detected.join(",")
        }
    ))
}

/// The sole binary target of a `cargo metadata --no-deps` document, or [`None`]
/// when there is not exactly one.
///
/// Refusing to pick is the point. A Cargo workspace with four binaries gives
/// cxg no way to know which one is the CLI under test, and choosing the first
/// would instrument something the operator never meant to scan.
pub fn sole_bin_target(metadata: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(metadata).ok()?;
    let mut bins: Vec<String> = Vec::new();
    for package in parsed.get("packages")?.as_array()? {
        for target in package.get("targets")?.as_array()? {
            let is_bin = target
                .get("kind")
                .and_then(|k| k.as_array())
                .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some("bin")));
            if is_bin {
                if let Some(name) = target.get("name").and_then(|n| n.as_str()) {
                    push_unique(&mut bins, name);
                }
            }
        }
    }
    match bins.len() {
        1 => bins.pop(),
        _ => None,
    }
}

/// Parse `supported-sanitizers` out of a `--print target-spec-json` document.
pub fn parse_supported_sanitizers(target_spec_json: &str) -> Option<Vec<String>> {
    let parsed: serde_json::Value = serde_json::from_str(target_spec_json).ok()?;
    let listed = parsed.get("supported-sanitizers")?.as_array()?;
    let sanitizers: Vec<String> = listed
        .iter()
        .filter_map(|s| s.as_str())
        .map(|s| s.to_lowercase())
        .collect();
    if sanitizers.is_empty() {
        None
    } else {
        Some(sanitizers)
    }
}

/// The last 20 lines of a build's combined output, for a failure manifest.
fn log_tail(stdout: &[u8], stderr: &[u8]) -> String {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    let lines: Vec<&str> = combined.lines().collect();
    let start = lines.len().saturating_sub(20);
    let tail = lines[start..].join("\n");
    // Bound it: a proc-macro backtrace can be megabytes on a single line.
    const MAX_CHARS: usize = 4000;
    let length = tail.chars().count();
    if length <= MAX_CHARS {
        return tail;
    }
    tail.chars().skip(length - MAX_CHARS).collect()
}

// ---------------------------------------------------------------------------
// Toolchain probes. Each shells out once and treats any failure as "no".
// ---------------------------------------------------------------------------

fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let program = format!("{program}{}", std::env::consts::EXE_SUFFIX);
    std::env::split_paths(&path)
        .map(|dir| dir.join(&program))
        .find(|candidate| candidate.is_file())
}

fn nightly_is_installed() -> bool {
    Command::new("rustup")
        .args(["toolchain", "list"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|line| line.starts_with("nightly"))
        })
}

fn rust_src_is_installed() -> bool {
    Command::new("rustup")
        .args(["component", "list", "--toolchain", "nightly", "--installed"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|line| line.starts_with("rust-src"))
        })
}

fn host_triple() -> Option<String> {
    let output = Command::new("rustup")
        .args(["run", "nightly", "rustc", "-vV"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(|triple| triple.trim().to_string())
}

fn supported_sanitizers(triple: &str) -> Option<Vec<String>> {
    let output = Command::new("rustup")
        .args(["run", "nightly", "rustc", "-Zunstable-options", "--target"])
        .arg(triple)
        .args(["--print", "target-spec-json"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_supported_sanitizers(&String::from_utf8_lossy(&output.stdout))
}

fn cargo_metadata(manifest_path: &Path) -> Option<String> {
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(manifest_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    /// The capability question is asked of rustc, never guessed, because the
    /// answer differs by platform.
    #[test]
    fn reads_the_supported_sanitizers_rustc_reports() {
        let spec = r#"{"arch":"aarch64","supported-sanitizers":["address","thread","cfi"]}"#;
        assert_eq!(
            parse_supported_sanitizers(spec),
            Some(names(&["address", "thread", "cfi"]))
        );
        assert_eq!(
            parse_supported_sanitizers(r#"{"arch":"wasm32"}"#),
            None,
            "a target that lists no sanitizers must not read as 'all of them'"
        );
        assert_eq!(parse_supported_sanitizers("not json"), None);
    }

    #[test]
    fn keeps_only_sanitizers_the_target_supports() {
        let plan = partition_requested(
            &names(&["address", "memory"]),
            &names(&["address", "thread", "cfi"]),
        );
        assert_eq!(plan.wanted, names(&["address"]));
        assert_eq!(plan.unsupported, names(&["memory"]));
    }

    /// MSan on arm64 macOS: rustc's own list has neither `memory` nor `leak`,
    /// so asking for it has to skip rather than build something that cannot
    /// show what it was asked to show.
    #[test]
    fn msan_on_a_target_without_it_skips_by_name() {
        let plan = partition_requested(&names(&["memory"]), &names(&["address", "thread", "cfi"]));
        assert!(plan.wanted.is_empty());
        assert_eq!(plan.empty_reason(), "sanitizer-unsupported-on-target");
    }

    /// **Rust has no UBSan.** `-Zsanitizer=undefined` does not exist on any
    /// target, on any nightly, so the skip must say so rather than imply that
    /// some other platform would have it.
    #[test]
    fn ubsan_on_rust_skips_with_the_reason_that_there_is_no_such_thing() {
        for alias in UBSAN_ALIASES {
            let plan =
                partition_requested(&[alias.to_string()], &names(&["address", "thread", "cfi"]));
            assert!(plan.wanted.is_empty(), "{alias} must not be buildable");
            assert_eq!(plan.unsupported, names(&["undefined"]));
            assert_eq!(plan.empty_reason(), "sanitizer-unsupported-on-target");
            assert!(
                plan.notes.iter().any(|n| n.contains("rustc-has-no-ubsan")),
                "{alias} must carry the note naming the real answer: {:?}",
                plan.notes
            );
            assert!(
                plan.notes.iter().any(|n| n.contains("overflow-checks=on")),
                "the note must point at the Rust equivalent"
            );
        }
    }

    /// A sanitizer rustc supports but cxg cannot read back out of the artefact
    /// is declined up front, with its own reason: no platform would help.
    #[test]
    fn a_sanitizer_cxg_cannot_verify_is_declined_before_the_build() {
        let plan = partition_requested(&names(&["cfi"]), &names(&["address", "cfi"]));
        assert!(plan.wanted.is_empty());
        assert_eq!(plan.unverifiable, names(&["cfi"]));
        assert_eq!(plan.empty_reason(), "sanitizer-not-verifiable(cfi)");
    }

    #[test]
    fn a_verifiable_sanitizer_survives_alongside_an_unverifiable_one() {
        let plan = partition_requested(&names(&["address", "cfi"]), &names(&["address", "cfi"]));
        assert_eq!(plan.wanted, names(&["address"]));
        assert_eq!(plan.unverifiable, names(&["cfi"]));
    }

    #[test]
    fn every_verifiable_sanitizer_maps_to_a_label_the_detector_reports() {
        for (name, label) in VERIFIABLE_SANITIZERS {
            assert_eq!(label_for(name), Some(*label));
        }
        assert_eq!(label_for("cfi"), None);
    }

    #[test]
    fn the_build_flags_carry_debug_info_and_the_overflow_check() {
        let flags = rustflags(&names(&["address"]));
        assert!(flags.contains("-Zsanitizer=address"), "{flags}");
        assert!(flags.contains("-C debuginfo=2"), "{flags}");
        assert!(flags.contains("-C force-frame-pointers=yes"), "{flags}");
        // Rust's answer to UBSan's integer check, set explicitly so a project
        // that disabled it in [profile.dev] gets it back.
        assert!(flags.contains("-C overflow-checks=on"), "{flags}");
        assert_eq!(
            rustflags(&names(&["address", "thread"])),
            rustflags(&names(&["address", "thread"])),
            "the flag string must be deterministic"
        );
        assert!(rustflags(&names(&["address", "thread"])).contains("-Zsanitizer=address,thread"));
    }

    /// **The case the whole component exists for.** A build can accept the
    /// flags, report success, link, run -- and carry no instrumentation at
    /// all. There is no path from that to `instrumented`.
    #[test]
    fn a_build_that_silently_dropped_the_flags_is_refused() {
        assert_eq!(
            verification_gap(&names(&["address"]), &[]),
            Some("build-produced-no-instrumentation(wanted=asan detected=none)".to_string())
        );
        assert_eq!(
            verification_gap(&names(&["address"]), &names(&["debug-info"])),
            Some("build-produced-no-instrumentation(wanted=asan detected=debug-info)".to_string())
        );
    }

    /// A build asked for two sanitizers and carrying one is not the build the
    /// operator is about to draw a conclusion from.
    #[test]
    fn a_partially_instrumented_build_is_refused_too() {
        assert_eq!(
            verification_gap(&names(&["address", "thread"]), &names(&["asan"])),
            Some("build-produced-no-instrumentation(wanted=asan,tsan detected=asan)".to_string())
        );
    }

    #[test]
    fn a_verified_build_passes_verification() {
        assert_eq!(
            verification_gap(&names(&["address"]), &names(&["asan", "debug-info"])),
            None
        );
        assert_eq!(
            verification_gap(
                &names(&["address", "thread"]),
                &names(&["asan", "debug-info", "tsan"])
            ),
            None
        );
    }

    #[test]
    fn infers_the_binary_target_when_a_project_has_exactly_one() {
        let metadata = r#"{"packages":[{"targets":[
            {"kind":["lib"],"name":"toy"},
            {"kind":["bin"],"name":"toy"}
        ]}]}"#;
        assert_eq!(sole_bin_target(metadata), Some("toy".to_string()));
    }

    /// A workspace with four binaries -- the real shape that provoked this --
    /// gives cxg no way to know which one is the CLI. Naming the flag that
    /// resolves it beats instrumenting something nobody asked for.
    #[test]
    fn refuses_to_choose_between_several_binary_targets() {
        let metadata = r#"{"packages":[
            {"targets":[{"kind":["bin"],"name":"app"},{"kind":["bin"],"name":"helper"}]},
            {"targets":[{"kind":["bin"],"name":"tool"}]}
        ]}"#;
        assert_eq!(sole_bin_target(metadata), None);
    }

    #[test]
    fn a_project_with_no_binary_target_is_also_ambiguous() {
        let metadata = r#"{"packages":[{"targets":[{"kind":["lib"],"name":"toy"}]}]}"#;
        assert_eq!(sole_bin_target(metadata), None);
        assert_eq!(sole_bin_target("not json"), None);
    }
}
