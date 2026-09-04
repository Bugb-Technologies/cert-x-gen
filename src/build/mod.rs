//! White-box build assist: produce an **instrumented** build of a target, or
//! say honestly why one could not be produced.
//!
//! `cxg scan` inspects a binary and refuses; it never builds the target. This
//! module is the deliberate opt-in on the other side of that line, reached
//! only through the separate `cxg build --instrument` verb. Building a project
//! runs that project's build system -- `build.rs`, `configure`, arbitrary
//! `Makefile` recipes -- as the invoking user, which is a different trust
//! decision from reading a file, and it costs minutes and gigabytes. Both are
//! reasons it is a verb an operator types rather than a flag a scan turns on.
//!
//! # The honest-failure boundary
//!
//! **There is no path from "I could not instrument this" to "here is a
//! binary".** Every precondition failure is a [`Skipped`] carrying a
//! machine-readable reason, and the last check is the one that earns the
//! phrase: after a build that reported success, cxg **re-reads the binary it
//! just produced** with the same symbol-table scan the scan preflight uses
//! ([`crate::engine::common::detect_instrumentation`]) and refuses to report
//! `instrumented` unless the instrumentation it asked for is actually in
//! there. A build system that accepted the flags and silently dropped them --
//! a `Makefile` that assigns rather than appends `CFLAGS` is the classic --
//! still links, still runs, and is indistinguishable from an instrumented
//! build until you look at the artefact. That case is
//! `build-produced-no-instrumentation`, and it skips.

pub mod cargo;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A build system cxg knows how to recognise.
///
/// Recognising one is not the same as being able to instrument it: only
/// [`BuildSystem::Cargo`] has a back end today, and every other arm skips with
/// `build-system-not-implemented`, which is the honest answer rather than a
/// hidden limitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildSystem {
    /// Rust, driven by `cargo`. The only back end implemented.
    Cargo,
    /// C/C++, configured by `cmake`.
    Cmake,
    /// Go, driven by the `go` tool.
    Go,
    /// C/C++, configured by a generated `configure` script.
    Autotools,
    /// C/C++, driven by a hand-written `Makefile`.
    Make,
    /// C/C++, configured by `meson`.
    Meson,
}

impl BuildSystem {
    /// The name this build system is reported under in a manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            BuildSystem::Cargo => "cargo",
            BuildSystem::Cmake => "cmake",
            BuildSystem::Go => "go",
            BuildSystem::Autotools => "autotools",
            BuildSystem::Make => "make",
            BuildSystem::Meson => "meson",
        }
    }
}

/// Marker files that identify a build system, **in priority order**.
///
/// First match wins, and the order is load bearing for polyglot repositories.
/// A Tauri application is a Cargo workspace with a `package.json`, a
/// `postcss.config.js` and a `tailwind.config.js` beside it; the thing cxg has
/// to instrument is the Rust binary, and putting `Cargo.toml` first is what
/// gets that right with no special-casing.
///
/// A tree matching none of these is [`None`] -- never a guess. Guessing here
/// ends in a build that produces the wrong artefact, or no artefact, and
/// either way the operator is told something untrue about what was scanned.
pub const BUILD_SYSTEM_MARKERS: &[(&str, BuildSystem)] = &[
    ("Cargo.toml", BuildSystem::Cargo),
    ("CMakeLists.txt", BuildSystem::Cmake),
    ("go.mod", BuildSystem::Go),
    ("configure", BuildSystem::Autotools),
    ("Makefile", BuildSystem::Make),
    ("makefile", BuildSystem::Make),
    ("meson.build", BuildSystem::Meson),
];

/// Which build system this directory holds, or [`None`] for a tree cxg does
/// not recognise.
pub fn detect_build_system(project: &Path) -> Option<BuildSystem> {
    BUILD_SYSTEM_MARKERS
        .iter()
        .find(|(marker, _)| project.join(marker).is_file())
        .map(|(_, system)| *system)
}

/// The marker files [`detect_build_system`] looked for, for a skip manifest to
/// report so the operator can see what would have been recognised.
pub fn build_system_markers_looked_for() -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for (marker, _) in BUILD_SYSTEM_MARKERS {
        if !seen.iter().any(|m| m == marker) {
            seen.push((*marker).to_string());
        }
    }
    seen
}

/// What the operator asked `cxg build --instrument` to do.
#[derive(Debug, Clone)]
pub struct InstrumentRequest {
    /// The project directory whose build system will be driven.
    pub project: PathBuf,
    /// Which binary target to build. `None` means "infer, and refuse if the
    /// project has more than one".
    pub bin: Option<String>,
    /// Sanitizers requested, in rustc's vocabulary (`address`, `thread`, ...).
    pub sanitizers: Vec<String>,
    /// Where to put the instrumented build tree. `None` means
    /// `<project>/target-instrumented`.
    ///
    /// Never the project's own `target/`: `RUSTFLAGS` is part of cargo's
    /// fingerprint, so sharing a target directory forces a full rebuild in
    /// *both* directions every time the operator alternates between an
    /// instrumented scan and their ordinary `cargo build`.
    pub out_dir: Option<PathBuf>,
    /// Rebuild `std` with the sanitizer (`-Zbuild-std`). Off by default;
    /// mandatory for MSan, and merely better for ASan, which interposes the
    /// allocator and so catches heap errors through a precompiled `std`.
    pub build_std: bool,
}

/// The single JSON object `cxg build --instrument` prints.
///
/// Two shapes, distinguished by `status`, and nothing in between -- see the
/// module documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Manifest {
    /// A binary was produced **and verified** to carry the instrumentation.
    Instrumented(Instrumented),
    /// No binary was produced, and `reason` says why.
    Skipped(Skipped),
}

impl Manifest {
    /// The instrumented half, or [`None`] when the build was skipped.
    pub fn instrumented(&self) -> Option<&Instrumented> {
        match self {
            Manifest::Instrumented(i) => Some(i),
            Manifest::Skipped(_) => None,
        }
    }
}

/// A build that ran, produced a binary, and had that binary verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instrumented {
    /// The build system that was driven (`cargo`).
    pub build_system: String,
    /// The toolchain that was selected (`nightly` -- `-Zsanitizer` is unstable
    /// and there is no stable equivalent).
    pub toolchain: String,
    /// The target triple the build was pinned to.
    pub target: String,
    /// The binary target that was built.
    pub bin: String,
    /// Absolute path to the produced binary.
    pub binary: PathBuf,
    /// The exact `RUSTFLAGS` value the build ran with.
    pub rustflags: String,
    /// Whether `std` was rebuilt with the sanitizer.
    pub build_std: bool,
    /// The instrumentation labels **read back out of the produced binary**.
    ///
    /// This is what makes the manifest evidence rather than an intention: it
    /// is what the artefact carries, not what cxg asked for. `cxg scan
    /// --instrumented-manifest` trusts this in preference to re-sniffing the
    /// file.
    pub instrumentation: Vec<String>,
    /// Sanitizers the operator asked for that this target cannot provide, kept
    /// so a manifest records what was declined as well as what was done.
    pub unsupported_requested: Vec<String>,
    /// Human-readable notes, e.g. that Rust has no UBSan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// A build that did not happen, or happened and did not earn the word
/// `instrumented`.
///
/// `reason` is the machine-readable half and is always present; every other
/// field is context for the operator and is omitted when it does not apply.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    /// The machine-readable reason, e.g.
    /// `build-produced-no-instrumentation(wanted=asan detected=none)`.
    pub reason: String,
    /// The build system that was recognised, when one was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_system: Option<String>,
    /// The project directory that was examined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<PathBuf>,
    /// The marker files that were looked for, for `unknown-build-system`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub looked_for: Vec<String>,
    /// The target triple whose capability was consulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The sanitizers the operator asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    /// The sanitizers this target actually supports, as rustc reported them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported: Option<String>,
    /// The binary that was produced but could not be verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binary: Option<PathBuf>,
    /// The `RUSTFLAGS` the build ran with, when it ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rustflags: Option<String>,
    /// The tail of the build log, for `instrumented-build-failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_log_tail: Option<String>,
    /// Human-readable notes, e.g. that Rust has no UBSan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Skipped {
    /// A skip carrying only its reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Skipped {
            reason: reason.into(),
            ..Skipped::default()
        }
    }
}

/// Build `request`'s project with instrumentation, or explain why not.
///
/// Never fails: every way this can go wrong is a [`Manifest::Skipped`] with a
/// reason, because a caller that got an error back would have to decide what
/// to do with it, and the only correct decision is the one this module already
/// made.
pub fn instrument(request: &InstrumentRequest) -> Manifest {
    let project = match request.project.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return Manifest::Skipped(Skipped {
                project: Some(request.project.clone()),
                ..Skipped::new(format!(
                    "project-directory-not-found({})",
                    request.project.display()
                ))
            })
        }
    };
    if !project.is_dir() {
        return Manifest::Skipped(Skipped {
            project: Some(project.clone()),
            ..Skipped::new(format!(
                "project-directory-not-found({})",
                project.display()
            ))
        });
    }

    let Some(system) = detect_build_system(&project) else {
        return Manifest::Skipped(Skipped {
            project: Some(project),
            looked_for: build_system_markers_looked_for(),
            ..Skipped::new("unknown-build-system")
        });
    };

    match system {
        BuildSystem::Cargo => cargo::instrument(&project, request),
        // Designed but not built. Refusing by name is the honest-failure
        // boundary doing its job: each of these needs its own flag plumbing
        // (cmake's separate linker flags, make's assign-vs-append trap), and a
        // back end that pretended to handle them would produce exactly the
        // uninstrumented binary the post-build verification exists to catch.
        other => Manifest::Skipped(Skipped {
            build_system: Some(other.as_str().to_string()),
            project: Some(project),
            ..Skipped::new(format!("build-system-not-implemented({})", other.as_str()))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_with(files: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("creating a project directory");
        for file in files {
            std::fs::write(dir.path().join(file), b"").expect("writing a marker file");
        }
        dir
    }

    #[test]
    fn recognises_each_build_system_by_its_marker_file() {
        for (marker, expected) in BUILD_SYSTEM_MARKERS {
            let dir = dir_with(&[marker]);
            assert_eq!(
                detect_build_system(dir.path()),
                Some(*expected),
                "{marker} should identify {expected:?}"
            );
        }
    }

    /// A Tauri application is a Cargo workspace with a JavaScript build beside
    /// it, and a `Makefile` is a common convenience wrapper in a Rust repo.
    /// The thing cxg has to instrument in both cases is the Rust binary.
    #[test]
    fn cargo_wins_over_every_other_marker_in_a_polyglot_tree() {
        let dir = dir_with(&["Cargo.toml", "Makefile", "CMakeLists.txt", "go.mod"]);
        assert_eq!(detect_build_system(dir.path()), Some(BuildSystem::Cargo));
    }

    /// The important direction: an unrecognised tree is not a guess.
    #[test]
    fn an_unrecognised_tree_is_not_guessed_at() {
        let dir = dir_with(&["README.md", "setup.py", "package.json"]);
        assert_eq!(detect_build_system(dir.path()), None);

        let manifest = instrument(&InstrumentRequest {
            project: dir.path().to_path_buf(),
            bin: None,
            sanitizers: vec!["address".to_string()],
            out_dir: None,
            build_std: false,
        });
        let Manifest::Skipped(skipped) = manifest else {
            panic!("an unrecognised tree must skip");
        };
        assert_eq!(skipped.reason, "unknown-build-system");
        assert!(skipped.looked_for.contains(&"Cargo.toml".to_string()));
        assert!(skipped.looked_for.contains(&"meson.build".to_string()));
    }

    /// A directory marker must not read as a build system: `configure` and
    /// `Makefile` are both plausible directory names.
    #[test]
    fn a_directory_named_like_a_marker_is_not_a_build_system() {
        let dir = tempfile::tempdir().expect("creating a project directory");
        std::fs::create_dir(dir.path().join("configure")).expect("creating the decoy directory");
        assert_eq!(detect_build_system(dir.path()), None);
    }

    #[test]
    fn a_recognised_build_system_with_no_back_end_names_itself() {
        let dir = dir_with(&["CMakeLists.txt"]);
        let manifest = instrument(&InstrumentRequest {
            project: dir.path().to_path_buf(),
            bin: None,
            sanitizers: vec!["address".to_string()],
            out_dir: None,
            build_std: false,
        });
        let Manifest::Skipped(skipped) = manifest else {
            panic!("cmake has no back end and must skip");
        };
        assert_eq!(skipped.reason, "build-system-not-implemented(cmake)");
        assert_eq!(skipped.build_system.as_deref(), Some("cmake"));
    }

    #[test]
    fn a_project_directory_that_does_not_exist_skips_by_name() {
        let manifest = instrument(&InstrumentRequest {
            project: PathBuf::from("/nonexistent/cxg-build-instrument-test"),
            bin: None,
            sanitizers: vec!["address".to_string()],
            out_dir: None,
            build_std: false,
        });
        let Manifest::Skipped(skipped) = manifest else {
            panic!("a missing project directory must skip");
        };
        assert!(
            skipped.reason.starts_with("project-directory-not-found("),
            "unexpected reason: {}",
            skipped.reason
        );
    }

    /// The manifest is a wire format: `cxg scan --instrumented-manifest` reads
    /// back what `cxg build --instrument` wrote, so the two shapes have to
    /// survive a round trip and stay distinguishable by `status` alone.
    #[test]
    fn both_manifest_shapes_round_trip_through_json() {
        let instrumented = Manifest::Instrumented(Instrumented {
            build_system: "cargo".to_string(),
            toolchain: "nightly".to_string(),
            target: "aarch64-apple-darwin".to_string(),
            bin: "toy".to_string(),
            binary: PathBuf::from("/tmp/out/aarch64-apple-darwin/debug/toy"),
            rustflags: "-Zsanitizer=address".to_string(),
            build_std: false,
            instrumentation: vec!["asan".to_string(), "debug-info".to_string()],
            unsupported_requested: vec!["undefined".to_string()],
            notes: vec!["rustc-has-no-ubsan".to_string()],
        });
        let json = serde_json::to_string(&instrumented).expect("serialising");
        assert!(json.contains(r#""status":"instrumented""#), "{json}");
        assert_eq!(
            serde_json::from_str::<Manifest>(&json).expect("deserialising"),
            instrumented
        );

        let skipped = Manifest::Skipped(Skipped::new("nightly-toolchain-unavailable"));
        let json = serde_json::to_string(&skipped).expect("serialising");
        assert_eq!(
            json, r#"{"status":"skipped","reason":"nightly-toolchain-unavailable"}"#,
            "a bare skip must not carry empty context fields"
        );
        assert_eq!(
            serde_json::from_str::<Manifest>(&json).expect("deserialising"),
            skipped
        );
    }
}
