//! End-to-end tests for how the Go engine resolves a template's imports.
//!
//! A Go template is one `package main` file. Before the private-module build,
//! one that imported anything outside the standard library failed with "no
//! required module provides package" unless the operator wrote a `go.mod` and
//! ran `go get` by hand. These tests drive the real `cxg` binary over Go
//! templates written into a temp dir (outside every module) and read the
//! execution ledger back.
//!
//! Every test needs a Go toolchain and is skipped, loudly, when `go` is not on
//! PATH. The one test that downloads a real module is `#[ignore]`d because it
//! needs the network: run it with
//! `cargo test --test go_template_modules -- --ignored`.
//!
//! Each run gets its own HOME, CERT_X_GEN_HOME, GOMODCACHE and GOCACHE, so the
//! tests neither read nor write the operator's caches.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

fn go_available() -> bool {
    let ok = Command::new("go")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: no `go` toolchain on PATH");
    }
    ok
}

/// A Go template that emits one high finding, plus whatever `imports` and
/// `body_prefix` code it needs to use them.
fn template(id: &str, imports: &str, use_imports: &str) -> String {
    format!(
        r#"package main

// @id: {id}
// @name: Go module resolution fixture
// @author: CERT-X-GEN
// @severity: high
// @description: Emits one finding once it compiles; under test is whether it compiles
// @tags: test, go
// @version: 1.0.0

import (
	"encoding/json"
	"fmt"
{imports}
)

func main() {{
	marker := {use_imports}
	out := map[string]interface{{}}{{
		"findings": []map[string]interface{{}}{{{{
			"template_id": "{id}",
			"severity":    "high",
			"confidence":  90,
			"title":       "compiled with " + marker,
			"description": "fixture",
		}}}},
	}}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}}
"#
    )
}

struct Row {
    status: String,
    findings: u64,
    detail: String,
}

/// Run `cxg scan` with one template against an unused loopback port, in an
/// isolated home and Go cache, and read back the single ledger row.
fn scan(dir: &Path, template_path: &Path, go_env: &[(&str, &str)]) -> (Row, String) {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cxg"));
    cmd.current_dir(dir)
        .env("CXG_NO_BANNER", "1")
        .env("HOME", &home)
        .env("CERT_X_GEN_HOME", &home)
        .env("GOMODCACHE", dir.join("gomodcache"))
        .env("GOCACHE", dir.join("gocache"))
        .env("GOPATH", dir.join("gopath"))
        // Let the test clean its temp dir: the module cache is read-only by default.
        .env("GOFLAGS", "-modcacherw")
        .env("GOTOOLCHAIN", "local")
        .arg("scan")
        .arg("--disable-update-check")
        .arg("--no-color")
        .args(["--scope", "127.0.0.1:9"])
        .args(["--templates", template_path.to_str().unwrap()])
        .args(["--timeout", "120s"])
        .args(["--output", "result"])
        .args(["--output-format", "json"]);
    for (k, v) in go_env {
        cmd.env(k, v);
    }

    let out = cmd.output().expect("run cxg scan");
    let logs = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let result_path = dir.join("result.json");
    assert!(
        result_path.exists(),
        "cxg scan produced no result.json\n{logs}"
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&result_path).unwrap()).unwrap();
    let rows = doc["executions"].as_array().expect("executions ledger");
    assert_eq!(rows.len(), 1, "expected one ledger row\n{logs}");
    let row = Row {
        status: rows[0]["status"].as_str().unwrap().to_string(),
        findings: rows[0]["findings"].as_u64().unwrap(),
        detail: rows[0]["detail"].as_str().unwrap_or_default().to_string(),
    };
    (row, logs)
}

/// A stdlib-only template outside any module still builds in place, as before.
#[test]
fn a_stdlib_only_template_builds_in_place() {
    if !go_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stdlib-only.go");
    std::fs::write(
        &path,
        template(
            "go-stdlib-only",
            "\t\"strings\"",
            "strings.ToUpper(\"stdlib\")",
        ),
    )
    .unwrap();

    let (row, logs) = scan(dir.path(), &path, &[]);
    assert_eq!(row.status, "confirmed", "{logs}\ndetail: {}", row.detail);
    assert_eq!(row.findings, 1);
    assert!(
        !dir.path()
            .join("home/.cert-x-gen/cache/go-modules")
            .exists(),
        "a stdlib-only template must not get a private module"
    );
}

/// A template already inside a Go module is built against THAT module, even
/// when its third-party import is only satisfiable through the module's own
/// `replace` directive -- i.e. no private module and no download.
#[test]
fn a_template_inside_a_module_builds_against_that_module() {
    if !go_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let module = dir.path().join("mod");
    std::fs::create_dir_all(module.join("dep")).unwrap();
    std::fs::write(
        module.join("go.mod"),
        "module example.test/templates\n\ngo 1.21\n\nrequire example.test/dep v0.0.0\n\nreplace example.test/dep => ./dep\n",
    )
    .unwrap();
    std::fs::write(
        module.join("dep/go.mod"),
        "module example.test/dep\n\ngo 1.21\n",
    )
    .unwrap();
    std::fs::write(
        module.join("dep/dep.go"),
        "package dep\n\nfunc Name() string { return \"local-dep\" }\n",
    )
    .unwrap();
    let path = module.join("in-module.go");
    std::fs::write(
        &path,
        template("go-in-module", "\t\"example.test/dep\"", "dep.Name()"),
    )
    .unwrap();

    // GOPROXY=off proves nothing was downloaded.
    let (row, logs) = scan(dir.path(), &path, &[("GOPROXY", "off")]);
    assert_eq!(row.status, "confirmed", "{logs}\ndetail: {}", row.detail);
    assert_eq!(row.findings, 1);
    assert!(
        !dir.path()
            .join("home/.cert-x-gen/cache/go-modules")
            .exists(),
        "an in-module template must not get a private module"
    );
}

/// With module downloads disabled, a template that needs one fails fast with
/// an error that names the import and says why -- it does not hang, and it
/// leaves no half-built cache entry behind for a later scan to trust.
#[test]
fn an_offline_private_module_build_fails_fast_and_clearly() {
    if !go_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("needs-network.go");
    std::fs::write(
        &path,
        template(
            "go-needs-network",
            "\t\"golang.org/x/text/language\"",
            "language.English.String()",
        ),
    )
    .unwrap();

    let started = Instant::now();
    let (row, logs) = scan(dir.path(), &path, &[("GOPROXY", "off")]);
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "an offline build must fail fast, took {:?}",
        started.elapsed()
    );
    assert_eq!(row.status, "errored", "{logs}");
    assert_eq!(row.findings, 0);
    let text = format!("{}\n{}", row.detail, logs);
    assert!(
        text.contains("golang.org/x/text/language") && text.contains("go mod tidy"),
        "the error must name the import and the step that failed:\n{text}"
    );
    assert!(text.contains("GOPROXY=off"), "{text}");

    let cache = dir.path().join("home/.cert-x-gen/cache/go-modules");
    let leftovers: Vec<_> = std::fs::read_dir(&cache)
        .map(|rd| rd.flatten().map(|e| e.file_name()).collect())
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "a failed build must not leave a cache entry: {leftovers:?}"
    );
}

/// The real fix: a template importing a third-party module, outside any
/// module, builds and runs with no hand-written go.mod. Downloads from the
/// operator's GOPROXY, so it needs the network. `github.com/google/uuid` is
/// used because its latest release still builds on old toolchains.
#[test]
#[ignore = "downloads github.com/google/uuid from GOPROXY; run with --ignored"]
fn a_third_party_import_outside_a_module_resolves_in_a_private_module() {
    if !go_available() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("third-party.go");
    std::fs::write(
        &path,
        template(
            "go-third-party",
            "\t\"github.com/google/uuid\"",
            "uuid.NewString()[:0] + \"uuid\"",
        ),
    )
    .unwrap();

    let (row, logs) = scan(dir.path(), &path, &[]);
    assert_eq!(row.status, "confirmed", "{logs}\ndetail: {}", row.detail);
    assert_eq!(row.findings, 1);

    let cache = dir.path().join("home/.cert-x-gen/cache/go-modules");
    let entries: Vec<_> = std::fs::read_dir(&cache)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    assert_eq!(entries.len(), 1, "one private module: {entries:?}");
    let go_mod = std::fs::read_to_string(entries[0].join("go.mod")).unwrap();
    assert!(go_mod.starts_with("module cxg.local/template"), "{go_mod}");
    assert!(go_mod.contains("github.com/google/uuid"), "{go_mod}");
    assert!(
        dir.path().join("third-party.go").exists() && !dir.path().join("go.mod").exists(),
        "the template's own directory is never written to"
    );

    // A second scan reuses the cached build, offline.
    let (again, logs) = scan(dir.path(), &path, &[("GOPROXY", "off")]);
    assert_eq!(again.status, "confirmed", "{logs}");
}
