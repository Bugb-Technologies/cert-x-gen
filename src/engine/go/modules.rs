//! Resolving third-party imports for Go templates.
//!
//! A Go template is a single `package main` file. `go build file.go` resolves
//! standard-library imports on its own, but an import such as
//! `google.golang.org/grpc` needs a module (`go.mod`) that requires it, and a
//! template downloaded into `~/.cert-x-gen/templates` has none. Before this
//! module existed such a template failed with "no required module provides
//! package" unless the operator hand-wrote a `go.mod` and ran `go get` first.
//!
//! The fix is a **private build module per template**: when a template imports
//! a non-stdlib package and is not already inside a Go module, cxg copies it
//! into its own directory under the cxg home, writes a generated `go.mod`, runs
//! `go mod tidy` there and builds. The directory is keyed by a hash of the
//! template's bytes, so an unchanged template reuses its binary and an edited
//! one gets a fresh module.
//!
//! Everything here except [`private_module_cache_root`] is a pure function of
//! its inputs so it can be unit-tested without a Go toolchain.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Module path written into a generated `go.mod`.
///
/// The first path element carries a dot so it can never shadow a standard
/// library package (Go treats a dot-free first element as stdlib), and `.local`
/// is not a resolvable proxy host, so nothing ever tries to download it.
pub const PRIVATE_MODULE_PATH: &str = "cxg.local/template";

/// Bumped whenever the shape of the private module changes (the generated
/// `go.mod`, the build command), so stale cache entries are not reused.
const PRIVATE_MODULE_SCHEMA: &str = "cxg-go-private-module-v1";

/// The `go.mod` cxg writes into a template's private build directory.
///
/// No `go` directive is written: `go mod tidy` adds one naming the operator's
/// own toolchain, which is the only version that is guaranteed to be valid on
/// this machine.
// @comment -- "generated go.mod for a Go template's private build module; the module path cannot collide with stdlib or a real host"
pub fn generate_go_mod() -> String {
    format!("module {}\n", PRIVATE_MODULE_PATH)
}

/// Cache key for a template's private build directory: a SHA-256 of the
/// template's bytes (plus the schema tag), as lowercase hex, truncated to
/// 16 characters.
///
/// Keyed on content rather than path or mtime, so the same template reached
/// through two paths shares one build and any edit gets a new one.
// @comment -- "content-hash cache key for the per-template private Go module; any edit to the template selects a new build directory"
pub fn content_cache_key(source: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PRIVATE_MODULE_SCHEMA.as_bytes());
    hasher.update([0u8]);
    hasher.update(source);
    let digest = format!("{:x}", hasher.finalize());
    digest[..16].to_string()
}

/// Where private build modules live: `<cxg home>/cache/go-modules`.
///
/// Honors `CERT_X_GEN_HOME` through [`crate::template::PathResolver`].
pub fn private_module_cache_root() -> PathBuf {
    crate::template::PathResolver::cache_dir().join("go-modules")
}

/// The nearest ancestor of `dir` (inclusive) that holds a `go.mod`, if any.
///
/// A template inside a module is built in place, against that module, exactly
/// as before; only a template outside every module gets a private one.
pub fn find_enclosing_module(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .find(|ancestor| ancestor.join("go.mod").is_file())
        .map(Path::to_path_buf)
}

/// Whether an import path names a standard-library package.
///
/// Go's own rule: a standard-library import path has no dot in its first
/// element (`net/http`, `encoding/json`), and every module path that can be
/// downloaded does (`google.golang.org/grpc`, `github.com/x/y`). `C` is cgo's
/// pseudo-package and needs no module either.
pub fn is_stdlib_import(path: &str) -> bool {
    let first = path.split('/').next().unwrap_or("");
    !first.contains('.')
}

/// Import paths in a Go source file that are not in the standard library, in
/// the order they appear, without duplicates.
///
/// Reads only the import declarations that follow the `package` clause, after
/// removing comments, so an `import` written inside a doc comment (templates
/// carry long ones) is never mistaken for a real import.
pub fn third_party_imports(source: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for path in import_paths(&strip_comments(source)) {
        if !is_stdlib_import(&path) && !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

/// Every import path declared in comment-free Go source.
fn import_paths(code: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut rest = code;

    // Skip to just after the package clause; imports may only follow it.
    match find_keyword(rest, "package") {
        Some(idx) => {
            rest = &rest[idx + "package".len()..];
            // Consume the package name.
            rest = rest.trim_start();
            let end = rest
                .find(|c: char| c.is_whitespace() || c == ';')
                .unwrap_or(rest.len());
            rest = &rest[end..];
        }
        None => return paths,
    }

    loop {
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == ';');
        let Some(after) = strip_keyword(rest, "import") else {
            // The first top-level declaration that is not an import ends the
            // import section (Go requires imports to come first).
            break;
        };
        let after = after.trim_start();
        if let Some(block) = after.strip_prefix('(') {
            let close = block.find(')').unwrap_or(block.len());
            for spec in block[..close].split(['\n', ';']) {
                if let Some(path) = first_string_literal(spec) {
                    paths.push(path);
                }
            }
            rest = block.get(close + 1..).unwrap_or("");
        } else {
            let line_end = after.find(['\n', ';']).unwrap_or(after.len());
            if let Some(path) = first_string_literal(&after[..line_end]) {
                paths.push(path);
            }
            rest = &after[line_end..];
        }
    }
    paths
}

/// `s` without a leading `keyword`, when `s` starts with that whole word.
fn strip_keyword<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    let after = s.strip_prefix(keyword)?;
    match after.chars().next() {
        Some(c) if c.is_alphanumeric() || c == '_' => None,
        _ => Some(after),
    }
}

/// Byte index of `keyword` where it stands as a whole word at a line start.
fn find_keyword(s: &str, keyword: &str) -> Option<usize> {
    let mut offset = 0;
    for line in s.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if strip_keyword(trimmed, keyword).is_some() {
            return Some(offset + (line.len() - trimmed.len()));
        }
        offset += line.len();
    }
    None
}

/// The contents of the first `"..."` or `` `...` `` literal in an import spec
/// (`alias "path"`, `_ "path"`, `. "path"` or just `"path"`).
fn first_string_literal(spec: &str) -> Option<String> {
    let start = spec.find(['"', '`'])?;
    let quote = spec[start..].chars().next()?;
    let body = &spec[start + 1..];
    let end = body.find(quote)?;
    let path = body[..end].trim();
    (!path.is_empty()).then(|| path.to_string())
}

/// Go source with `//` and `/* */` comments replaced by whitespace, leaving
/// string, raw-string and rune literals intact (a `//` inside a URL string is
/// not a comment).
fn strip_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'/') => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut prev = '\0';
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                    }
                    if prev == '*' && next == '/' {
                        break;
                    }
                    prev = next;
                }
                out.push(' ');
            }
            '"' | '\'' => {
                out.push(c);
                let mut escaped = false;
                for next in chars.by_ref() {
                    out.push(next);
                    if escaped {
                        escaped = false;
                    } else if next == '\\' {
                        escaped = true;
                    } else if next == c || next == '\n' {
                        break;
                    }
                }
            }
            '`' => {
                out.push(c);
                for next in chars.by_ref() {
                    out.push(next);
                    if next == '`' {
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// A one-line hint appended to a failed `go mod tidy`, for the two failures
/// an operator can fix without touching the template: module downloads
/// disabled or unreachable, and a dependency whose latest version needs a
/// newer Go than the local toolchain.
pub fn tidy_failure_hint(stderr: &str) -> Option<&'static str> {
    const OFFLINE_MARKERS: &[&str] = &[
        "GOPROXY=off",
        "GOFLAGS=-mod=",
        "dial tcp",
        "no such host",
        "i/o timeout",
        "connection refused",
        "TLS handshake timeout",
    ];
    if OFFLINE_MARKERS.iter().any(|marker| stderr.contains(marker)) {
        return Some(
            "module downloads are disabled or unreachable. Run the scan once while online \
             (or with GOPROXY set) to populate the module cache, point \
             GOPROXY=file://$(go env GOMODCACHE)/cache/download at an already-populated \
             cache, or place the template in a Go module with its dependencies vendored.",
        );
    }
    if stderr.contains("toolchain upgrade needed") || stderr.contains("requires go >=") {
        return Some(
            "the newest version of a dependency needs a newer Go than this toolchain. \
             Upgrade Go, allow GOTOOLCHAIN=auto, or place the template in a Go module \
             that pins compatible versions.",
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRPC_TEMPLATE: &str = r#"package main

// @id: grpc-reflection-abuse
/*
WHY GO:
- Native gRPC support via google.golang.org/grpc
import "example.com/in/a/comment"
*/

import (
	"context"
	"encoding/json"
	"fmt" // a trailing "comment.example/x"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	refl "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
)

var url = "https://example.com/not/an/import"

func main() {}
"#;

    #[test]
    fn finds_only_the_non_stdlib_imports_of_a_block() {
        assert_eq!(
            third_party_imports(GRPC_TEMPLATE),
            vec![
                "google.golang.org/grpc",
                "google.golang.org/grpc/credentials/insecure",
                "google.golang.org/grpc/reflection/grpc_reflection_v1alpha",
            ]
        );
    }

    #[test]
    fn an_import_written_in_a_comment_is_not_an_import() {
        let imports = third_party_imports(GRPC_TEMPLATE);
        assert!(!imports.iter().any(|i| i.contains("example.com")));
        assert!(!imports.iter().any(|i| i.contains("comment.example")));
    }

    #[test]
    fn a_stdlib_only_template_needs_no_module() {
        let src =
            "package main\n\nimport (\n\t\"fmt\"\n\t\"net/http\"\n\t\"C\"\n)\n\nfunc main() {}\n";
        assert!(third_party_imports(src).is_empty());
    }

    #[test]
    fn reads_single_line_imports_with_alias_blank_and_dot_forms() {
        let src = "package main\n\
                   import \"fmt\"\n\
                   import x \"github.com/a/x\"\n\
                   import _ \"github.com/b/y\"; import . `gopkg.in/c.v1`\n\
                   import \"github.com/a/x\"\n\
                   func main() { import_like := \"github.com/never/z\"; _ = import_like }\n";
        assert_eq!(
            third_party_imports(src),
            vec!["github.com/a/x", "github.com/b/y", "gopkg.in/c.v1"]
        );
    }

    #[test]
    fn stdlib_is_decided_by_a_dot_in_the_first_path_element() {
        assert!(is_stdlib_import("net/http"));
        assert!(is_stdlib_import("encoding/json"));
        assert!(is_stdlib_import("C"));
        assert!(!is_stdlib_import("google.golang.org/grpc"));
        assert!(!is_stdlib_import("github.com/x/y"));
    }

    #[test]
    fn the_generated_go_mod_names_the_private_module_and_nothing_else() {
        let go_mod = generate_go_mod();
        assert_eq!(go_mod, "module cxg.local/template\n");
        // The module path must never be read as a stdlib path.
        assert!(!is_stdlib_import(PRIVATE_MODULE_PATH));
    }

    #[test]
    fn the_cache_key_follows_content_not_location() {
        let a = content_cache_key(b"package main\nfunc main() {}\n");
        let same = content_cache_key(b"package main\nfunc main() {}\n");
        let edited = content_cache_key(b"package main\nfunc main() { }\n");
        assert_eq!(a, same);
        assert_ne!(a, edited);
        assert_eq!(a.len(), 16);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn finds_the_nearest_enclosing_module() {
        let root = tempfile::tempdir().unwrap();
        let module = root.path().join("mod");
        let nested = module.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        // Before a go.mod is written, the answer is whatever encloses the temp
        // dir itself (normally nothing), never the not-yet-a-module directory.
        assert_eq!(
            find_enclosing_module(&nested),
            find_enclosing_module(root.path())
        );
        std::fs::write(module.join("go.mod"), "module example.com/m\n").unwrap();
        assert_eq!(find_enclosing_module(&nested), Some(module.clone()));
        assert_eq!(find_enclosing_module(&module), Some(module));
    }

    #[test]
    fn a_fixable_tidy_failure_gets_a_hint_and_a_compile_error_does_not() {
        let offline = "go: cxg.local/template imports\n\tgoogle.golang.org/grpc: \
                       cannot find module providing package google.golang.org/grpc: \
                       module lookup disabled by GOPROXY=off";
        assert!(tidy_failure_hint(offline)
            .unwrap()
            .starts_with("module downloads"));
        let too_new = "go: toolchain upgrade needed to resolve golang.org/x/text/language\n\
                       go: golang.org/x/text@v0.42.0 requires go >= 1.26.0 (running go 1.25.6; \
                       GOTOOLCHAIN=local)";
        assert!(tidy_failure_hint(too_new).unwrap().contains("newer Go"));
        assert!(tidy_failure_hint("./main.go:3:2: undefined: foo").is_none());
    }

    #[test]
    fn the_private_module_cache_lives_under_the_cxg_home() {
        let root = private_module_cache_root();
        assert!(root.ends_with("cache/go-modules"));
        assert!(root.to_string_lossy().contains(".cert-x-gen"));
    }
}
