//! Execute the documented local-template workflow with an offline scanner.
#![cfg(unix)]

use std::fs;
use std::process::Command;

#[test]
fn readme_and_mcp_select_the_reviewed_file_and_save_the_report() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("repository with spaces");
    let templates = root.join(".guardlink/cxg-templates");
    fs::create_dir_all(&templates).unwrap();
    fs::write(
        templates.join("reviewed-check.py"),
        r#"#!/usr/bin/env python3
# @id: docs-loop-offline-check
# @name: Documentation loop offline fixture
# @author: CERT-X-GEN contributors
# @severity: info
# @description: Exercise command selection without network traffic.
# @tags: documentation,offline
import json
from pathlib import Path
with Path("executed.log").open("a") as marker:
    marker.write("executed\n")
print(json.dumps([]))
"#,
    )
    .unwrap();

    let readme = include_str!("../README.md");
    let developer_loop = readme
        .split("### GuardLink developer loop")
        .nth(1)
        .unwrap()
        .split("### Scanning")
        .next()
        .unwrap();
    let script = developer_loop.split("```bash\n").nth(1).unwrap();
    let script = script.split("```").next().unwrap();
    // Keep commands and setup from the public guide, replacing only the binary.
    let script = script
        .lines()
        .map(|line| {
            line.strip_prefix("cxg ").map_or_else(
                || line.to_owned(),
                |args| format!("\"$CXG_DOCS_BINARY\" {args}"),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let run = |script: &str| {
        let output = Command::new("sh")
            .args(["-eu", "-c", script])
            .current_dir(&root)
            .env("CXG_DOCS_BINARY", env!("CARGO_BIN_EXE_cxg"))
            .env("CERT_X_GEN_HOME", &root)
            .env("HOME", &root)
            .env("CXG_NO_BANNER", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "documented commands failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };
    assert!(!root.join(".guardlink/pentest-findings").exists());
    run(&script);
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join(".guardlink/pentest-findings/change.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report["statistics"]["templates_executed"], 1);
    assert_eq!(report["executions"].as_array().unwrap().len(), 1);
    assert_eq!(report["findings"], serde_json::json!([]));
    assert_eq!(report["errors"], serde_json::json!([]));
    assert_eq!(
        fs::read_to_string(root.join("executed.log")).unwrap(),
        "executed\n"
    );

    let mcp = include_str!("../src/mcp/server.rs");
    let prefix = "`cxg scan --scope <target> --templates ";
    let selected = mcp.split(prefix).nth(1).unwrap().split('`').next().unwrap();
    run(&format!(
        "\"$CXG_DOCS_BINARY\" scan --scope http://127.0.0.1:8080 --templates {selected}"
    ));
    assert_eq!(
        fs::read_to_string(root.join("executed.log")).unwrap(),
        "executed\nexecuted\n"
    );
}
