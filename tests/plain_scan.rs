//! Plain scan discovery, accounting and CI exit behavior through the real CLI.
#![cfg(unix)]

use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

fn cli(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cxg"));
    cmd.current_dir(dir)
        .env("HOME", dir)
        .env("CERT_X_GEN_HOME", dir)
        .env("CXG_NO_BANNER", "1")
        .args(["--disable-update-check", "--no-color"]);
    cmd
}

fn scan(dir: &Path, extra: &[&str]) -> (Output, Value) {
    scan_at(dir, "http://127.0.0.1:1", extra)
}

fn scan_at(dir: &Path, target: &str, extra: &[&str]) -> (Output, Value) {
    let result_path = dir.join("result.json");
    if result_path.exists() {
        std::fs::remove_file(&result_path).unwrap();
    }
    let mut cmd = cli(dir);
    cmd.args(["scan", "--scope", target, "--template-dir", "pack"])
        .args(["--output", "result", "--output-format", "json"]);
    if !extra.contains(&"--retry") {
        cmd.args(["--retry", "0"]);
    }
    let output = cmd.args(extra).output().unwrap();
    let raw = std::fs::read_to_string(dir.join("result.json")).unwrap_or_else(|e| {
        panic!(
            "no report: {e}\n{:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, serde_json::from_str(&raw).unwrap())
}

fn pack(dir: &Path) {
    std::fs::create_dir(dir.join("pack")).unwrap();
}

fn python(dir: &Path, name: &str, body: &str) {
    std::fs::write(dir.join("pack").join(name), format!(
        "# @id: {name}\n# @name: Scan fixture\n# @author: Test\n# @severity: info\n# @description: Tests scan reporting\n{body}\n"
    )).unwrap();
}

fn yaml(author: &str) -> String {
    format!("id: check\nname: Check\nauthor: {author}\nseverity: info\ndescription: Scan fixture\nlanguage: yaml\nhttp:\n  - method: GET\n    path: [/, /second]\n")
}

#[test]
fn directory_reports_helpers_and_load_failures_without_executing_helpers() {
    let dir = tempfile::tempdir().unwrap();
    pack(dir.path());
    python(dir.path(), "check.py", "print('[]')");
    std::fs::write(
        dir.path().join("pack/helper.py"),
        "raise RuntimeError('helper executed')",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("pack/test_helper.py"),
        "raise RuntimeError('test executed')",
    )
    .unwrap();
    std::fs::write(dir.path().join("pack/bad.yaml"), yaml("Test")).unwrap();
    let (out, doc) = scan(dir.path(), &[]);
    assert!(out.status.success());
    assert_eq!(doc["statistics"]["templates_executed"], 1);
    let errors = doc["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1, "{doc:#}");
    assert!(errors[0].as_str().unwrap().contains("bad.yaml"));
    let rows = doc["executions"].as_array().unwrap();
    assert_eq!(rows.iter().filter(|r| r["status"] == "errored").count(), 1);
    assert_eq!(
        rows.iter()
            .filter(|r| r["detail"] == "skipped-non-template")
            .count(),
        2
    );
}

#[test]
fn directory_with_only_invalid_templates_still_writes_a_report() {
    let dir = tempfile::tempdir().unwrap();
    pack(dir.path());
    std::fs::write(dir.path().join("pack/bad.yaml"), yaml("Test")).unwrap();
    let (default, doc) = scan(dir.path(), &[]);
    assert_eq!(default.status.code(), Some(1));
    assert_eq!(doc["errors"].as_array().unwrap().len(), 1);
    let (out, doc) = scan(dir.path(), &["--fail-on", "errored"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(doc["errors"].as_array().unwrap().len(), 1);
    assert_eq!(doc["executions"][0]["status"], "errored");
}

#[test]
fn python_imports_do_not_write_bytecode_and_unknown_requests_are_null() {
    let dir = tempfile::tempdir().unwrap();
    pack(dir.path());
    std::fs::write(dir.path().join("pack/helper.py"), "VALUE = 42").unwrap();
    python(
        dir.path(),
        "check.py",
        "import helper\nassert helper.VALUE == 42\nprint('[]')",
    );
    let (_, doc) = scan(dir.path(), &[]);
    assert!(!dir.path().join("pack/__pycache__").exists());
    assert!(doc["statistics"]["network_requests"].is_null());
}

#[test]
fn fail_on_is_opt_in_and_reports_declared_and_inferred_verdicts() {
    let dir = tempfile::tempdir().unwrap();
    pack(dir.path());
    python(
        dir.path(),
        "finding.py",
        r#"print('{"findings":[{"title":"Fixture finding","severity":"info","description":"Fixture"}]}')"#,
    );
    python(
        dir.path(),
        "declared.sh",
        r#"printf '%s\n' '{"findings":[],"metadata":{"status":"refuted"}}'"#,
    );
    let (default, _) = scan(dir.path(), &[]);
    assert!(default.status.success());
    let (failed, doc) = scan(dir.path(), &["--fail-on", "confirmed"]);
    assert_eq!(failed.status.code(), Some(2));
    assert_eq!(doc["findings"].as_array().unwrap().len(), 1);
    let summary = String::from_utf8_lossy(&failed.stdout);
    assert!(summary.contains("1 declared, 0 inferred"), "{summary}");
    assert!(summary.contains("0 declared, 1 inferred"), "{summary}");
    let (other, _) = scan(dir.path(), &["--fail-on", "errored,timed-out"]);
    assert!(other.status.success());
}

#[test]
fn validation_rejects_the_same_yaml_schema_as_loading() {
    let dir = tempfile::tempdir().unwrap();
    pack(dir.path());
    std::fs::write(dir.path().join("pack/bad.yaml"), yaml("Test")).unwrap();
    let out = cli(dir.path())
        .args(["template", "validate", "pack/bad.yaml", "--json"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("yaml.loader_schema"));
}

#[tokio::test(flavor = "multi_thread")]
async fn native_http_counts_requests_including_redirects_and_retries() {
    let mut server = mockito::Server::new_async().await;
    let first = server
        .mock("GET", "/")
        .with_status(302)
        .with_header("Location", "/redirected")
        .expect(1)
        .create_async()
        .await;
    let redirected = server
        .mock("GET", "/redirected")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;
    let second = server
        .mock("GET", "/second")
        .with_status(503)
        .expect(2)
        .create_async()
        .await;
    let dir = tempfile::tempdir().unwrap();
    pack(dir.path());
    std::fs::write(dir.path().join("pack/check.yaml"), yaml("{name: Test}")).unwrap();
    let (out, doc) = scan_at(
        dir.path(),
        &server.url(),
        &["--retry", "1", "--follow-redirects"],
    );
    assert!(out.status.success());
    first.assert_async().await;
    redirected.assert_async().await;
    second.assert_async().await;
    assert_eq!(doc["statistics"]["network_requests"], 4, "{doc:#}");
}

#[test]
fn helper_only_directory_is_reported_without_launching_any_interpreter() {
    let dir = tempfile::tempdir().unwrap();
    pack(dir.path());
    std::fs::create_dir(dir.path().join("pack/nested")).unwrap();
    for extension in ["py", "js", "rb", "sh", "go"] {
        std::fs::write(
            dir.path().join(format!("pack/nested/helper.{extension}")),
            "tags = ['helper']",
        )
        .unwrap();
    }
    std::fs::write(dir.path().join("pack/config.yaml"), "timeout: 10").unwrap();
    let (out, doc) = scan(dir.path(), &["--fail-on", "skipped"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(doc["statistics"]["templates_executed"], 0);
    assert_eq!(doc["statistics"]["network_requests"], 0);
    assert!(doc["errors"].as_array().unwrap().is_empty());
    let rows = doc["executions"].as_array().unwrap();
    assert_eq!(rows.len(), 6);
    assert!(rows
        .iter()
        .all(|row| row["detail"] == "skipped-non-template"));
}

#[test]
fn helpers_do_not_hide_an_unmatched_template_selector() {
    let dir = tempfile::tempdir().unwrap();
    pack(dir.path());
    std::fs::write(dir.path().join("pack/helper.py"), "VALUE = 42").unwrap();
    let (out, doc) = scan(dir.path(), &["--templates", "missing-template"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("No templates found matching"));
    assert_eq!(doc["executions"][0]["detail"], "skipped-non-template");
}

#[test]
fn fail_on_matches_every_declared_status_and_can_be_repeated() {
    for status in ["confirmed", "refuted", "errored", "skipped", "timed-out"] {
        let dir = tempfile::tempdir().unwrap();
        pack(dir.path());
        python(
            dir.path(),
            "declared.sh",
            &format!(r#"printf '%s\n' '{{"findings":[],"metadata":{{"status":"{status}"}}}}'"#),
        );
        let (out, doc) = scan(dir.path(), &["--fail-on", "confirmed", "--fail-on", status]);
        assert_eq!(out.status.code(), Some(2), "{status}: {doc}");
        assert_eq!(doc["executions"][0]["status"], status);
        assert_eq!(doc["executions"][0]["declared_by_template"], true);
    }
}

#[test]
fn shell_launched_python_helpers_do_not_write_bytecode() {
    let dir = tempfile::tempdir().unwrap();
    pack(dir.path());
    std::fs::write(dir.path().join("pack/helper.py"), "VALUE = 42").unwrap();
    python(
        dir.path(),
        "check.sh",
        "cd pack\npython3 -c 'import helper; assert helper.VALUE == 42'\nprintf '[]'",
    );
    let (_, doc) = scan(dir.path(), &[]);
    assert!(!dir.path().join("pack/__pycache__").exists());
    assert_eq!(doc["executions"][0]["status"], "refuted");
}

#[tokio::test(flavor = "multi_thread")]
async fn mixed_engines_preserve_measured_requests_while_total_is_unknown() {
    let mut server = mockito::Server::new_async().await;
    let requests = server
        .mock("GET", mockito::Matcher::Any)
        .with_status(200)
        .expect(2)
        .create_async()
        .await;
    let dir = tempfile::tempdir().unwrap();
    pack(dir.path());
    std::fs::write(dir.path().join("pack/check.yaml"), yaml("{name: Test}")).unwrap();
    python(dir.path(), "check.py", "print('[]')");
    let (_, doc) = scan_at(dir.path(), &server.url(), &[]);
    requests.assert_async().await;
    assert!(doc["statistics"]["network_requests"].is_null());
    assert_eq!(doc["statistics"]["network_requests_measured"], 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn native_flows_count_each_http_step() {
    let mut server = mockito::Server::new_async().await;
    let requests = server
        .mock("POST", "/flow")
        .with_status(200)
        .expect(1)
        .create_async()
        .await;
    let dir = tempfile::tempdir().unwrap();
    pack(dir.path());
    let content = format!("{}flows:\n  - name: check\n    steps:\n      - action: http_request\n        method: POST\n        path: /flow\n", yaml("{name: Test}").split("http:").next().unwrap());
    std::fs::write(dir.path().join("pack/check.yaml"), content).unwrap();
    let (_, doc) = scan_at(dir.path(), &server.url(), &[]);
    requests.assert_async().await;
    assert_eq!(doc["statistics"]["network_requests"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn native_tcp_counts_payloads_sent_on_one_connection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let (mut stream, _) = listener.accept().await.unwrap();
            for _ in 0..2 {
                let mut payload = [0; 4];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
                stream.write_all(b"pong").await.unwrap();
            }
        })
        .await
        .unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    pack(dir.path());
    let content = format!(
        "{}network:\n  - port: {}\n    payloads: [ping, ping]\n",
        yaml("{name: Test}").split("http:").next().unwrap(),
        address.port()
    );
    std::fs::write(dir.path().join("pack/check.yaml"), content).unwrap();
    let (_, doc) = scan_at(dir.path(), &format!("tcp://{address}"), &[]);
    server.await.unwrap();
    assert_eq!(doc["statistics"]["network_requests"], 2);
}
