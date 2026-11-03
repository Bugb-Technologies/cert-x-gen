//! Plain scan dispatches probe contracts without ever launching Node or a model.
#![cfg(unix)]
use std::process::Command;

fn run(scenario: &str) {
    static LIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LIVE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let home = tempfile::tempdir().unwrap();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/auto-probe-scan/run.py");
    let output = match Command::new("python3")
        .arg(script)
        .arg(env!("CARGO_BIN_EXE_cxg"))
        .arg(scenario)
        .arg(home.path())
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("start fixture: {error}"),
    };
    if output.status.code() == Some(77) {
        eprintln!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    assert!(
        output.status.success(),
        "scenario {scenario}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn plain_probe_confirms_using_browser_evidence() {
    run("confirmed");
}
#[test]
fn plain_probe_refutes_using_observed_identity_controls() {
    run("refuted");
}
#[test]
fn missing_identities_refuse_the_probe_without_target_requests() {
    run("missing");
}
#[test]
fn mixed_pack_keeps_distinct_verdict_sources() {
    run("mixed");
}
#[test]
fn refusing_one_probe_keeps_scanners_and_other_probes_running() {
    run("partial");
}
#[test]
fn a_direct_probe_path_uses_the_engine() {
    run("direct");
}
#[test]
fn same_ids_do_not_hide_a_scanner_or_probe() {
    run("duplicate_id");
}
#[test]
fn a_refused_probe_with_a_repeated_id_keeps_its_source_path() {
    run("partial_duplicate");
}
