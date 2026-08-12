//! Regression test: the shipped `cert-x-gen.example.yaml` must load through
//! `Config::from_file` and validate. This guards against the example drifting
//! back into an unloadable state (e.g. documenting keys the parser rejects).

use std::path::PathBuf;

use cert_x_gen::config::Config;

#[test]
fn example_config_loads_and_validates() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cert-x-gen.example.yaml");

    let config = Config::from_file(&path)
        .unwrap_or_else(|e| panic!("cert-x-gen.example.yaml failed to load: {e}"));

    config
        .validate()
        .unwrap_or_else(|e| panic!("cert-x-gen.example.yaml failed to validate: {e}"));
}
