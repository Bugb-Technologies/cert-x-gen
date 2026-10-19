// Generate the manifest from exactly the bytes the runtime materializer filters.
// Cargo packages this generator and pentest/, so registry builds embed the same
// inventory without needing a checkout, Python, or a network manifest service.
#[path = "src/pentest_bundle.rs"]
mod pentest_bundle;
use std::{collections::BTreeMap, fs, path::Path};

fn collect(root: &Path, dir: &Path, files: &mut BTreeMap<String, String>) {
    for entry in fs::read_dir(dir).expect("read pentest bundle") {
        let entry = entry.expect("read bundle entry");
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap();
        if pentest_bundle::excluded(rel) {
            continue;
        }
        assert!(pentest_bundle::relative(rel), "invalid bundle path");
        let kind = entry.file_type().unwrap();
        assert!(!kind.is_symlink(), "bundle must not contain symlinks");
        if kind.is_dir() {
            collect(root, &path, files);
        } else if kind.is_file() {
            files.insert(
                rel.to_string_lossy().replace('\\', "/"),
                pentest_bundle::hash(&fs::read(path).unwrap()),
            );
        }
    }
}
fn main() {
    println!("cargo:rerun-if-changed=pentest");
    println!("cargo:rerun-if-changed=src/pentest_bundle.rs");
    let mut files = BTreeMap::new();
    collect(Path::new("pentest"), Path::new("pentest"), &mut files);
    assert!(files.contains_key("cxg_pentest.py") && files.contains_key("requirements.txt"));
    let inventory = serde_json::json!({
        "schema": 1,
        "digest": pentest_bundle::inventory_digest(&files),
        "files": files,
    });
    println!("cargo:rerun-if-changed=pentest-manifest.json");
    println!("cargo:rerun-if-env-changed=CXG_REGENERATE_PENTEST_MANIFEST");
    if std::env::var_os("CXG_REGENERATE_PENTEST_MANIFEST").is_some() {
        fs::write(
            "pentest-manifest.json",
            serde_json::to_vec_pretty(&inventory).unwrap(),
        )
        .expect("regenerate pentest-manifest.json");
    }
    let recorded: serde_json::Value = serde_json::from_slice(
        &fs::read("pentest-manifest.json").expect("packaged pentest-manifest.json must exist"),
    )
    .expect("valid pentest bundle inventory");
    assert_eq!(
        recorded, inventory,
        "pentest bundle changed: regenerate with CXG_REGENERATE_PENTEST_MANIFEST=1 cargo check"
    );
    let mut manifest = recorded;
    manifest["version"] = std::env::var("CARGO_PKG_VERSION").unwrap().into();
    manifest["origin"] = serde_json::json!({"kind": "embedded"});
    fs::write(
        Path::new(&std::env::var_os("OUT_DIR").unwrap()).join("pentest-manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .expect("write bundled pipeline manifest");
}
