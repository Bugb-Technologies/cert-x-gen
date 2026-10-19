//! `cxg update`: replace the installed binary with a GitHub release asset.
//!
//! Release assets are plain per-platform binaries named `cxg-<os>-<arch>`
//! beside one `SHA256SUMS` file (see `.github/workflows/release.yml`). The
//! release lookup goes through `self_update`; the download, the checksum and
//! the replacement are done here, for two reasons:
//!
//! - **The replacement must follow the symlink to an absolute path.**
//!   `self_replace` (1.5.0) reads a symlinked executable with `read_link` and
//!   then uses the result as-is, so a RELATIVE link target such as Homebrew's
//!   `bin/cxg -> ../Cellar/cxg/<version>/bin/cxg` is resolved against the
//!   process's working directory instead of the link's directory, and the
//!   update fails with "No such file or directory" from everywhere except the
//!   link's own directory. macOS reports the invoked (symlink) path as the
//!   current executable, so this is the path a Homebrew user hits.
//! - **The download is checked against `SHA256SUMS` before anything is
//!   replaced**, which `self_update` does not do for plain assets.
//!
//! A binary that a package manager owns is not replaced at all unless the
//! caller forces it: overwriting a Homebrew Cellar file or a `cargo install`ed
//! binary leaves the manager believing the old version is installed, and a
//! replacement inside a container is lost with the container.

use sha2::{Digest, Sha256};
use std::io;
use std::path::{Component, Path, PathBuf};

/// Name of the checksum asset every release carries.
pub const CHECKSUMS_ASSET: &str = "SHA256SUMS";

/// Who owns the installed `cxg` binary, and so who should replace it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallKind {
    /// Installed by hand, by `install.sh` or by a previous `cxg update`.
    Direct,
    /// Inside a Homebrew Cellar.
    Homebrew,
    /// In cargo's binary directory, put there by `cargo install`.
    Cargo,
    /// Running inside a container, whose image is what should be updated.
    Container,
}

impl InstallKind {
    /// What manages this install, for a sentence such as "managed by Homebrew".
    pub fn manager(self) -> Option<&'static str> {
        match self {
            InstallKind::Direct => None,
            InstallKind::Homebrew => Some("Homebrew"),
            InstallKind::Cargo => Some("cargo install"),
            InstallKind::Container => Some("a container image"),
        }
    }

    /// The command that upgrades this install through its own manager.
    pub fn upgrade_command(self) -> Option<&'static str> {
        match self {
            InstallKind::Direct => None,
            InstallKind::Homebrew => Some("brew upgrade cxg"),
            InstallKind::Cargo => Some("cargo install cert-x-gen --force"),
            InstallKind::Container => {
                Some("docker pull ghcr.io/bugb-technologies/cert-x-gen:latest")
            }
        }
    }
}

/// Resolve the path the binary was invoked by to the file that actually holds
/// it: every symlink followed, each relative target taken relative to its own
/// link, so the answer does not depend on the working directory.
pub fn installed_executable(invoked: &Path) -> io::Result<PathBuf> {
    invoked.canonicalize()
}

/// Classify an install from the resolved executable path.
///
/// `cargo_bin` is cargo's binary directory (`$CARGO_HOME/bin`), already
/// resolved; `in_container` is whether a container runtime marker exists.
pub fn classify_install(exe: &Path, cargo_bin: Option<&Path>, in_container: bool) -> InstallKind {
    // Homebrew installs every formula as <prefix>/Cellar/<formula>/<version>/,
    // on macOS and Linux alike, and links it into <prefix>/bin.
    if exe
        .components()
        .any(|c| c == Component::Normal("Cellar".as_ref()))
    {
        return InstallKind::Homebrew;
    }
    if let (Some(dir), Some(bin)) = (exe.parent(), cargo_bin) {
        if dir == bin {
            return InstallKind::Cargo;
        }
    }
    if in_container {
        return InstallKind::Container;
    }
    InstallKind::Direct
}

/// Classify the install at `exe` (already resolved) against this machine.
pub fn detect_install(exe: &Path) -> InstallKind {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".cargo")));
    let cargo_bin = cargo_home.and_then(|h| h.join("bin").canonicalize().ok());
    let in_container =
        Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists();
    classify_install(exe, cargo_bin.as_deref(), in_container)
}

/// The SHA-256 that a `sha256sum`-format listing records for `asset`, in
/// lowercase hex. Accepts both the text (`<hash>  name`) and binary
/// (`<hash> *name`) forms.
pub fn expected_sha256(sums: &str, asset: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (hash, name) = line.trim().split_once(char::is_whitespace)?;
        let name = name.trim_start();
        let name = name.strip_prefix('*').unwrap_or(name);
        (name == asset).then(|| hash.to_ascii_lowercase())
    })
}

/// Check `bytes` against the listing's entry for `asset`. The error says why,
/// in a sentence fit to show the user.
pub fn verify_sha256(bytes: &[u8], sums: &str, asset: &str) -> Result<(), String> {
    let expected = expected_sha256(sums, asset)
        .ok_or_else(|| format!("{CHECKSUMS_ASSET} has no entry for {asset}"))?;
    let actual = hex::encode(Sha256::digest(bytes));
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "checksum mismatch for {asset}: {CHECKSUMS_ASSET} lists {expected}, download is {actual}"
        ))
    }
}

/// Replace the binary at `installed` (a resolved path, see
/// [`installed_executable`]) with the file at `new_exe`, keeping the old
/// file's permissions.
///
/// The new file is written beside the old one and renamed over it, so the
/// swap is atomic and a symlink pointing at `installed` keeps pointing at it.
#[cfg(unix)]
pub fn replace_executable(installed: &Path, new_exe: &Path) -> io::Result<()> {
    use std::fs;

    let permissions = fs::metadata(installed)?.permissions();
    let dir = installed
        .parent()
        .ok_or_else(|| io::Error::other("executable has no known parent folder"))?;
    let tmp = tempfile::Builder::new()
        .prefix(".cxg.__update__")
        .tempfile_in(dir)?;
    fs::copy(new_exe, tmp.path())?;
    fs::set_permissions(tmp.path(), permissions)?;
    tmp.persist(installed).map_err(|e| e.error)?;
    Ok(())
}

/// Replace the running binary with the file at `new_exe`.
///
/// Windows cannot overwrite a running executable, so this defers to
/// `self_replace`, which renames it aside first. `installed` is unused: that
/// crate locates the running executable itself.
#[cfg(windows)]
pub fn replace_executable(_installed: &Path, new_exe: &Path) -> io::Result<()> {
    self_update::self_replace::self_replace(new_exe)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::fs;

    #[test]
    fn a_cellar_path_is_homebrew_on_either_prefix() {
        for exe in [
            "/opt/homebrew/Cellar/cxg/1.5.0/bin/cxg",
            "/usr/local/Cellar/cxg/1.5.0/bin/cxg",
            "/home/linuxbrew/.linuxbrew/Cellar/cxg/1.5.0/bin/cxg",
        ] {
            assert_eq!(
                classify_install(Path::new(exe), None, false),
                InstallKind::Homebrew,
                "{exe}"
            );
        }
    }

    #[test]
    fn a_name_merely_containing_cellar_is_not_homebrew() {
        assert_eq!(
            classify_install(Path::new("/opt/WineCellar/bin/cxg"), None, false),
            InstallKind::Direct
        );
    }

    #[test]
    fn cargo_bin_is_cargo_and_its_subdirectories_are_not() {
        let bin = Path::new("/home/u/.cargo/bin");
        assert_eq!(
            classify_install(Path::new("/home/u/.cargo/bin/cxg"), Some(bin), false),
            InstallKind::Cargo
        );
        assert_eq!(
            classify_install(Path::new("/home/u/.cargo/bin/x/cxg"), Some(bin), false),
            InstallKind::Direct
        );
    }

    #[test]
    fn a_container_is_detected_only_where_no_manager_claims_the_file() {
        assert_eq!(
            classify_install(Path::new("/usr/local/bin/cxg"), None, true),
            InstallKind::Container
        );
        assert_eq!(
            classify_install(Path::new("/usr/local/bin/cxg"), None, false),
            InstallKind::Direct
        );
        assert_eq!(
            classify_install(Path::new("/opt/homebrew/Cellar/cxg/1/bin/cxg"), None, true),
            InstallKind::Homebrew
        );
    }

    #[test]
    fn every_managed_kind_names_its_own_upgrade_command() {
        assert_eq!(InstallKind::Direct.upgrade_command(), None);
        assert_eq!(
            InstallKind::Homebrew.upgrade_command(),
            Some("brew upgrade cxg")
        );
        assert_eq!(
            InstallKind::Cargo.upgrade_command(),
            Some("cargo install cert-x-gen --force")
        );
        assert!(InstallKind::Container
            .upgrade_command()
            .is_some_and(|c| c.starts_with("docker pull ")));
    }

    // The listing format the release workflow publishes (`sha256sum *`).
    const SUMS: &str = "\
3bdfbe694bae2d57becd42bf5be27dcd09bcc7b7293f7eac4e7db17a847d4b4f  cxg-darwin-amd64
A0FE5AF83CFD505E98DADA5242EFBFDBE45C9820286CBCD97BA28897DF1F6C73 *cxg-darwin-arm64
";

    #[test]
    fn checksums_are_read_in_text_and_binary_form() {
        assert_eq!(
            expected_sha256(SUMS, "cxg-darwin-amd64").as_deref(),
            Some("3bdfbe694bae2d57becd42bf5be27dcd09bcc7b7293f7eac4e7db17a847d4b4f")
        );
        assert_eq!(
            expected_sha256(SUMS, "cxg-darwin-arm64").as_deref(),
            Some("a0fe5af83cfd505e98dada5242efbfdbe45c9820286cbcd97ba28897df1f6c73")
        );
        assert_eq!(expected_sha256(SUMS, "cxg-darwin"), None);
        assert_eq!(expected_sha256(SUMS, "cxg-linux-amd64"), None);
    }

    #[test]
    fn verification_accepts_a_match_and_refuses_a_mismatch_or_a_missing_entry() {
        let bytes = b"cxg";
        let sums = format!("{}  cxg-linux-amd64\n", hex::encode(Sha256::digest(bytes)));
        assert_eq!(verify_sha256(bytes, &sums, "cxg-linux-amd64"), Ok(()));

        let err = verify_sha256(b"tampered", &sums, "cxg-linux-amd64").unwrap_err();
        assert!(err.contains("checksum mismatch"), "{err}");

        let err = verify_sha256(bytes, &sums, "cxg-linux-arm64").unwrap_err();
        assert!(err.contains("no entry for cxg-linux-arm64"), "{err}");
    }

    /// The Homebrew layout: `bin/cxg -> ../Cellar/cxg/1.5.0/bin/cxg`.
    #[cfg(unix)]
    fn homebrew_layout(root: &Path) -> (PathBuf, PathBuf) {
        let cellar_bin = root.join("Cellar/cxg/1.5.0/bin");
        fs::create_dir_all(&cellar_bin).unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        let real = cellar_bin.join("cxg");
        fs::write(&real, b"old").unwrap();
        let link = root.join("bin/cxg");
        std::os::unix::fs::symlink("../Cellar/cxg/1.5.0/bin/cxg", &link).unwrap();
        (link, real)
    }

    // The regression: the relative link target must resolve against the
    // link's directory. The test process's working directory is the crate
    // root, from which `../Cellar/...` does not exist — the same condition
    // that made the update fail for everyone not standing in `bin/`.
    #[cfg(unix)]
    #[test]
    fn a_relative_symlink_resolves_against_its_own_directory_not_the_cwd() {
        let root = tempfile::tempdir().unwrap();
        let (link, real) = homebrew_layout(root.path());
        assert!(!Path::new("../Cellar/cxg/1.5.0/bin/cxg").exists());

        let installed = installed_executable(&link).unwrap();
        assert!(installed.is_absolute());
        assert_eq!(installed, real.canonicalize().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn replacing_through_a_relative_symlink_rewrites_the_target_and_keeps_the_link() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let (link, real) = homebrew_layout(root.path());
        fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
        // A freshly downloaded file is not executable; the old file's mode wins.
        let new = root.path().join("download");
        fs::write(&new, b"new").unwrap();
        fs::set_permissions(&new, fs::Permissions::from_mode(0o600)).unwrap();

        replace_executable(&installed_executable(&link).unwrap(), &new).unwrap();

        assert_eq!(fs::read(&real).unwrap(), b"new");
        assert_eq!(fs::read(&link).unwrap(), b"new");
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::metadata(&real).unwrap().permissions().mode() & 0o777,
            0o755
        );
        // Nothing left behind beside the binary.
        let leftovers: Vec<_> = fs::read_dir(real.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("cxg")]);
    }
}
