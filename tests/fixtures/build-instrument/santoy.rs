//! `santoy` -- the **benign synthetic** cargo toy for the instrumented build.
//!
//! It exists to prove the *build path* end to end: `cargo +nightly build
//! --target <host triple>` with `RUSTFLAGS=-Zsanitizer=address`, the sanitizer
//! runtime that ships as an `@rpath` dylib, and the post-build verification
//! that reads the produced artefact back. Nothing here reproduces any real
//! defect in any real program; both flaws are planted, with their one-line
//! corrections beside them.
//!
//! Two planted defects, one per low-level family, both reachable from the
//! over-length payloads the shipped CLI Security Baseline B11 template already
//! sends:
//!
//! * `--tag <text>` -- memory (CWE-787): a one-byte heap overwrite. Without a
//!   redzone the allocator's bucket absorbs it, so the defective build prints
//!   the right answer and exits 0. **ASan sees it; nothing else does.**
//! * `--reserve <text>` -- integer (CWE-190): a signed 32-bit product of an
//!   attacker-controlled length. Rust has **no UBSan**, so the check that
//!   makes this observable is `-C overflow-checks=on`, which turns the wrap
//!   into a panic. Compile it out and the same program prints a plainly wrong
//!   number and exits 0.
//!
//! Which twin this is comes from `argv[0]`, the same one-source-many-twins
//! convention as `tests/fixtures/cli-baseline/memtoy.c`: twins that can drift
//! apart are worth nothing as a refutation test. Three names are recognised:
//!
//! * `*defective*` -- both defects present
//! * `*intonly*` -- only the integer defect; the memory one is repaired
//! * anything else -- both repaired

use std::alloc::{alloc, dealloc, Layout};

/// Bytes the tool claims to reserve per character. Large enough that a 65-char
/// argument overflows a signed 32-bit product.
const PER_CHAR: i32 = 33_554_432;

fn usage() {
    println!(
        "usage: santoy <command> [value]\n\
         \n\
         commands:\n\
         \x20 --tag <text>      copy <text> into a heap tag buffer\n\
         \x20 --reserve <text>  report the byte budget <text> would need\n\
         \x20 version           print the build identity"
    );
}

/// Memory family. ASan-visible; silent on an uninstrumented build.
fn cmd_tag(text: &str, is_defective: bool) -> i32 {
    let n = text.len();
    // The defective allocation forgets the byte the terminating NUL needs, so
    // the write below lands exactly one past the end of the block.
    let cap = if is_defective { n } else { n + 1 };
    if cap == 0 {
        println!("tag: 0 bytes");
        return 0;
    }
    let layout = Layout::from_size_align(cap, 1).expect("layout");
    unsafe {
        let p = alloc(layout);
        if p.is_null() {
            return 71;
        }
        std::ptr::copy_nonoverlapping(text.as_ptr(), p, n);
        *p.add(n) = 0; // one past the end on the defective twin
        println!("tag: {} bytes", n);
        dealloc(p, layout);
    }
    0
}

/// Integer family. Observable only where `-C overflow-checks=on` compiled the
/// check in.
fn cmd_reserve(text: &str, is_defective: bool) -> i32 {
    if is_defective {
        let n = text.len() as i32;
        let bytes = n * PER_CHAR;
        println!("reserve: {} chars -> {} bytes", n, bytes);
        0
    } else {
        let n = text.len();
        match (n as u64).checked_mul(PER_CHAR as u64) {
            Some(bytes) if bytes <= i32::MAX as u64 => {
                println!("reserve: {} chars -> {} bytes", n, bytes);
                0
            }
            _ => {
                eprintln!("santoy: refusing: {} chars exceeds the budget", n);
                4
            }
        }
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let base = std::path::Path::new(&argv[0])
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    let is_defective = base.contains("defective");
    let int_defective = is_defective || base.contains("intonly");

    if argv.len() < 2 {
        usage();
        std::process::exit(64);
    }
    match argv[1].as_str() {
        "version" => {
            println!(
                "santoy 0.1 ({})",
                if is_defective {
                    "defective"
                } else if int_defective {
                    "intonly"
                } else {
                    "fixed"
                }
            );
            std::process::exit(0);
        }
        "--help" | "-h" | "help" => {
            usage();
            std::process::exit(0);
        }
        _ => {}
    }
    if argv.len() < 3 {
        usage();
        std::process::exit(64);
    }
    let rc = match argv[1].as_str() {
        "--tag" => cmd_tag(&argv[2], is_defective),
        "--reserve" => cmd_reserve(&argv[2], int_defective),
        _ => {
            usage();
            64
        }
    };
    std::process::exit(rc);
}
