mod common;

use std::path::{Path, PathBuf};

#[test]
fn a_backtrace_exported_into_the_suite_never_reaches_the_binary() {
    // SAFETY: the sibling test in this binary reads no environment variable.
    unsafe { std::env::set_var("RUST_BACKTRACE", "1") };

    let output = common::rastreo_server()
        .args(["--port", "0"])
        .output()
        .expect("spawn rastreo-server");

    assert!(
        !output.status.success(),
        "a server with no auth configuration must refuse to start"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("RASTREO_API_TOKEN is not set"),
        "expected the auth refusal: {stderr}"
    );
    assert!(
        !stderr.contains("backtrace"),
        "a backtrace is not part of the binary's output contract: {stderr}"
    );
}

#[test]
fn every_test_spawns_the_binary_through_the_shared_helper() {
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let helper = tests.join("common").join("mod.rs");
    let sources = rust_sources(&tests);
    assert!(sources.len() > 3, "expected to walk the integration tests");

    // Split so this guard does not match itself.
    let binary_path_macro = concat!("CARGO_BIN", "_EXE");
    let offenders: Vec<String> = sources
        .iter()
        .filter(|path| **path != helper)
        .filter(|path| {
            std::fs::read_to_string(path)
                .expect("read test source")
                .contains(binary_path_macro)
        })
        .map(|path| path.display().to_string())
        .collect();

    assert!(
        offenders.is_empty(),
        "spawn through common::rastreo_server(), which clears the environment; a hand-built \
         command inherits whatever the shell or the CI job exported: {offenders:?}"
    );
}

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).expect("read the tests directory");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    out
}
