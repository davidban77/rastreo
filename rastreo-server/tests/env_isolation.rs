mod common;

use rastreo_core::{Env, SystemEnv};
use std::path::{Path, PathBuf};

const RERUN_MARKER: &str = "RASTREO_ENV_ISOLATION_RERUN";
const POLLUTED_TEST: &str = "a_backtrace_exported_into_the_suite_never_reaches_the_binary";

#[test]
fn a_backtrace_exported_into_the_suite_never_reaches_the_binary() {
    if SystemEnv.var(RERUN_MARKER).is_err() {
        return rerun_with_a_backtrace_exported();
    }
    assert_eq!(
        SystemEnv.var("RUST_BACKTRACE").ok().as_deref(),
        Some("1"),
        "the re-run must export the pollutant this test exists to catch"
    );

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

// The variable has to be in *this* process's environment for the assertion to mean anything, and
// setting it here would realloc the environ array under every other thread's read of it. A child
// owns its own environment from the moment it starts.
fn rerun_with_a_backtrace_exported() {
    let output = std::process::Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", POLLUTED_TEST])
        .env("RUST_BACKTRACE", "1")
        .env(RERUN_MARKER, "1")
        .output()
        .expect("re-run this test binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the re-run failed: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "expected {POLLUTED_TEST} to run once in the re-run: {stdout}\n{stderr}"
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
