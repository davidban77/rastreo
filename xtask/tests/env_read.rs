mod common;

use std::fs;
use std::path::PathBuf;

/// The spellings a process-environment read is written in: the prefix `std`'s four read functions
/// share, the import forms that bring one into scope renamed or globbed, the C call in both its
/// forms, and the `EnvFilter` constructors that go to `RUST_LOG` themselves. `EnvFilter::from_env(v)`
/// naming its variable by an expression is outside the set rather than missed by it — it is spelled
/// exactly like the seam's own `from_env(env)`. Split so this guard does not match itself.
const ENV_READS: [&str; 9] = [
    concat!("env::", "var"),
    concat!("std::env::", "{"),
    concat!("env::", "*"),
    concat!("env", " as "),
    concat!("get", "env"),
    concat!("from_default", "_env"),
    concat!("from_env", "_lossy"),
    concat!("from_env", "()"),
    concat!("from_env", "(\""),
];

const FILES_THAT_MAY_READ_THE_ENVIRONMENT: [&str; 5] = [
    "rastreo-core/src/env.rs",
    "rastreo/src/main.rs",
    "rastreo/src/cli/output/theme.rs",
    "rastreo-server/src/main.rs",
    "xtask/tests/schema_render_idempotent.rs",
];

fn names_an_env_read(body: &str) -> bool {
    let names = |text: &str| ENV_READS.iter().any(|call| text.contains(call));
    names(body) || names(&flatten_path_groups(body))
}

/// `body` with every brace group written out under its own prefix — `use a::{b::{self, c}, d};`
/// yields `a::b::c` — so a nested import reaches the same needle a flat one does.
fn flatten_path_groups(body: &str) -> String {
    fn flush(prefixes: &[String], segment: &mut String, out: &mut String) {
        out.push_str(prefixes.last().map_or("", String::as_str));
        out.push_str(segment);
        out.push('\n');
        segment.clear();
    }

    let mut out = String::with_capacity(body.len() * 2);
    let mut prefixes: Vec<String> = Vec::new();
    let mut segment = String::new();
    for c in body.chars().filter(|c| !c.is_whitespace()) {
        match c {
            '{' => {
                let mut nested = prefixes.last().cloned().unwrap_or_default();
                nested.push_str(&segment);
                prefixes.push(nested);
                segment.clear();
            }
            '}' => {
                flush(&prefixes, &mut segment, &mut out);
                prefixes.pop();
            }
            ',' | ';' => flush(&prefixes, &mut segment, &mut out),
            _ => segment.push(c),
        }
    }
    flush(&prefixes, &mut segment, &mut out);
    out
}

#[test]
fn no_source_file_reads_the_process_environment_outside_the_seam() {
    let (root, files) = common::workspace_sources();

    let owners: Vec<PathBuf> = FILES_THAT_MAY_READ_THE_ENVIRONMENT
        .iter()
        .map(|rel| root.join(rel))
        .collect();
    for owner in &owners {
        assert!(
            owner.is_file(),
            "{} is exempt from this guard but no longer exists; point the exemption at the file \
             that reads, or drop it",
            owner.display()
        );
        assert!(
            names_an_env_read(&fs::read_to_string(owner).expect("read exempt source")),
            "{} is exempt from this guard but no longer reads the environment; drop it, so the \
             list keeps naming every direct read and only those",
            owner.display()
        );
    }

    let offenders: Vec<String> = files
        .iter()
        .filter(|path| !owners.contains(path))
        .filter(|path| names_an_env_read(&fs::read_to_string(path).expect("read source")))
        .map(|path| {
            path.strip_prefix(&root)
                .unwrap_or(path)
                .display()
                .to_string()
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "a value the caller goes on to use must arrive through `rastreo_core::env::Env` — \
         `SystemEnv` named at the call site in a binary, a `MapEnv` the test owns in a test. \
         Expansion is then the only route environment content has into a scenario, which is what \
         lets `parse_discover_scenario_json` hold no `Env` and thereby read none of the server's \
         environment back to a client. Joining the exemption list costs one of three proofs, which \
         is why it is this short: the file is the seam, and reading the process is what the seam \
         is for; or the value reaches no caller, because the decision it feeds is already a pure \
         function a test calls with arguments; or the read is the harness locating its own \
         toolchain rather than code under test. A read that hands its value on to code under test \
         proves none of the three, however small the value. This walks raw file text and a copy \
         with its path groups flattened, so a comment or a string naming one of these calls trips \
         it too — split the name the way this file does. Found: {offenders:?}"
    );
}

#[test]
fn every_form_of_an_environment_read_is_matched() {
    for call in [
        concat!("let level = std::env::", "var(\"RUST_LOG\").ok();"),
        concat!("if std::env::", "var_os(MARKER).is_none() {"),
        concat!("for (k, v) in std::env::", "vars() {"),
        concat!("let first = std::env::", "vars_os().next();"),
        concat!("use std::env::", "var;"),
        concat!("use std::env::", "var as read;"),
        concat!("use std::env::", "{self, var};"),
        concat!("use std::env::", "*;"),
        concat!("use std::env", " as e; e::var(k)"),
        concat!("use std::{env", " as e};"),
        concat!("use std::env; env::", "var(\"HOME\")"),
        concat!("use std::{env", "::{var}};"),
        concat!("use std::{env", "::{var, var_os}, fs};"),
        concat!("use std::{fs, env", "::{vars_os}};"),
        concat!("use std::{env", "::{self, var}};"),
        concat!("use std::{\n    env", "::{var, var_os},\n    fs,\n};"),
        concat!("unsafe { libc::get", "env(key) }"),
        concat!("unsafe { libc::secure_get", "env(key) }"),
        concat!("EnvFilter::from_default", "_env()"),
        concat!("EnvFilter::try_from_default", "_env()"),
        concat!("EnvFilter::builder().from", "_env()"),
        concat!("EnvFilter::builder().try_from", "_env()?"),
        concat!(
            "EnvFilter::builder().with_default_directive(d).from_env",
            "_lossy()"
        ),
        concat!("EnvFilter::from", "_env(\"MY_LOG\")"),
        concat!("EnvFilter::try_from", "_env(\"MY_LOG\")"),
    ] {
        assert!(names_an_env_read(call), "{call}");
    }
}

#[test]
fn a_read_through_the_seam_is_not_matched() {
    for call in [
        "env.var(\"RASTREO_SNMP_COMMUNITY\")",
        "fn from_env(env: &dyn Env) -> Result<Self, VarError>",
        "use crate::env::{Env, VarError};",
        "use rastreo_core::env::{Env, MapEnv, SystemEnv};",
        "pub use std::env::VarError;",
        "MapEnv::new().set(\"KEY\", \"value\")",
        "ReadinessConfig::from_env(env)?",
        "OtlpConfig::from_env(env.as_ref())?",
    ] {
        assert!(!names_an_env_read(call), "{call}");
    }
}

#[test]
fn a_call_that_does_not_read_the_environment_is_not_matched() {
    for call in [
        "std::env::args().collect()",
        "std::env::current_exe().expect(\"this test binary\")",
        "std::env::current_dir()",
        "env!(\"CARGO_MANIFEST_DIR\")",
        "option_env!(\"CARGO_PKG_VERSION\")",
        "let environment = Environment::new();",
        "EnvFilter::new(directive)",
        "EnvFilter::builder().parse(directive)",
    ] {
        assert!(!names_an_env_read(call), "{call}");
    }
}
