mod common;

use std::fs;

/// Every call that writes the process environment, in the Rust and the C spelling. Split so this
/// guard does not match itself.
const ENV_MUTATIONS: [&str; 5] = [
    concat!("set", "_var"),
    concat!("remove", "_var"),
    concat!("set", "env"),
    concat!("unset", "env"),
    concat!("put", "env"),
];

fn names_an_env_mutation(body: &str) -> bool {
    ENV_MUTATIONS.iter().any(|call| {
        body.match_indices(call).any(|(at, _)| {
            let leading_is_separate = body[..at]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_alphanumeric() && c != '_');
            let trailing_is_separate =
                !body[at + call.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_');
            leading_is_separate && trailing_is_separate
        })
    })
}

#[test]
fn no_source_file_writes_the_process_environment() {
    let (root, files) = common::workspace_sources();

    let offenders: Vec<String> = files
        .iter()
        .filter(|path| names_an_env_mutation(&fs::read_to_string(path).expect("read source")))
        .map(|path| {
            path.strip_prefix(&root)
                .unwrap_or(path)
                .display()
                .to_string()
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "writing the process environment reallocates the environ array under every concurrent \
         reader, and `cargo test` runs one process with hundreds of threads — a `tempfile` call \
         in an unrelated test reads freed memory. A reader takes `&dyn rastreo_core::env::Env`; \
         hand it a `MapEnv` from the test and a `SystemEnv` from the binary. A test that needs a \
         variable in its own process re-runs itself in a child that starts with one. This walks \
         raw file text, so a comment or a string naming one of these calls trips it too — split \
         the name the way this file does. Found: {offenders:?}"
    );
}

#[test]
fn every_form_of_an_environment_write_is_matched() {
    for call in [
        concat!("unsafe { std::env::set", "_var(\"K\", \"v\") };"),
        concat!("unsafe { env::remove", "_var(\"K\") };"),
        concat!("cmd.set", "_var(name, value);"),
        concat!("unsafe { libc::set", "env(key, value, 1) };"),
        concat!("unsafe { libc::unset", "env(key) };"),
        concat!("unsafe { libc::put", "env(entry) };"),
    ] {
        assert!(names_an_env_mutation(call), "{call}");
    }
}

#[test]
fn a_call_that_only_contains_the_name_is_not_matched() {
    for call in [
        concat!("let unset", "_var = true;"),
        concat!("std::env::set", "_variable(k, v)"),
        concat!("self.remove", "_vars();"),
        "let env = MapEnv::new().set(\"K\", \"v\");",
        "// a thread inside getenv reads freed memory",
        concat!("let set", "env_calls = 0;"),
    ] {
        assert!(!names_an_env_mutation(call), "{call}");
    }
}
