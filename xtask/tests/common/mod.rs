use std::fs;
use std::path::{Path, PathBuf};

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent")
        .to_path_buf()
}

pub fn declared_members(manifest: &str) -> Vec<String> {
    let lines: Vec<&str> = manifest.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.trim_start().starts_with("members"))
        .expect("the workspace manifest declares members");
    let tail = lines[start..].join("\n");
    let list = tail
        .split_once('[')
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(list, _)| list)
        .expect("the members list is a bracketed array");
    list.split(',')
        .map(|entry| entry.trim().trim_matches('"').to_string())
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// The workspace root and every `.rs` file under every crate it declares.
pub fn workspace_sources() -> (PathBuf, Vec<PathBuf>) {
    let root = workspace_root();
    let crates = crate_dirs(&root);
    let declared = declared_members(
        &fs::read_to_string(root.join("Cargo.toml")).expect("read the workspace manifest"),
    );
    let unwalked: Vec<&String> = declared
        .iter()
        .filter(|member| !crates.contains(&root.join(member)))
        .collect();
    assert!(
        unwalked.is_empty(),
        "this walk covers the workspace's top-level crate directories, and {unwalked:?} is \
         declared but not among {crates:?}"
    );

    let mut files = Vec::new();
    for dir in &crates {
        rust_sources(dir, &mut files);
    }
    assert!(
        files.len() > 50,
        "walked {} files, expected the whole workspace source tree",
        files.len()
    );
    (root, files)
}

fn crate_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(root)
        .expect("read the workspace root")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.join("Cargo.toml").is_file())
        .collect();
    out.sort();
    out
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}
