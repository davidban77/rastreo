use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct WriteFailure {
    pub path: PathBuf,
    pub source: std::io::Error,
}

/// Write to `<path>.tmp`, then rename onto `<path>`, so a reader never observes a partially written
/// file (atomic on POSIX within one filesystem).
pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), WriteFailure> {
    let tmp = tmp_path(path);
    std::fs::write(&tmp, bytes).map_err(|source| WriteFailure {
        path: tmp.clone(),
        source,
    })?;
    std::fs::rename(&tmp, path).map_err(|source| WriteFailure {
        path: path.to_path_buf(),
        source,
    })
}

pub(crate) fn tmp_path(path: &Path) -> PathBuf {
    let mut raw = path.as_os_str().to_owned();
    raw.push(".tmp");
    PathBuf::from(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bytes_land_at_the_named_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("artifact.json");
        write_atomically(&path, b"{}").expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"{}");
    }

    #[test]
    fn no_temporary_file_survives_a_successful_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("artifact.json");
        write_atomically(&path, b"{}").expect("write");
        assert!(!tmp_path(&path).exists());
    }

    #[test]
    fn a_second_write_replaces_the_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("artifact.json");
        write_atomically(&path, b"first").expect("write");
        write_atomically(&path, b"second").expect("rewrite");
        assert_eq!(std::fs::read(&path).expect("read"), b"second");
    }

    #[test]
    fn a_write_into_a_missing_directory_names_the_temporary_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("missing").join("artifact.json");
        let failure = write_atomically(&path, b"{}").expect_err("no such directory");
        assert_eq!(failure.path, tmp_path(&path));
    }
}
