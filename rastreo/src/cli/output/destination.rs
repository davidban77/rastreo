use std::io::IsTerminal;

/// Where the record stream lands relative to the stderr stream every printer in `output/` writes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordDestination {
    Separate,
    SharedTerminal,
    SharedCapture,
}

impl RecordDestination {
    pub(crate) fn is_shared(self) -> bool {
        self != RecordDestination::Separate
    }
}

pub(crate) fn record_destination(records_on_stdout: bool) -> RecordDestination {
    classify(
        records_on_stdout,
        stdout_and_stderr_are_one_file(),
        std::io::stderr().is_terminal(),
    )
}

// A terminal is painted for a person as the run goes; anything else is captured and read afterwards.
fn classify(
    records_on_stdout: bool,
    one_file: bool,
    stderr_is_terminal: bool,
) -> RecordDestination {
    if !records_on_stdout || !one_file {
        RecordDestination::Separate
    } else if stderr_is_terminal {
        RecordDestination::SharedTerminal
    } else {
        RecordDestination::SharedCapture
    }
}

#[cfg(unix)]
fn stdout_and_stderr_are_one_file() -> bool {
    use std::os::fd::AsFd;
    one_file(same_file(
        std::io::stdout().as_fd(),
        std::io::stderr().as_fd(),
    ))
}

// An unreadable identity cannot prove the streams apart, and a banner in the record stream costs more.
#[cfg(unix)]
fn one_file(identity: Option<bool>) -> bool {
    identity.unwrap_or(true)
}

// `> out 2>&1`, `2>&1 | jq`, and a terminal all name one file through two descriptors.
#[cfg(unix)]
fn same_file(a: std::os::fd::BorrowedFd<'_>, b: std::os::fd::BorrowedFd<'_>) -> Option<bool> {
    Some(file_id(a)? == file_id(b)?)
}

#[cfg(unix)]
fn file_id(fd: std::os::fd::BorrowedFd<'_>) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let duplicate = std::fs::File::from(fd.try_clone_to_owned().ok()?);
    let metadata = duplicate.metadata().ok()?;
    Some((metadata.dev(), metadata.ino()))
}

// Descriptor identity is a Unix notion; off it, a shared terminal is the case that reaches a user.
#[cfg(not(unix))]
fn stdout_and_stderr_are_one_file() -> bool {
    std::io::stdout().is_terminal() && std::io::stderr().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_on_another_destination_are_separate_however_the_streams_are_wired() {
        for one_file in [false, true] {
            for stderr_is_terminal in [false, true] {
                assert_eq!(
                    classify(false, one_file, stderr_is_terminal),
                    RecordDestination::Separate,
                    "one_file: {one_file}, stderr_is_terminal: {stderr_is_terminal}"
                );
            }
        }
    }

    #[test]
    fn two_files_keep_the_streams_separate_even_on_a_terminal() {
        assert_eq!(classify(true, false, true), RecordDestination::Separate);
        assert_eq!(classify(true, false, false), RecordDestination::Separate);
    }

    #[test]
    fn one_terminal_carrying_both_is_shared_and_read_live() {
        assert_eq!(
            classify(true, true, true),
            RecordDestination::SharedTerminal
        );
    }

    #[test]
    fn one_redirected_file_carrying_both_is_a_capture() {
        assert_eq!(
            classify(true, true, false),
            RecordDestination::SharedCapture
        );
    }

    #[test]
    fn only_separate_is_unshared() {
        assert!(!RecordDestination::Separate.is_shared());
        assert!(RecordDestination::SharedTerminal.is_shared());
        assert!(RecordDestination::SharedCapture.is_shared());
    }

    #[cfg(unix)]
    mod fds {
        use super::*;
        use std::io::Write;
        use std::os::fd::AsFd;

        #[test]
        fn a_descriptor_is_the_same_file_as_itself() {
            let file = tempfile::tempfile().expect("tempfile");
            assert_eq!(same_file(file.as_fd(), file.as_fd()), Some(true));
        }

        #[test]
        fn a_duplicated_descriptor_names_the_same_file() {
            let file = tempfile::tempfile().expect("tempfile");
            let duplicate = file.try_clone().expect("dup");
            assert_eq!(same_file(file.as_fd(), duplicate.as_fd()), Some(true));
        }

        #[test]
        fn two_opens_of_one_path_name_the_same_file() {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("out.txt");
            let first = std::fs::File::create(&path).expect("create");
            let second = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("reopen");
            assert_eq!(same_file(first.as_fd(), second.as_fd()), Some(true));
        }

        #[test]
        fn two_distinct_files_are_not_the_same_file() {
            let dir = tempfile::tempdir().expect("tempdir");
            let first = std::fs::File::create(dir.path().join("a.txt")).expect("create a");
            let second = std::fs::File::create(dir.path().join("b.txt")).expect("create b");
            assert_eq!(same_file(first.as_fd(), second.as_fd()), Some(false));
        }

        #[test]
        fn both_ends_of_one_shell_pipeline_name_the_same_pipe() {
            let (_reader, writer) = std::io::pipe().expect("pipe");
            let duplicate = writer.try_clone().expect("dup");
            assert_eq!(same_file(writer.as_fd(), duplicate.as_fd()), Some(true));
        }

        #[test]
        fn two_pipes_are_not_the_same_file() {
            let (_first_reader, first) = std::io::pipe().expect("pipe");
            let (_second_reader, second) = std::io::pipe().expect("pipe");
            assert_eq!(same_file(first.as_fd(), second.as_fd()), Some(false));
        }

        #[test]
        fn reading_the_identity_leaves_the_descriptor_open() {
            let mut file = tempfile::tempfile().expect("tempfile");
            assert_eq!(same_file(file.as_fd(), file.as_fd()), Some(true));
            file.write_all(b"still open").expect("write after the stat");
        }

        #[test]
        fn an_unreadable_identity_counts_as_one_file() {
            assert!(one_file(None));
        }

        #[test]
        fn a_readable_identity_is_taken_at_its_word() {
            assert!(one_file(Some(true)));
            assert!(!one_file(Some(false)));
        }
    }
}
