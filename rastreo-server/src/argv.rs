use clap::Parser;

/// Parse `argv` with every `env =` source stripped, so an exported variable cannot decide the result.
pub(crate) fn parse_without_env<T, I, S>(argv: I) -> std::result::Result<T, clap::Error>
where
    T: Parser,
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let matches = without_env_sources(T::command()).try_get_matches_from(argv)?;
    T::from_arg_matches(&matches)
}

fn without_env_sources(command: clap::Command) -> clap::Command {
    command
        .mut_args(|arg| arg.env(None::<&'static str>))
        .mut_subcommands(without_env_sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[derive(Parser, Debug)]
    struct AmbientProbe {
        #[arg(long, env = "PATH")]
        path: Option<String>,
    }

    fn env_backed_arguments(command: &clap::Command) -> Vec<String> {
        let mut out: Vec<String> = command
            .get_arguments()
            .filter(|arg| arg.get_env().is_some())
            .map(|arg| format!("{}.{}", command.get_name(), arg.get_id()))
            .collect();
        for sub in command.get_subcommands() {
            out.extend(env_backed_arguments(sub));
        }
        out
    }

    #[test]
    fn no_argument_in_the_command_tree_keeps_an_env_source() {
        assert!(
            !env_backed_arguments(&crate::Cli::command()).is_empty(),
            "the crate has no env-backed argument left, so this guard proves nothing"
        );
        assert_eq!(
            env_backed_arguments(&without_env_sources(crate::Cli::command())),
            Vec::<String>::new()
        );
    }

    #[test]
    fn parse_without_env_ignores_a_variable_the_process_already_carries() {
        let through_clap = AmbientProbe::try_parse_from(["probe"]).expect("parses");
        assert!(
            through_clap.path.is_some(),
            "this assertion needs a PATH in the ambient environment to strip"
        );

        let stripped: AmbientProbe = parse_without_env(["probe"]).expect("parses");
        assert_eq!(stripped.path, None);
    }

    #[test]
    fn parse_without_env_still_reads_the_flag() {
        let cli: crate::Cli =
            parse_without_env(["rastreo-server", "--request-timeout-ms", "30000"]).expect("parses");
        assert_eq!(cli.request_timeout_ms, 30_000);
    }
}
