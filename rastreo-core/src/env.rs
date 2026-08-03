//! The environment as an injected value rather than process-global state, so a reader whose input
//! genuinely is the environment stays a pure function of it. Kept dep-free (`std` only) so it
//! compiles under `--no-default-features` and both binaries can read their startup config through it.

use std::collections::BTreeMap;
use std::ffi::OsString;

pub use std::env::VarError;

/// A source of environment variables, read-only: writing the process environment is unsound while
/// any other thread may be reading it.
pub trait Env: Send + Sync {
    fn var(&self, key: &str) -> Result<String, VarError>;
}

/// The variables of the running process.
#[derive(Debug, Clone, Copy)]
pub struct SystemEnv;

impl Env for SystemEnv {
    fn var(&self, key: &str) -> Result<String, VarError> {
        std::env::var(key)
    }
}

/// A fixed set of variables owned by the caller. Values are `OsString` so a reader's non-UTF-8 arm
/// stays reachable.
// No `Debug`: an environment holds credentials, and this crate redacts those everywhere else.
#[derive(Clone, Default)]
pub struct MapEnv(BTreeMap<String, OsString>);

impl MapEnv {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(mut self, key: impl Into<String>, value: impl Into<OsString>) -> Self {
        self.0.insert(key.into(), value.into());
        self
    }
}

impl Env for MapEnv {
    fn var(&self, key: &str) -> Result<String, VarError> {
        match self.0.get(key) {
            None => Err(VarError::NotPresent),
            Some(value) => value.clone().into_string().map_err(VarError::NotUnicode),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_variable_the_map_does_not_carry_is_not_present() {
        let env = MapEnv::new().set("PRESENT", "value");
        assert_eq!(env.var("PRESENT").as_deref(), Ok("value"));
        assert_eq!(env.var("ABSENT"), Err(VarError::NotPresent));
    }

    #[test]
    fn the_last_write_of_a_key_wins() {
        let env = MapEnv::new().set("KEY", "first").set("KEY", "second");
        assert_eq!(env.var("KEY").as_deref(), Ok("second"));
    }

    #[cfg(unix)]
    #[test]
    fn a_value_that_is_not_utf8_reads_back_as_not_unicode() {
        use std::os::unix::ffi::OsStringExt;

        let env = MapEnv::new().set("RAW", OsString::from_vec(vec![0x66, 0xff, 0x6f]));
        assert!(matches!(env.var("RAW"), Err(VarError::NotUnicode(_))));
    }

    #[test]
    fn the_system_environment_reads_what_the_process_carries() {
        let (key, value) = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .next()
            .expect("the test process carries a UTF-8 variable");
        assert_eq!(SystemEnv.var(&key).as_deref(), Ok(value.as_str()));
        assert_eq!(
            SystemEnv.var("RASTREO_A_VARIABLE_NO_ONE_EXPORTS"),
            Err(VarError::NotPresent)
        );
    }

    #[test]
    fn both_implementations_are_usable_behind_a_trait_object() {
        fn read(env: &dyn Env) -> Result<String, VarError> {
            env.var("RASTREO_TRAIT_OBJECT_KEY")
        }
        assert_eq!(
            read(&MapEnv::new().set("RASTREO_TRAIT_OBJECT_KEY", "v")).as_deref(),
            Ok("v")
        );
        assert_eq!(read(&SystemEnv), Err(VarError::NotPresent));
    }
}
