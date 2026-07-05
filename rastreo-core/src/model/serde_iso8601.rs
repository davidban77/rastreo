//! RFC 3339 UTC serde helpers for `SystemTime` fields; used via `#[serde(with = ...)]`.

use std::time::SystemTime;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
    let dt: DateTime<Utc> = (*t).into();
    s.serialize_str(&dt.to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SystemTime, D::Error> {
    let s = String::deserialize(d)?;
    let dt = DateTime::parse_from_rfc3339(&s).map_err(serde::de::Error::custom)?;
    Ok(SystemTime::from(dt.with_timezone(&Utc)))
}

pub fn date_time_schema(generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
    let mut schema: schemars::schema::SchemaObject = generator.subschema_for::<String>().into();
    schema.format = Some("date-time".to_owned());
    schema.into()
}
