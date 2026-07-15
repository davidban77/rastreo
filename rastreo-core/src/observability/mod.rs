//! Cross-crate observability primitives — types and helpers shared between `rastreo` and `rastreo-server` so OTLP config parsing lives in exactly one place.

#[cfg(feature = "otlp")]
pub mod otlp;
pub mod otlp_config;
