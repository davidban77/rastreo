"""Environment-driven configuration for the reference consumer."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


class ConfigError(RuntimeError):
    """Raised when required environment variables are missing or malformed."""


@dataclass(frozen=True, slots=True)
class Config:
    """Typed view of the environment variables the consumer reads at startup."""

    kafka_brokers: str
    kafka_topic: str
    kafka_group_id: str
    kafka_auto_offset_reset: str
    poll_timeout_ms: int
    netbox_url: str
    netbox_token: str
    netbox_verify_tls: bool
    netbox_timeout_seconds: int
    log_level: str
    dry_run: bool

    @classmethod
    def from_env(cls, *, load_dotenv_file: bool = True) -> Config:
        """Build a Config from the process environment, optionally reading .env first."""
        if load_dotenv_file:
            load_dotenv()

        missing = [
            name
            for name in ("KAFKA_BROKERS", "NETBOX_URL", "NETBOX_TOKEN")
            if not os.environ.get(name, "").strip()
        ]
        if missing:
            raise ConfigError("missing required environment variables: " + ", ".join(missing))

        offset_reset = os.environ.get("KAFKA_AUTO_OFFSET_RESET", "earliest").strip().lower()
        if offset_reset not in {"earliest", "latest"}:
            raise ConfigError(
                f"KAFKA_AUTO_OFFSET_RESET must be 'earliest' or 'latest', got {offset_reset!r}"
            )

        log_level = os.environ.get("LOG_LEVEL", "INFO").strip().upper()
        if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigError(
                f"LOG_LEVEL must be one of DEBUG, INFO, WARNING, ERROR, CRITICAL; got {log_level!r}"
            )

        return cls(
            kafka_brokers=os.environ["KAFKA_BROKERS"].strip(),
            kafka_topic=os.environ.get("KAFKA_TOPIC", "rastreo.devices"),
            kafka_group_id=os.environ.get("KAFKA_GROUP_ID", "rastreo-netbox-consumer"),
            kafka_auto_offset_reset=offset_reset,
            poll_timeout_ms=_int("POLL_TIMEOUT_MS", "1000"),
            netbox_url=os.environ["NETBOX_URL"].strip().rstrip("/"),
            netbox_token=os.environ["NETBOX_TOKEN"].strip(),
            netbox_verify_tls=_bool("NETBOX_VERIFY_TLS", "true"),
            netbox_timeout_seconds=_int("NETBOX_TIMEOUT_SECONDS", "30"),
            log_level=log_level,
            dry_run=_bool("DRY_RUN", "false"),
        )


def _bool(name: str, default: str) -> bool:
    raw = os.environ.get(name, default).strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean, got {raw!r}")


def _int(name: str, default: str) -> int:
    raw = os.environ.get(name, default)
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
