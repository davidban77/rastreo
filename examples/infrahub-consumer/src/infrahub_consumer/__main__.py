"""Entry point: `python -m infrahub_consumer`."""

from __future__ import annotations

import json
import logging
import sys

from .config import Config, ConfigError
from .consumer import run

_STANDARD_LOG_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None)).keys()) | {
    "message",
    "asctime",
    "taskName",
}


class _JsonFormatter(logging.Formatter):
    """One JSON line per log record, with `extra=` fields merged flat."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_LOG_ATTRS:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def _configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


try:
    config = Config.from_env()
except ConfigError as exc:
    print(f"configuration error: {exc}", file=sys.stderr)
    sys.exit(1)

_configure_logging(config.log_level)
run(config)
