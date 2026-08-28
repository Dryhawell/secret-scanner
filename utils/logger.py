"""Application logging.

Logs go to a file by default. Secret values — plaintext or masked — are
never written. A finding is recorded as type + location + severity only.
"""

from __future__ import annotations

import logging
from pathlib import Path

LOGGER_NAME = "secret_scanner"
DEFAULT_LOG_PATH = Path("logs") / "secret_scanner.log"

_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def get_logger() -> logging.Logger:
    """Return the package logger. Safe to call before setup_logging()."""
    logger = logging.getLogger(LOGGER_NAME)
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    return logger


def setup_logging(
    *,
    log_file: Path | None = None,
    verbose: bool = False,
) -> Path:
    """Configure file logging. Returns the log file path.

    Repeated calls replace handlers so tests can isolate log files.
    """
    path = Path(log_file) if log_file is not None else DEFAULT_LOG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler.setFormatter(logging.Formatter(_FORMAT))
    logger.addHandler(handler)
    return path
