"""Typed exceptions for probepath.

Parse/ingest failures must *fail loud* — a silently-swallowed error on a gating
attribute is a false-negative vector (DESIGN.md §3.6). These exceptions exist so the
CLI can distinguish a usage/ingest problem (exit 2) from a clean run (exit 0/1).
"""

from __future__ import annotations


class ProbepathError(Exception):
    """Base class for all probepath errors."""


class IngestError(ProbepathError):
    """Raised when a Terraform input cannot be read or parsed at all."""


class UnsupportedFormatError(IngestError):
    """Raised when an input file's format cannot be detected or is unsupported."""


class ConfigError(ProbepathError):
    """Raised when ``.probepath.yml`` is malformed or self-contradictory."""
