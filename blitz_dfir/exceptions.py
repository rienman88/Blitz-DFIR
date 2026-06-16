from __future__ import annotations


class BlitzError(Exception):
    """Base error for Blitz DFIR."""


class ManifestError(BlitzError):
    """Manifest schema, registration, or loading error."""


class EvidenceSecurityError(BlitzError):
    """Evidence path or access policy violation."""


class IntegrityError(BlitzError):
    """Hash or integrity verification failure."""


class ValidationError(BlitzError):
    """Evidence validation failure."""

