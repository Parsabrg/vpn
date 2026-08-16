"""Driver-level error hierarchy: distinguishes rejected input from a failed apply."""


class DriverError(Exception):
    """Base class for all driver failures."""


class ValidationError(DriverError):
    """Request failed validation before any subprocess call or state mutation was attempted."""


class ApplyError(DriverError):
    """Applying the desired state failed; rollback to the last-known-good state was attempted."""


class RollbackFailedError(DriverError):
    """Rollback to the last-known-good state also failed -- the interface is in an unknown state."""
