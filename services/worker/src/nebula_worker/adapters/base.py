"""Shared adapter contract: send one email, return the provider's message id."""

from typing import Protocol


class EmailSendError(RuntimeError):
    """Raised when a provider rejects or fails to deliver a message."""


class EmailAdapter(Protocol):
    async def send(self, *, to: str, subject: str, body: str) -> str: ...
