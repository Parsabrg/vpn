"""The one place this package calls a subprocess: fixed argv, never a shell."""

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass

_MINIMAL_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


@dataclass(frozen=True, slots=True)
class CompletedRun:
    returncode: int
    stdout: bytes
    stderr: bytes


class SubprocessTimeoutError(RuntimeError):
    """The subprocess did not finish within the configured timeout and was killed."""


async def run_fixed_argv(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    stdin: bytes | None = None,
) -> CompletedRun:
    """argv[0] must already be an absolute path validated by Settings; every
    other element must come from typed, already-validated fields -- never
    caller-supplied free text. The child gets a fixed minimal PATH, not the
    agent process's own environment, so nothing the agent holds (secrets,
    unrelated configuration) leaks into wg/wg-quick's environment."""

    # argv is built entirely from validated Settings paths and internally
    # rendered temp-file paths, never from caller-supplied strings.
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=_MINIMAL_ENV,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(stdin), timeout=timeout_seconds)
    except TimeoutError as error:
        process.kill()
        await process.wait()
        raise SubprocessTimeoutError(
            f"{argv[0]} did not finish within {timeout_seconds}s"
        ) from error

    returncode = process.returncode
    if returncode is None:
        raise RuntimeError("subprocess exited without reporting a return code")
    return CompletedRun(returncode=returncode, stdout=stdout, stderr=stderr)
