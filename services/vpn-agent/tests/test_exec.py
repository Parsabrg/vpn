import sys

import pytest

from nebula_agent.drivers._exec import SubprocessTimeoutError, run_fixed_argv


@pytest.mark.anyio
async def test_captures_stdout_and_a_zero_returncode() -> None:
    result = await run_fixed_argv([sys.executable, "-c", "print('hello')"], timeout_seconds=5)

    assert result.returncode == 0
    assert result.stdout.strip() == b"hello"


@pytest.mark.anyio
async def test_captures_stderr_and_a_nonzero_returncode_without_raising() -> None:
    result = await run_fixed_argv(
        [sys.executable, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"],
        timeout_seconds=5,
    )

    assert result.returncode == 3
    assert result.stderr.strip() == b"boom"


@pytest.mark.anyio
async def test_stdin_is_piped_to_the_child() -> None:
    result = await run_fixed_argv(
        [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read().upper())"],
        timeout_seconds=5,
        stdin=b"hello",
    )

    assert result.stdout == b"HELLO"


@pytest.mark.anyio
async def test_a_slow_child_is_killed_on_timeout() -> None:
    with pytest.raises(SubprocessTimeoutError, match="did not finish within"):
        await run_fixed_argv(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout_seconds=0.1,
        )


@pytest.mark.anyio
async def test_the_child_does_not_inherit_the_parent_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEBULA_TEST_MARKER_SHOULD_NOT_LEAK", "present")
    result = await run_fixed_argv(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ.get('NEBULA_TEST_MARKER_SHOULD_NOT_LEAK', 'absent'))",
        ],
        timeout_seconds=5,
    )

    assert result.stdout.strip() == b"absent"
