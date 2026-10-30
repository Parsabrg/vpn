"""The alert path must not depend on the thing it reports on.

This is the whole premise of running the alerter on the host with only the
standard library: an alerter that needs the agent's machinery working cannot
tell you the agent's machinery is broken.

It was wrong once, and silently. nebula_agent.main calls create_app() at
import time, which constructs the operation ledger and reads its file, so
importing it from preflight made `nebula-agent-alert` die on a PermissionError
before it could send anything. The unit that existed to report failures was
itself the thing that failed, and it only surfaced because the alert path was
exercised for real rather than assumed to work.
"""

import subprocess
import sys


def _import_in_a_fresh_interpreter(statement: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - this interpreter, literal args
        [sys.executable, "-c", statement],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_importing_the_alert_path_does_not_build_the_agent_app() -> None:
    """A subprocess, not an in-process import: pytest has already imported
    half the package by the time a test runs, so an in-process check would
    pass on modules another test happened to load first.
    """

    result = _import_in_a_fresh_interpreter(
        "import sys;"
        "import nebula_agent.healthcheck;"
        "loaded = 'nebula_agent.main' in sys.modules;"
        "print('LOADED' if loaded else 'CLEAN')"
    )

    assert result.returncode == 0, result.stderr
    assert "CLEAN" in result.stdout, (
        "importing the alert path pulled in nebula_agent.main, which calls "
        "create_app() at import time and reads the operation ledger. The "
        "alerter must not need any of that to report a fault."
    )


def test_importing_the_alert_path_does_not_touch_the_ledger() -> None:
    """The specific failure, pinned by its symptom rather than its cause: no
    file under the agent's state directory may be opened just to import."""

    result = _import_in_a_fresh_interpreter(
        "import builtins;"
        "opened = [];"
        "real = builtins.open;"
        "builtins.open = lambda f, *a, **k: (opened.append(str(f)), real(f, *a, **k))[1];"
        "import nebula_agent.healthcheck;"
        "builtins.open = real;"
        "bad = [f for f in opened if 'nebula' in f and 'ledger' in f];"
        "print('TOUCHED' if bad else 'CLEAN')"
    )

    assert result.returncode == 0, result.stderr
    assert "CLEAN" in result.stdout


def test_the_alerting_module_imports_nothing_from_the_agent_but_its_version() -> None:
    """alerting.py is deliberately standalone -- stdlib plus one version
    string. Anything else creeping in is the coupling coming back."""

    source = subprocess.run(
        [
            sys.executable,
            "-c",
            "import inspect, nebula_agent.alerting as a; print(inspect.getsource(a))",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    ).stdout

    agent_imports = [
        line.strip()
        for line in source.splitlines()
        if line.startswith(("import nebula_agent", "from nebula_agent"))
    ]

    assert agent_imports == ["from nebula_agent import __version__"], agent_imports


def test_building_a_driver_does_not_build_the_agent_app() -> None:
    """The import-time checks above passed while this was still broken.

    The first fix moved the `nebula_agent.main` import inside
    check_advertised_endpoints, so importing the alert path was clean -- and
    the health check still constructed the whole application the moment it
    actually ran, because that is when the deferred import happened. It failed
    in production with the same PermissionError, one command further along.

    Import-time isolation is not the property that matters; not needing the
    application at all is. The builder now lives in its own module, and this
    asserts the runtime path rather than the import.
    """

    result = _import_in_a_fresh_interpreter(
        "import sys;"
        "from nebula_agent.driver_factory import build_xray_driver;"
        "from nebula_agent.settings import Settings;"
        "build_xray_driver(Settings(env='test'));"
        "loaded = 'nebula_agent.main' in sys.modules;"
        "print('LOADED' if loaded else 'CLEAN')"
    )

    assert result.returncode == 0, result.stderr
    assert "CLEAN" in result.stdout, (
        "building a driver pulled in nebula_agent.main, which calls create_app() "
        "at import and reads the operation ledger. The monitoring commands run "
        "with an empty CapabilityBoundingSet, so root does not bypass file "
        "permissions and that read fails with EACCES."
    )


def test_the_healthcheck_run_path_never_reaches_the_agent_app() -> None:
    """End to end through collect_problems, which is what the unit runs."""

    # The outcome of the run is deliberately ignored: on a machine with no
    # systemd and a fake driver it ends in SystemExit, and that is not what is
    # under test. The property is that nebula_agent.main was never reached,
    # whichever way the run ended.
    result = _import_in_a_fresh_interpreter(
        "\n".join(
            [
                "import sys, asyncio, datetime",
                "from nebula_agent.healthcheck import collect_problems",
                "from nebula_agent.settings import Settings",
                "try:",
                "    asyncio.run(",
                "        collect_problems(Settings(env='test'),"
                " datetime.datetime.now(datetime.UTC))",
                "    )",
                "except BaseException:",
                "    pass",
                "print('LOADED' if 'nebula_agent.main' in sys.modules else 'CLEAN')",
            ]
        )
    )

    assert result.returncode == 0, result.stderr
    assert "CLEAN" in result.stdout
