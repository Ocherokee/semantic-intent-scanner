"""
Shared pytest configuration.

Two things live here:

* the ``live_model`` marker -- any test that makes a real Anthropic API call.
  The deterministic release gate runs ``pytest -m "not live_model"`` and must
  see zero skips and zero failures.

* ``--fail-on-skip`` -- turns any skipped test into a failure. CI's
  deterministic job passes this so an accidentally-skipped deterministic test
  (a broken import guard, a platform gate that should not be there) fails the
  build instead of hiding.
"""

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live_model: exercises a live Anthropic model; excluded from the "
        "deterministic release gate (run with -m 'not live_model').",
    )


def pytest_addoption(parser):
    parser.addoption(
        "--fail-on-skip",
        action="store_true",
        default=False,
        help="Treat any skipped test as a failure (deterministic release gate).",
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if (
        item.config.getoption("--fail-on-skip")
        and report.skipped
        and call.when in ("setup", "call")
    ):
        report.outcome = "failed"
        report.longrepr = (
            f"{item.nodeid} was skipped while --fail-on-skip is set. "
            f"The deterministic gate expects no skips. Original: {report.longrepr}"
        )
