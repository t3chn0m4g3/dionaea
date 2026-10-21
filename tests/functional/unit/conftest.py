# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import pytest


@pytest.fixture(scope="session", autouse=True)
def dionaea_ready():
    """The unit tests need no dionaea container (overrides the fixture of ../conftest.py)."""


class SummaryClock:
    """The clock and the timer of the LogSummary objects of a test (logtext.py)."""

    def __init__(self):
        self.now = 1000.0
        # summary -> the time its timer fires
        self.timers = {}

    def __call__(self):
        return self.now

    def schedule(self, summary, after):
        assert after > 0
        self.timers[summary] = self.now + after
        return True

    def advance(self, seconds):
        """The clock goes on; the timers that are due on the way fire."""
        end = self.now + seconds
        while True:
            due = [(at, s) for s, at in self.timers.items() if at <= end]
            if not due:
                break
            at, summary = min(due, key=lambda item: item[0])
            del self.timers[summary]
            self.now = at
            summary.due()
        self.now = end


@pytest.fixture
def summaries(monkeypatch):
    """summaries(*objects): the LogSummary objects use the clock of the test (returned), their
    events and their last warning are forgotten."""
    clock = SummaryClock()

    def use(*objects):
        for summary in objects:
            monkeypatch.setattr(summary, "clock", clock)
            monkeypatch.setattr(summary, "schedule", clock.schedule)
            summary.reset()
        return clock

    yield use
