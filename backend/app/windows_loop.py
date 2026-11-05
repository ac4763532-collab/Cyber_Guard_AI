"""
Windows event loop factory for uvicorn.

psycopg's async mode (used by app.database.connection's
AsyncConnectionPool) requires a SelectorEventLoop. asyncio's default on
Windows is ProactorEventLoop, and critically, uvicorn >= 0.36 no longer
respects a globally-set asyncio.set_event_loop_policy() for its own loop
creation - uvicorn.loops.asyncio.asyncio_loop_factory() hardcodes
`return asyncio.ProactorEventLoop` for the "asyncio"/"auto" loop presets
on Windows (except when use_subprocess is True, which is about
--reload/--workers subprocess spawning, not something to rely on here).
Setting the policy (as tests/conftest.py and this project's historical
app/main.py and run_windows.py did) has no effect on the loop uvicorn
itself constructs - it only affects loops created via
asyncio.new_event_loop()/asyncio.get_event_loop_policy() directly, which
uvicorn's modern loop_factory-based startup bypasses entirely.

Pass this factory's dotted path to uvicorn's `loop` argument/--loop flag
instead of a preset name:
    uvicorn.run("app.main:app", loop="app.windows_loop:selector_loop_factory")
    uvicorn app.main:app --loop app.windows_loop:selector_loop_factory
"""

from __future__ import annotations

import asyncio
import selectors


def selector_loop_factory() -> asyncio.AbstractEventLoop:
    """Return a SelectorEventLoop, compatible with psycopg's async mode."""
    return asyncio.SelectorEventLoop(selectors.SelectSelector())
