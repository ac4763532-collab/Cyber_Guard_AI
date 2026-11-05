import os

import uvicorn

# uvicorn >= 0.36 builds its own event loop via a loop_factory and does
# NOT consult asyncio.set_event_loop_policy() for it (its "asyncio"/"auto"
# loop presets hardcode ProactorEventLoop on Windows - see
# app/windows_loop.py for the full explanation). Pass our own factory's
# dotted path instead of the "asyncio" preset so psycopg's async
# connection pool gets a SelectorEventLoop.
if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 8000)),
        loop="app.windows_loop:selector_loop_factory",
    )
