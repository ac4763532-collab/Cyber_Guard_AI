"""
CyberGuard AI - Gmail Automatic Polling Service

Supervised background task that makes Gmail analysis actually automatic:
without this, "automatically analyze new email" only ever meant "the
synchronous analyze endpoint also happens to publish to the bus" - a user
still had to open the Email Analysis page and click into a message. This
polls each connected Gmail account on an interval, detects new messages via
Gmail's incremental history.list() cursor (not a full mailbox listing), and
runs each one through the same publish_email_event() path analyze_gmail_message
already uses - so new mail is found and analyzed with no user action.

Mirrors app/logs/collector_manager.py's supervised-task shape: one
asyncio.Task per logical unit of work (here, "poll every connected account
once"), interruptible sleep via asyncio.wait_for(stop_event.wait(), ...),
and per-cycle exception isolation so one account's failure (expired token,
Gmail API error) never stops polling for every other account or kills the
task outright.

Gmail push notifications (watch() + Pub/Sub) are NOT used - they need a
public HTTPS endpoint and a configured Google Cloud Pub/Sub topic this
project does not have. Polling with an incremental historyId cursor is the
implemented substitute (see history_list() on GmailClient) and is
documented as such; this is a known, stated limitation, not an oversight.

Usage:
    # Started/stopped from the FastAPI lifespan, alongside the existing
    # collector manager.
    await start_gmail_poller()
    ...
    await stop_gmail_poller()
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import structlog

from app.config import get_settings
from app.database.repositories.gmail_sync_state import get_gmail_sync_state_repository
from app.database.repositories.oauth_tokens import get_oauth_token_repository
from app.services.email_ingestion import publish_email_event
from app.services.gmail.client import GmailClient
from app.services.gmail.oauth import GmailTokens, get_gmail_oauth_service
from app.services.gmail.parser import GmailParser
from app.services.token_encryption import get_token_encryption_service

logger = structlog.get_logger(__name__)

# Backoff bounds for the poller's own supervisor loop (distinct from the
# fixed per-account gmail_poll_interval_seconds - this only governs how
# quickly the overall task recovers from an unexpected failure in the
# poll-cycle loop itself, not normal per-account error handling, which is
# isolated per account and never aborts the cycle).
_INITIAL_RESTART_DELAY = 5.0
_MAX_RESTART_DELAY = 300.0

# Gmail returns 404 when startHistoryId is too old/expired (history is
# only retained for a limited time, typically ~7 days). On that specific
# failure, fall back once to a bounded recent-messages listing and reseed
# the cursor - this must be an explicit, logged fallback, never a silent,
# unbounded resync of the whole mailbox.
_HISTORY_EXPIRED_LOOKBACK_MESSAGES = 25


class GmailPoller:
    """
    Supervises automatic Gmail polling for every connected account.

    One supervisor task total (not one per account) - each cycle iterates
    every stored Google OAuth token via list_by_provider() and polls them
    in turn. A user with no stored tokens is simply absent from that list;
    there is no fabricated "monitoring" status for a disconnected account.
    """

    def __init__(self):
        self._task: asyncio.Task | None = None
        self._stop_event = asyncio.Event()

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        """Start the poller's supervisor task, if not already running."""
        if self.is_running:
            logger.warning("Gmail poller already running")
            return

        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._run_supervisor())
        logger.info("Gmail poller started")

    async def stop(self) -> None:
        """Signal the supervisor task to stop and wait for it to finish."""
        if not self.is_running:
            return

        self._stop_event.set()
        try:
            await asyncio.wait_for(self._task, timeout=30.0)
        except asyncio.TimeoutError:
            logger.warning("Gmail poller did not stop in time - cancelling")
            self._task.cancel()
        except Exception as e:
            logger.warning("Gmail poller stop raised", error=str(e))

        logger.info("Gmail poller stopped")

    async def _run_supervisor(self) -> None:
        """
        Top-level supervisor loop: run a poll cycle, sleep for the
        configured interval (interruptibly), repeat. Any exception escaping
        a full cycle (should not normally happen - _poll_once isolates
        per-account errors) is logged and backed off from, exactly like
        collector_manager.py's per-source supervisor, rather than letting
        the task die silently.
        """
        settings = get_settings()
        restart_delay = _INITIAL_RESTART_DELAY

        while not self._stop_event.is_set():
            try:
                await self._poll_once()
                restart_delay = _INITIAL_RESTART_DELAY  # Reset backoff on a clean cycle

                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=settings.gmail_poll_interval_seconds,
                    )
                    break  # Stop requested during the normal interval wait
                except asyncio.TimeoutError:
                    continue  # Interval elapsed - run the next cycle

            except asyncio.CancelledError:
                raise

            except Exception as e:
                logger.error(
                    "Gmail poll cycle failed unexpectedly - backing off",
                    error=str(e),
                    restart_in_seconds=restart_delay,
                )
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=restart_delay)
                    break
                except asyncio.TimeoutError:
                    pass
                restart_delay = min(restart_delay * 2, _MAX_RESTART_DELAY)

    async def _poll_once(self) -> None:
        """
        Poll every connected Google account once. Each account's failure
        is caught and recorded independently - one user's expired token
        must never stop polling for every other connected account.
        """
        token_repo = get_oauth_token_repository()
        encryption = get_token_encryption_service()
        tokens_list = await token_repo.list_by_provider("google")

        if not tokens_list:
            logger.debug("No connected Gmail accounts to poll")
            return

        for token_record in tokens_list:
            try:
                access_token = encryption.decrypt(token_record.encrypted_access_token)
                refresh_token = (
                    encryption.decrypt(token_record.encrypted_refresh_token)
                    if token_record.encrypted_refresh_token else None
                )
            except ValueError:
                logger.error(
                    "Failed to decrypt Gmail tokens for poll - skipping account",
                    user_id=token_record.user_id,
                )
                continue

            tokens = GmailTokens(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type=token_record.token_type or "Bearer",
                expires_at=token_record.expires_at or datetime.now(timezone.utc),
                scope=token_record.scopes or "",
            )

            try:
                await self._poll_account(token_record.user_id, tokens)
            except Exception as e:
                logger.error(
                    "Gmail poll failed for account - continuing with other accounts",
                    user_id=token_record.user_id,
                    error=str(e),
                )
                try:
                    sync_repo = get_gmail_sync_state_repository()
                    await sync_repo.record_error(token_record.user_id, str(e))
                except Exception:
                    pass

    async def _poll_account(self, user_id: str, tokens: GmailTokens) -> None:
        """
        Poll a single connected account: refresh the token if needed,
        resolve the history_id cursor, fetch new messages since that
        cursor (or seed one on first poll), parse and publish each new
        message, then persist the new cursor.
        """
        oauth_service = get_gmail_oauth_service()

        if tokens.is_expired():
            if not tokens.refresh_token:
                raise RuntimeError("Gmail token expired and no refresh_token stored")
            tokens = await oauth_service.refresh_tokens(tokens.refresh_token)
            # Persist the refreshed token so the next cycle (and any
            # manual API call) sees it too, reusing the same storage path
            # app/api/v1/gmail.py's _refresh_and_store_tokens uses.
            from app.auth import get_user_manager
            user_manager = get_user_manager()
            user = await user_manager.get_user_async(user_id)
            if user:
                await get_oauth_token_repository().store(
                    user_id=user_id,
                    provider="google",
                    access_token=tokens.access_token,
                    refresh_token=tokens.refresh_token,
                    token_type=tokens.token_type,
                    expires_at=tokens.expires_at,
                    scopes=tokens.scope,
                )

        client = GmailClient(tokens)
        sync_repo = get_gmail_sync_state_repository()
        state = await sync_repo.get(user_id)

        if state is None or not state.history_id:
            # First poll for this account: there is no cursor to resume
            # from yet. Seed one from the current profile's historyId -
            # intentionally does NOT backfill the existing mailbox (that
            # would mean "downloading complete mailbox contents on first
            # connect", exactly what this design avoids) - only messages
            # that arrive after this point are picked up automatically.
            profile = await client.get_profile()
            new_history_id = profile.get("historyId")
            if new_history_id:
                await sync_repo.set_history_id(user_id, str(new_history_id))
            logger.info(
                "Gmail poll: seeded initial history cursor (no backfill)",
                user_id=user_id,
                history_id=new_history_id,
            )
            return

        try:
            message_ids = await self._fetch_new_message_ids(client, state.history_id)
        except _HistoryExpiredError:
            logger.warning(
                "Gmail history cursor expired - falling back to bounded "
                "recent-messages listing and reseeding cursor",
                user_id=user_id,
            )
            message_ids = await self._fallback_recent_message_ids(client)
            profile = await client.get_profile()
            new_history_id = profile.get("historyId")
            if new_history_id:
                await sync_repo.set_history_id(user_id, str(new_history_id))
            await self._process_messages(client, user_id, message_ids)
            return

        if message_ids:
            await self._process_messages(client, user_id, message_ids)

        profile = await client.get_profile()
        new_history_id = profile.get("historyId")
        if new_history_id:
            await sync_repo.set_history_id(user_id, str(new_history_id))

        logger.info(
            "Gmail poll cycle complete",
            user_id=user_id,
            new_messages=len(message_ids),
            history_id=new_history_id,
        )

    async def _fetch_new_message_ids(self, client: GmailClient, start_history_id: str) -> list[str]:
        """
        Fetch message IDs added since start_history_id, paging through
        history.list() as needed. Raises _HistoryExpiredError on Gmail's
        404 (cursor too old) so the caller can fall back explicitly.
        """
        message_ids: list[str] = []
        page_token: str | None = None

        while True:
            try:
                data = await client.history_list(
                    start_history_id=start_history_id,
                    page_token=page_token,
                    history_types=["messageAdded"],
                )
            except ValueError as e:
                if "404" in str(e):
                    raise _HistoryExpiredError(str(e)) from e
                raise

            for record in data.get("history", []):
                for added in record.get("messagesAdded", []):
                    msg_id = added.get("message", {}).get("id")
                    if msg_id:
                        message_ids.append(msg_id)

            page_token = data.get("nextPageToken")
            if not page_token:
                break

        return message_ids

    async def _fallback_recent_message_ids(self, client: GmailClient) -> list[str]:
        """
        Bounded fallback when the history cursor has expired: list only
        the most recent N messages rather than the whole mailbox. This
        intentionally may re-process a message already analyzed before
        the cursor expired - that is the accepted, explicit tradeoff
        logged above, not a silent full resync.
        """
        response = await client.list_messages(max_results=_HISTORY_EXPIRED_LOOKBACK_MESSAGES)
        return [m.id for m in response.messages]

    async def _process_messages(
        self, client: GmailClient, user_id: str, message_ids: list[str]
    ) -> None:
        """Parse and publish each new message. One message's parse/publish
        failure is logged and skipped, never aborts the rest of the batch."""
        if not message_ids:
            return

        parser = GmailParser()

        from app.auth import get_user_manager
        user_manager = get_user_manager()
        user = await user_manager.get_user_async(user_id)
        tenant_id = (user.organization_id if user else None) or "admin"

        for message_id in message_ids:
            try:
                message = await client.get_message(message_id, include_raw=True)
                parsed = parser.parse(message)
                analysis_data = parser.to_analysis_request(parsed)

                await publish_email_event(analysis_data, tenant_id=tenant_id, source="gmail")

                logger.info(
                    "Gmail poll: new message published for automatic analysis",
                    user_id=user_id,
                    message_id=message_id,
                )
            except Exception as e:
                logger.warning(
                    "Gmail poll: failed to process one message - skipping",
                    user_id=user_id,
                    message_id=message_id,
                    error=str(e),
                )


class _HistoryExpiredError(Exception):
    """Raised internally when Gmail's history.list() 404s (cursor expired)."""


# Singleton
_gmail_poller: GmailPoller | None = None


def get_gmail_poller() -> GmailPoller:
    """Get the singleton GmailPoller instance."""
    global _gmail_poller
    if _gmail_poller is None:
        _gmail_poller = GmailPoller()
    return _gmail_poller


async def start_gmail_poller() -> None:
    """Start automatic Gmail polling, if enabled in settings."""
    settings = get_settings()
    if not settings.gmail_poll_enabled:
        logger.info("Gmail poller disabled (gmail_poll_enabled=False)")
        return
    await get_gmail_poller().start()


async def stop_gmail_poller() -> None:
    """Stop automatic Gmail polling."""
    await get_gmail_poller().stop()
