import logging
import time

import httpx

log = logging.getLogger("vulnwatch.http")


class FetchError(Exception):
    """Raised when a source fetch fails after bounded retries."""


def fetch(
    client: httpx.Client,
    url: str,
    *,
    retries: int,
    timeout: float,
    backoff: float,
    expect_json: bool = True,
) -> httpx.Response:
    """GET with bounded retries. Raises FetchError on final failure."""
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            resp = client.get(url, timeout=timeout)
            if resp.status_code in (429, 503):
                raise httpx.HTTPStatusError(
                    "rate limited", request=resp.request, response=resp
                )
            resp.raise_for_status()
            if expect_json:
                resp.json()  # validate parse before returning (cheap sanity check)
            return resp
        except Exception as exc:  # noqa: BLE001 - bounded, logged, re-raised at end
            last = exc
            wait = backoff * attempt
            log.warning("fetch attempt %d/%d failed for %s: %r", attempt, retries, url, exc)
            if attempt < retries:
                time.sleep(wait)
    raise FetchError(f"failed to fetch {url}: {last!r}") from last
