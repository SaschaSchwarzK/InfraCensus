import asyncio

import pytest

from central.core.rate_limit import CollectorRateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_allows_within_limit():
    limiter = CollectorRateLimiter(max_per_hour=10)
    for _ in range(10):
        assert await limiter.allow("key1")
    assert not await limiter.allow("key1")


@pytest.mark.asyncio
async def test_rate_limiter_window_reset():
    limiter = CollectorRateLimiter(max_per_hour=1)
    assert await limiter.allow("key1")
    assert not await limiter.allow("key1")


@pytest.mark.asyncio
async def test_rate_limiter_concurrent_safety():
    limiter = CollectorRateLimiter(max_per_hour=100)
    results = await asyncio.gather(*[limiter.allow("key1") for _ in range(100)])
    assert sum(results) == 100
