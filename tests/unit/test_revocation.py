"""Unit tests for ``RevocationStore`` — fake Redis, no network.

These tests deliberately bypass ``AuthService`` and the router. The store is
the only piece of the revocation feature with interesting I/O behaviour
(TTLs, key shapes, no-op guards); policy (which user, what TTL) is exercised
by the e2e suite through real HTTP.
"""

import asyncio
import uuid

from queuepass.modules.auth.revocation import RevocationStore


async def test_revoke_jti_marks_revoked(fake_revocation_store: RevocationStore) -> None:
    await fake_revocation_store.revoke_jti("abc", 60)
    assert await fake_revocation_store.is_jti_revoked("abc") is True


async def test_unknown_jti_not_revoked(fake_revocation_store: RevocationStore) -> None:
    assert await fake_revocation_store.is_jti_revoked("never-seen") is False


async def test_revoke_jti_with_zero_or_negative_ttl_is_noop(
    fake_revocation_store: RevocationStore,
) -> None:
    await fake_revocation_store.revoke_jti("zero", 0)
    await fake_revocation_store.revoke_jti("neg", -10)
    assert await fake_revocation_store.is_jti_revoked("zero") is False
    assert await fake_revocation_store.is_jti_revoked("neg") is False


async def test_revoke_jti_ttl_expires(fake_revocation_store: RevocationStore) -> None:
    # fakeredis honours real wall-clock for SETEX expiry, so a 1-second TTL is
    # the simplest way to observe the expiry path. Slightly over 1s keeps this
    # reliable across machines; the point is that expiry actually happens.
    await fake_revocation_store.revoke_jti("short-lived", 1)
    assert await fake_revocation_store.is_jti_revoked("short-lived") is True
    await asyncio.sleep(1.2)
    assert await fake_revocation_store.is_jti_revoked("short-lived") is False


async def test_set_user_cutoff_stores_epoch(fake_revocation_store: RevocationStore) -> None:
    await fake_revocation_store.set_user_cutoff("u1", 1_700_000_000, 60)
    assert await fake_revocation_store.get_user_cutoff("u1") == 1_700_000_000


async def test_set_user_cutoff_with_zero_ttl_is_noop(
    fake_revocation_store: RevocationStore,
) -> None:
    await fake_revocation_store.set_user_cutoff("u2", 1_700_000_000, 0)
    assert await fake_revocation_store.get_user_cutoff("u2") is None


async def test_unknown_user_cutoff_returns_none(fake_revocation_store: RevocationStore) -> None:
    assert await fake_revocation_store.get_user_cutoff("nobody") is None


async def test_uuid_string_as_user_id_works(fake_revocation_store: RevocationStore) -> None:
    # The cutoff key embeds the id verbatim — verify a real UUID round-trips
    # through the string. This locks in the UUID-string key format against
    # regressions where someone "helpfully" switches to ``uuid.hex`` or similar.
    user_id = str(uuid.uuid4())
    await fake_revocation_store.set_user_cutoff(user_id, 12_345, 60)
    assert await fake_revocation_store.get_user_cutoff(user_id) == 12_345
