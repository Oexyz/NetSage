from pathlib import Path

import pytest

from netsage.drivers.fortios import SSHHostKeyPin
from netsage.state import (
    DuplicateSSHTrustError,
    LocalState,
    SSHHostIdentityChangedError,
    SSHHostTrustManager,
    SSHTrustBindingError,
    SSHTrustNotFoundError,
    StatePaths,
)


def pin(
    *, fingerprint: str, public_key: bytes = b"ssh-ed25519 synthetic-public-key\n"
) -> SSHHostKeyPin:
    return SSHHostKeyPin(
        algorithm="ssh-ed25519",
        fingerprint=fingerprint,
        known_hosts_data=b"fortigate.example.test " + public_key,
    )


@pytest.mark.asyncio
async def test_first_trust_persists_fingerprint_and_later_match_is_reused(
    tmp_path: Path,
) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    discovered = pin(fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    calls: list[tuple[str, int]] = []

    async def discover(host: str, port: int) -> SSHHostKeyPin:
        calls.append((host, port))
        return discovered

    manager = SSHHostTrustManager(state.host_trust, discovery=discover)
    reviewed = await manager.discover("fortigate.example.test", 22)
    manager.trust_first(
        name="fortigate-example",
        host="fortigate.example.test",
        port=22,
        pin=reviewed,
    )
    verified = await manager.verify(
        name="fortigate-example",
        host="fortigate.example.test",
        port=22,
    )

    assert verified is discovered
    assert calls == [
        ("fortigate.example.test", 22),
        ("fortigate.example.test", 22),
    ]
    stored = state.host_trust.get("fortigate-example")
    assert stored.fingerprint == discovered.fingerprint
    serialized = state.paths.host_trust.read_text(encoding="utf-8")
    assert "synthetic-public-key" not in serialized
    assert "known_hosts_data" not in serialized


@pytest.mark.asyncio
async def test_changed_host_key_is_rejected_and_never_silently_replaced(
    tmp_path: Path,
) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    original = pin(fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    changed = pin(fingerprint="SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")

    async def discover(_host: str, _port: int) -> SSHHostKeyPin:
        return changed

    manager = SSHHostTrustManager(state.host_trust, discovery=discover)
    manager.trust_first(
        name="fortigate-example",
        host="192.0.2.10",
        port=22,
        pin=original,
    )
    with pytest.raises(SSHHostIdentityChangedError) as captured:
        await manager.verify(name="fortigate-example", host="192.0.2.10", port=22)

    assert captured.value.expected_fingerprint == original.fingerprint
    assert captured.value.received_fingerprint == changed.fingerprint
    assert state.host_trust.get("fortigate-example").fingerprint == original.fingerprint


@pytest.mark.asyncio
async def test_missing_trust_and_changed_address_fail_before_discovery(tmp_path: Path) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    calls = 0

    async def discover(_host: str, _port: int) -> SSHHostKeyPin:
        nonlocal calls
        calls += 1
        return pin(fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

    manager = SSHHostTrustManager(state.host_trust, discovery=discover)
    with pytest.raises(SSHTrustNotFoundError):
        await manager.verify(name="missing", host="192.0.2.10", port=22)

    manager.trust_first(
        name="fortigate-example",
        host="192.0.2.10",
        port=22,
        pin=await manager.discover("192.0.2.10", 22),
    )
    with pytest.raises(SSHTrustBindingError):
        await manager.verify(name="fortigate-example", host="192.0.2.11", port=22)
    assert calls == 1


def test_explicit_replace_changes_trust_and_duplicate_first_trust_is_rejected(
    tmp_path: Path,
) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    original = pin(fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    replacement = pin(fingerprint="SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    manager = SSHHostTrustManager(state.host_trust)
    manager.trust_first(
        name="fortigate-example",
        host="192.0.2.10",
        port=22,
        pin=original,
    )
    with pytest.raises(DuplicateSSHTrustError):
        manager.trust_first(
            name="fortigate-example",
            host="192.0.2.10",
            port=22,
            pin=replacement,
        )

    manager.replace(
        name="fortigate-example",
        host="192.0.2.10",
        port=22,
        pin=replacement,
    )
    assert state.host_trust.get("fortigate-example").fingerprint == replacement.fingerprint
