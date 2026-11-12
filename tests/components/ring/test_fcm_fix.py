"""Tests for the firebase-messaging runtime fix used by the Ring listener."""

from base64 import urlsafe_b64encode
import binascii
import json
import os
from typing import Any
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from firebase_messaging import FcmPushClient, FcmRegisterConfig
from firebase_messaging.fcmregister import FcmRegister
from firebase_messaging.proto.mcs_pb2 import DataMessageStanza  # pylint: disable=no-name-in-module
import http_ece
import pytest
from pytest_homeassistant.common import MockConfigEntry

from homeassistant.components.ring import fcm_fix
from homeassistant.config_entries import ConfigEntryState

# Captured at collection time, before any test set up the integration.
ORIGINAL_HANDLE_DATA_MESSAGE = FcmPushClient.__dict__["_handle_data_message"]
ORIGINAL_DECRYPT_RAW_DATA = FcmPushClient.__dict__["_decrypt_raw_data"]

APP_ID = "com.ring.test"
PERSISTENT_ID = "0:1762790000000000%abc"
PAYLOAD = {"data": {"gcmData": '{"ding": {"id": 1, "doorbot_id": 42}}'}}
VAPID_KEY = (
    "BDd3_hVL9fZi9Ybo2UUzA284WG5FZR30_95YeZJsiApwXKpNcF1rRPF3foIiBHXRdJI2"
    "Qhumhf6_LFTeZaNndIo"
)

# (crypto-key header, encryption header) as sent by FCM.
HEADERS = {
    "legacy_padded": ("dh={dh_padded}", "salt={salt_padded}"),
    "vapid_multi_param": (f"dh={{dh}}; p256ecdsa={VAPID_KEY}", "salt={salt}"),
    "unpadded": ("dh={dh}", "salt={salt}"),
    "reordered": (f"p256ecdsa={VAPID_KEY};dh={{dh}}", "rs=4096;salt={salt}"),
}


def _b64(data: bytes, *, pad: bool) -> str:
    encoded = urlsafe_b64encode(data).decode()
    return encoded if pad else encoded.rstrip("=")


def _credentials() -> dict[str, Any]:
    keys = FcmRegister(FcmRegisterConfig("p", "a", "k", 1)).generate_keys()
    return {"keys": keys, "gcm": {"app_id": APP_ID}}


def _message(
    credentials: dict[str, Any], crypto_key_header: str, salt_header: str
) -> DataMessageStanza:
    """Build a data message encrypted for the client like FCM does."""
    private_key = serialization.load_der_private_key(
        fcm_fix.b64url_decode(credentials["keys"]["private"]), password=None
    )
    receiver_public = private_key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    sender = ec.generate_private_key(ec.SECP256R1())
    sender_public = sender.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    salt = os.urandom(16)
    raw_data = http_ece.encrypt(
        json.dumps(PAYLOAD).encode(),
        salt=salt,
        private_key=sender,
        dh=receiver_public,
        auth_secret=fcm_fix.b64url_decode(credentials["keys"]["secret"]),
        version="aesgcm",
    )
    msg = DataMessageStanza(
        persistent_id=PERSISTENT_ID, raw_data=raw_data, category="x"
    )
    app_data = {
        "crypto-key": crypto_key_header.format(
            dh=_b64(sender_public, pad=False), dh_padded=_b64(sender_public, pad=True)
        ),
        "encryption": salt_header.format(
            salt=_b64(salt, pad=False), salt_padded=_b64(salt, pad=True)
        ),
        "subtype": APP_ID,
    }
    for key, value in app_data.items():
        item = msg.app_data.add()
        item.key = key
        item.value = value
    return msg


def _client(credentials: dict[str, Any], received: list[dict]) -> FcmPushClient:
    client = FcmPushClient(
        lambda data, persistent_id, ctx: received.append(data),
        FcmRegisterConfig("p", "a", "k", 1),
        credentials,
    )
    client._send_selective_ack = AsyncMock()  # type: ignore[method-assign]
    return client


@pytest.fixture
def stock_client_class(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make FcmPushClient use the unpatched library code during the test."""
    monkeypatch.setattr(
        FcmPushClient, "_handle_data_message", ORIGINAL_HANDLE_DATA_MESSAGE
    )
    monkeypatch.setattr(FcmPushClient, "_decrypt_raw_data", ORIGINAL_DECRYPT_RAW_DATA)
    monkeypatch.setattr(FcmPushClient, fcm_fix._PATCH_MARKER, False, raising=False)


@pytest.fixture
def patched_client_class(stock_client_class: None) -> None:
    """Apply the fix; the library is restored after the test."""
    fcm_fix.apply()


@pytest.mark.usefixtures("stock_client_class")
async def test_stock_library_crashes_on_vapid_header() -> None:
    """Reproduce home-assistant/core#191852 with the unpatched library."""
    credentials, received = _credentials(), []
    client = _client(credentials, received)

    with pytest.raises(binascii.Error, match="Incorrect padding"):
        await client._handle_message(
            _message(credentials, *HEADERS["vapid_multi_param"])
        )

    # The message is never acknowledged, so MCS replays it on the next login.
    client._send_selective_ack.assert_not_called()
    assert client.persistent_ids == []
    assert received == []


@pytest.mark.usefixtures("stock_client_class")
async def test_stock_library_handles_legacy_header() -> None:
    """The old padded single parameter header works without the fix."""
    credentials, received = _credentials(), []
    client = _client(credentials, received)

    await client._handle_message(_message(credentials, *HEADERS["legacy_padded"]))

    assert received == [PAYLOAD]


@pytest.mark.usefixtures("patched_client_class")
@pytest.mark.parametrize("variant", list(HEADERS))
async def test_patched_decrypts_all_header_shapes(variant: str) -> None:
    """All known header shapes are decrypted and delivered."""
    credentials, received = _credentials(), []
    client = _client(credentials, received)

    await client._handle_message(_message(credentials, *HEADERS[variant]))

    assert received == [PAYLOAD]
    client._send_selective_ack.assert_awaited_once_with(PERSISTENT_ID)
    assert client.persistent_ids == [PERSISTENT_ID]


@pytest.mark.usefixtures("patched_client_class")
async def test_patched_skips_and_acks_undecryptable_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A message that cannot be decrypted does not stop the client."""
    credentials, received = _credentials(), []
    client = _client(credentials, received)
    # Encrypted for different keys -> authentication of the payload fails.
    foreign = _message(_credentials(), *HEADERS["vapid_multi_param"])

    await client._handle_message(foreign)

    assert received == []
    client._send_selective_ack.assert_awaited_once_with(PERSISTENT_ID)
    assert "Unable to decrypt FCM data message" in caplog.text

    await client._handle_message(_message(credentials, *HEADERS["vapid_multi_param"]))
    assert received == [PAYLOAD]


@pytest.mark.usefixtures("patched_client_class")
@pytest.mark.parametrize(
    ("crypto_key_header", "salt_header"),
    [
        (f"p256ecdsa={VAPID_KEY}", "salt=AAAA"),
        ("dh=AAAA", "salt=!!"),
        ("dh=", "rs=4096"),
    ],
)
async def test_patched_skips_garbage_headers(
    crypto_key_header: str, salt_header: str
) -> None:
    """Broken headers are logged and acknowledged instead of raising."""
    credentials, received = _credentials(), []
    client = _client(credentials, received)

    await client._handle_message(_message(credentials, crypto_key_header, salt_header))

    assert received == []
    client._send_selective_ack.assert_awaited_once_with(PERSISTENT_ID)


@pytest.mark.parametrize(
    ("header", "name", "expected"),
    [
        ("dh=abc", "dh", "abc"),
        ("dh=abc; p256ecdsa=def", "dh", "abc"),
        ("p256ecdsa=def;dh=abc", "dh", "abc"),
        ("dh=abc, p256ecdsa=def", "p256ecdsa", "def"),
        ("DH=abc==", "dh", "abc=="),
        ("salt=xyz", "salt", "xyz"),
        ("abc==", "dh", "abc=="),
    ],
)
def test_webpush_header_param(header: str, name: str, expected: str) -> None:
    """Parameters are selected by name."""
    assert fcm_fix.webpush_header_param(header, name) == expected


def test_webpush_header_param_missing() -> None:
    """A header without the requested parameter raises ValueError."""
    with pytest.raises(ValueError, match="'dh' not found"):
        fcm_fix.webpush_header_param("p256ecdsa=def", "dh")


@pytest.mark.parametrize("value", ["YWJj", "YWI", "YQ", "YWI=", " YQ== "])
def test_b64url_decode_tolerates_missing_padding(value: str) -> None:
    """Padding is restored before decoding."""
    assert fcm_fix.b64url_decode(value) in (b"abc", b"ab", b"a")


@pytest.mark.usefixtures("stock_client_class")
def test_apply_is_idempotent() -> None:
    """Applying twice keeps the patched methods."""
    fcm_fix.apply()
    fcm_fix.apply()

    assert FcmPushClient.__dict__["_handle_data_message"] is (
        fcm_fix.handle_data_message
    )
    assert FcmPushClient._decrypt_raw_data is fcm_fix.decrypt_raw_data


@pytest.mark.usefixtures("stock_client_class")
def test_apply_skips_unknown_library_version(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A different library version is left untouched."""
    with patch.object(fcm_fix, "version", return_value="0.5.0"):
        fcm_fix.apply()

    assert FcmPushClient.__dict__["_handle_data_message"] is (
        ORIGINAL_HANDLE_DATA_MESSAGE
    )
    assert "Ring FCM fix not applied: firebase-messaging 0.5.0" in caplog.text


async def test_setup_entry_applies_fix(
    stock_client_class: None,
    mock_ring_client: Any,
    mock_added_config_entry: MockConfigEntry,
) -> None:
    """Setting up the integration patches the library."""
    assert mock_added_config_entry.state is ConfigEntryState.LOADED
    assert FcmPushClient.__dict__["_handle_data_message"] is (
        fcm_fix.handle_data_message
    )
