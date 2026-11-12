"""Runtime fix for firebase-messaging 0.4.5 used by the Ring event listener.

TEST BUILD ONLY - this patches a third-party library at runtime.

firebase-messaging 0.4.5 has two defects that together stop all Ring realtime
events (ding / motion / intercom unlock), see home-assistant/core#191852 and
sdb9696/firebase-messaging#40 / #44:

1. The Web Push headers are sliced by position (``crypto-key[3:]`` and
   ``encryption[5:]``) and decoded without restoring base64 padding. Pushes
   now arrive as ``dh=<unpadded base64url>; p256ecdsa=<...>`` which raises
   ``binascii.Error: Incorrect padding``.
2. Any exception while handling a data message escapes the read loop and
   shuts down the whole FcmPushClient. The message is never acknowledged, so
   it is replayed after every login and the client dies again right away.

The fix selects header parameters by name, tolerates missing padding and
isolates failures per message, so a message that cannot be decrypted is
logged, acknowledged and skipped instead of terminating the client.
"""

# pylint: disable=protected-access

from base64 import urlsafe_b64decode
from importlib.metadata import PackageNotFoundError, version
import json
import logging
from typing import Any

from firebase_messaging import fcmpushclient
from firebase_messaging.fcmpushclient import ErrorType, FcmPushClient
from firebase_messaging.proto.mcs_pb2 import DataMessageStanza  # pylint: disable=no-name-in-module

_LOGGER = logging.getLogger(__name__)

PATCHED_VERSIONS = {"0.4.5"}
_PATCH_MARKER = "_ha_ring_webpush_fix"


def b64url_decode(value: str) -> bytes:
    """Decode base64url, restoring the padding that Web Push strips."""
    value = value.strip()
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def webpush_header_param(header: str, name: str) -> str:
    """Return parameter ``name`` from a Web Push header like ``a=1; b=2``.

    The order of parameters does not matter, ``,`` is accepted as separator
    and a bare value without any ``name=`` prefix is returned unchanged.
    """
    params = [p.strip() for p in header.replace(",", ";").split(";") if p.strip()]
    for param in params:
        key, sep, val = param.partition("=")
        if sep and key.strip().lower() == name:
            return val.strip().strip('"')
    if len(params) == 1 and "=" not in params[0].rstrip("="):
        return params[0]
    raise ValueError(f"Parameter {name!r} not found in Web Push header {header!r}")


def decrypt_raw_data(
    credentials: dict[str, dict[str, str]],
    crypto_key_str: str,
    salt_str: str,
    raw_data: bytes,
) -> bytes:
    """Decrypt an aesgcm encrypted FCM payload."""
    privkey = fcmpushclient.load_der_private_key(
        b64url_decode(credentials["keys"]["private"]),
        password=None,
        backend=fcmpushclient.default_backend(),
    )
    decrypted: bytes = fcmpushclient.http_decrypt(
        raw_data,
        salt=b64url_decode(salt_str),
        private_key=privkey,
        dh=b64url_decode(crypto_key_str),
        version="aesgcm",
        auth_secret=b64url_decode(credentials["keys"]["secret"]),
    )
    return decrypted


def handle_data_message(self: FcmPushClient, msg: DataMessageStanza) -> None:
    """Replacement for FcmPushClient._handle_data_message that never raises."""
    _LOGGER.debug(
        "Received data message Stream ID: %s, Last: %s, Status: %s",
        msg.stream_id,
        msg.last_stream_id_received,
        msg.status,
    )
    if (
        self._app_data_by_key(msg, "message_type", do_not_raise=True)
        == "deleted_messages"
    ):
        # The deleted_messages message does not contain data.
        return
    if not self.credentials:
        return

    subtype = self._app_data_by_key(msg, "subtype", do_not_raise=True)
    if subtype != self.credentials["gcm"]["app_id"]:
        self._log_warn_with_limit(
            "Subtype %s in data message does not match "
            "app id client was registered with %s",
            subtype,
            self.credentials["gcm"]["app_id"],
        )

    try:
        crypto_key = webpush_header_param(
            self._app_data_by_key(msg, "crypto-key"), "dh"
        )
        salt = webpush_header_param(self._app_data_by_key(msg, "encryption"), "salt")
        decrypted = decrypt_raw_data(self.credentials, crypto_key, salt, msg.raw_data)
    except Exception:  # one bad message must not stop the client
        _LOGGER.warning(
            "Unable to decrypt FCM data message %s, skipping it",
            msg.persistent_id,
            exc_info=True,
        )
        return

    decrypted_json: Any = None
    try:
        decrypted_json = json.loads(decrypted.decode("utf-8"))
    except ValueError:
        self._log_warn_with_limit(
            "Failed to decrypt data for message %s", msg.persistent_id
        )

    ret_val: Any = decrypted_json or decrypted
    self._log_verbose("Data for message %s is: %s", msg.persistent_id, ret_val)
    if not isinstance(ret_val, dict):
        ret_val = {"message": ret_val}
    try:
        self.callback(ret_val, msg.persistent_id, self.callback_context)
        self._reset_error_count(ErrorType.NOTIFY)
    except Exception:
        _LOGGER.exception("Unexpected exception calling notification callback")
        self._try_increment_error_count(ErrorType.NOTIFY)


def apply() -> None:
    """Patch FcmPushClient in place. Safe to call more than once."""
    if getattr(FcmPushClient, _PATCH_MARKER, False):
        return
    try:
        installed = version("firebase-messaging")
    except PackageNotFoundError:
        installed = "unknown"
    if installed not in PATCHED_VERSIONS:
        _LOGGER.warning(
            "Ring FCM fix not applied: firebase-messaging %s is installed, "
            "fix targets %s",
            installed,
            ", ".join(sorted(PATCHED_VERSIONS)),
        )
        return
    FcmPushClient._decrypt_raw_data = staticmethod(decrypt_raw_data)  # type: ignore[method-assign]  # noqa: SLF001
    FcmPushClient._handle_data_message = handle_data_message  # type: ignore[method-assign]  # noqa: SLF001
    setattr(FcmPushClient, _PATCH_MARKER, True)
    _LOGGER.info(
        "Applied Ring FCM Web Push header fix to firebase-messaging %s", installed
    )
