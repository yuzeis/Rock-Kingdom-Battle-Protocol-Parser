from __future__ import annotations

import pathlib
import socket
import tempfile
import time
import unittest
import urllib.error
import urllib.request

import Data
import rkpp_network as network
from rkpp_relay import OpcodeRelayServer


class _DummyLogger:
    def log(self, message: str) -> None:
        return


def _reserve_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(url: str, *, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/health", timeout=0.5):
                return
        except Exception as exc:  # pragma: no cover - retry loop
            last_error = exc
            time.sleep(0.05)
    if last_error is not None:
        raise last_error
    raise TimeoutError("relay server did not become ready")


class BoundaryGuardTests(unittest.TestCase):
    def test_parse_key_text_rejects_non_ascii_16char_input(self) -> None:
        with self.assertRaisesRegex(ValueError, "ASCII"):
            network.parse_key_text("\u4e2d" * 16)

    def test_load_key_from_file_ignores_invalid_key_ascii_line(self) -> None:
        key_file = pathlib.Path(tempfile.gettempdir()) / "rkpp_invalid_key_ascii.txt"
        key_file.write_text("key_ascii=" + ("\u4e2d" * 16), encoding="utf-8")
        try:
            self.assertIsNone(network.load_key_from_file(key_file))
        finally:
            key_file.unlink(missing_ok=True)

    def test_data_bundle_reader_returns_empty_dict_on_malformed_json(self) -> None:
        bad_json = pathlib.Path(tempfile.gettempdir()) / "rkpp_bad_bundle.json"
        bad_json.write_text('{"broken": ', encoding="utf-8")
        try:
            self.assertEqual(Data._read_json_dict(bad_json), {})
        finally:
            bad_json.unlink(missing_ok=True)

    def test_relay_latest_invalid_limit_returns_http_400(self) -> None:
        relay = OpcodeRelayServer(
            host="127.0.0.1",
            port=_reserve_local_port(),
            logger=_DummyLogger(),  # type: ignore[arg-type]
        )
        relay.start()
        try:
            _wait_for_server(relay.url)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(relay.url + "/latest?limit=bad", timeout=1).read()
            self.assertEqual(cm.exception.code, 400)
        finally:
            relay.close()


if __name__ == "__main__":
    unittest.main()
