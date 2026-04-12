from __future__ import annotations

import unittest

import rkbpp_proto as proto


class ProtoGuardTests(unittest.TestCase):
    def test_strip_tsf4g_padding_accepts_legacy_marker_suffix(self) -> None:
        self.assertEqual(proto.strip_tsf4g_padding(b"abc" + b"tsf4g\x06"), b"abc")

    def test_strip_tsf4g_padding_accepts_marker_plus_single_byte_padding(self) -> None:
        self.assertEqual(proto.strip_tsf4g_padding(b"abc" + b"tsf4g\x01"), b"abc" + b"tsf4g")

    def test_strip_tsf4g_padding_rejects_large_pad_value(self) -> None:
        data = b"abc" + b"tsf4g" + b"\xc8"
        self.assertEqual(proto.strip_tsf4g_padding(data), data)

    def test_strip_tsf4g_padding_rejects_invalid_padding_bytes(self) -> None:
        data = b"abc" + b"tsf4g\x06"
        tampered = data[:-6] + b"\x06\x06\x06\x06\x05\x06"
        self.assertEqual(proto.strip_tsf4g_padding(tampered), tampered)

    def test_strip_tsf4g_padding_ignores_missing_marker(self) -> None:
        data = b"payload" + b"\x04" * 4
        self.assertEqual(proto.strip_tsf4g_padding(data), data)

    def test_extract_130c_result_returns_none_when_all_fields_missing(self) -> None:
        record = {"opcode": 0x130C, "opcode_hex": "0x130C", "root": {"fields": []}}
        self.assertIsNone(proto.extract_130c_result(record))


if __name__ == "__main__":
    unittest.main()
