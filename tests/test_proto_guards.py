from __future__ import annotations

import unittest

import rkpp_analysis as analysis
import rkpp_proto as proto


class ProtoGuardTests(unittest.TestCase):
    def test_strip_tsf4g_padding_accepts_legacy_marker_suffix(self) -> None:
        self.assertEqual(proto.strip_tsf4g_padding(b"abc" + b"tsf4g\x06"), b"abc")

    def test_strip_tsf4g_padding_accepts_variable_length_tsf4g_trailer(self) -> None:
        self.assertEqual(
            proto.strip_tsf4g_padding(bytes.fromhex("0a020800637ca939bb31aa5a43994518747366346712")),
            bytes.fromhex("0a020800"),
        )

    def test_strip_tsf4g_padding_accepts_short_variable_length_tsf4g_trailer(self) -> None:
        self.assertEqual(
            proto.strip_tsf4g_padding(bytes.fromhex("2ded747366346708")),
            b"",
        )

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

    def test_normalize_c2s_opcode_strips_0001_prefix(self) -> None:
        self.assertEqual(proto.normalize_c2s_opcode(0x000101A9), (0x01A9, True))
        self.assertEqual(proto.normalize_c2s_opcode(0x000001A9), (0x01A9, False))

    def test_parse_record_handles_binary_heartbeat_notify(self) -> None:
        packet = {
            "cmd": 0x4013,
            "direction": "s2c",
            "seq": 666,
            "first_frame": 18,
            "first_time": 0.0,
            "decrypted_body_hex": "0000013d55aa00000000060000000000000064000000f7aed7a674736634670a",
        }
        record = proto.parse_record(packet)
        self.assertIsNotNone(record)
        self.assertEqual(record["opcode"], 0x013D)
        self.assertEqual(record["payload_trailer_len"], 10)
        self.assertTrue(record["root"]["clean"])
        self.assertEqual(
            record["special_payload"],
            {"heartbeat_seq": 6, "server_logic_tick_ivl": 100},
        )

    def test_decode_record_uses_special_binary_payload(self) -> None:
        packet = {
            "cmd": 0x4013,
            "direction": "s2c",
            "seq": 668,
            "first_frame": 22,
            "first_time": 0.0,
            "decrypted_body_hex": "0000013f55aa000000000000000006000000000000007c1b7d7b9d0100002d00000031000000481b7d7b9d01000000000000fa81392e6b40284074736634670e",
        }
        record = proto.parse_record(packet)
        self.assertIsNotNone(record)
        decoded = analysis.decode_record(record)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["message_name"], "ZoneSceneHeartbeatResultNty")
        self.assertEqual(decoded["decoded"]["ret_info"]["ret_code"], 0)
        self.assertEqual(decoded["decoded"]["heartbeat_seq"], 6)
        self.assertEqual(decoded["decoded"]["trans_delay_time"], 45)
        self.assertEqual(decoded["decoded"]["avg_trans_delay_time"], 49)


if __name__ == "__main__":
    unittest.main()
