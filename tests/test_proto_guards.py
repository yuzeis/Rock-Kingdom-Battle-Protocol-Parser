from __future__ import annotations

import unittest

import rkpp_analysis as analysis
import rkpp_proto as proto
import rkpp_proto_battle as proto_battle


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

    def test_extract_1324_action_uses_shared_perform_parser(self) -> None:
        record = {
            "opcode": 0x1324,
            "opcode_hex": "0x1324",
            "root": {"fields": [{"field": 1, "sub": {"fields": []}}]},
        }
        original = proto_battle._extract_perform_cmd
        proto_battle._extract_perform_cmd = lambda container, rec: {"delegated": True, "opcode": rec["opcode"]}
        try:
            self.assertEqual(
                proto.extract_1324_action(record),
                {"delegated": True, "opcode": 0x1324},
            )
        finally:
            proto_battle._extract_perform_cmd = original

    def test_battle_enter_prefers_schema_postprocess(self) -> None:
        record = {
            "opcode": 0x1316,
            "opcode_hex": "0x1316",
            "seq": 1,
            "root": {"fields": []},
            "_message_name": "ZoneBattleEnterNotify",
            "_schema_found": True,
            "_decoded": {
                "battle_mode": 7,
                "round": 1,
                "npc_id": [1001, 1002],
                "is_reconnect": True,
                "weather_expire_round": 4,
                "init_info": {
                    "battle_id": 123456,
                    "battle_cfg_id": [7001, 7002],
                    "battle_state": {"value": 9, "name": "BATTLEFIELD_STATE_ROUND_FIGHT"},
                },
            },
        }

        detail = proto.extract_1316_enter(record)

        self.assertEqual(detail["parse_quality"], "schema_postprocess")
        self.assertEqual(detail["battle_id"], 123456)
        self.assertEqual(detail["battle_cfg_id"], 7001)
        self.assertEqual(detail["battle_cfg_ids"], [7001, 7002])
        self.assertEqual(detail["npc_id"], 1001)
        self.assertEqual(detail["npc_ids"], [1001, 1002])
        self.assertEqual(detail["battle_state_name"], "BATTLEFIELD_STATE_ROUND_FIGHT")

    def test_round_start_prefers_schema_postprocess(self) -> None:
        record = {
            "opcode": 0x131A,
            "opcode_hex": "0x131A",
            "seq": 2,
            "root": {"fields": []},
            "_message_name": "ZoneBattleRoundStartNotify",
            "_schema_found": True,
            "_decoded": {
                "state_type": {"value": 1, "name": "BATTLE_STATE_SELECT_CMD"},
                "state_info": {
                    "battle_id": 123456,
                    "round": 3,
                    "series_index": 4,
                    "npc_escape": [9],
                },
                "perform_cmd": {
                    "is_battle_finished": False,
                    "round": 3,
                    "seq_num": 99,
                },
            },
        }

        detail = proto.extract_131a_round_start(record)

        self.assertEqual(detail["parse_quality"], "schema_postprocess")
        self.assertEqual(detail["state_type"], 1)
        self.assertEqual(detail["state_type_name"], "BATTLE_STATE_SELECT_CMD")
        self.assertEqual(detail["battle_id"], 123456)
        self.assertEqual(detail["npc_escape"], 9)
        self.assertTrue(detail["has_perform"])
        self.assertEqual(detail["perform_seq_num"], 99)

    def test_battle_finish_prefers_schema_postprocess(self) -> None:
        record = {
            "opcode": 0x132C,
            "opcode_hex": "0x132C",
            "seq": 3,
            "root": {"fields": []},
            "_message_name": "ZoneBattleFinishNotify",
            "_schema_found": True,
            "_decoded": {
                "settle_info": {
                    "result": {"value": 2, "name": "TRUE_BATTLE_RESULT_WIN"},
                    "battle_conf_id": 7001,
                    "battle_id": 123456,
                    "rounds": 5,
                    "seconds": 42,
                },
                "seen_monster_id": [3001],
                "ret_info": {"ret_code": 0, "ret_msg": "ok"},
                "pet_info": [{"pet_gid": 11, "remain_hp": 20, "remain_energy": 8, "battle_max_hp": 30}],
            },
        }

        detail = proto.extract_132c_finish(record)

        self.assertEqual(detail["parse_quality"], "schema_postprocess")
        self.assertEqual(detail["result_code"], 2)
        self.assertEqual(detail["result_name"], "WIN")
        self.assertEqual(detail["result_enum_name"], "TRUE_BATTLE_RESULT_WIN")
        self.assertEqual(detail["battle_id"], 123456)
        self.assertEqual(detail["seen_monster_ids"], [3001])
        self.assertEqual(detail["finish_pet_infos"][0]["remain_hp"], 20)

    def test_round_flow_marks_raw_quality_when_schema_is_absent(self) -> None:
        record = {
            "opcode": 0x1312,
            "opcode_hex": "0x1312",
            "seq": 4,
            "root": {"fields": [{"field": 1, "wire": 0, "value": 8}]},
        }

        detail = proto.extract_1312_round_flow(record)

        self.assertEqual(detail["parse_quality"], "raw_field_postprocess")
        self.assertEqual(detail["semantic_level"], "raw_field_dump_with_wrappers")
        self.assertEqual(detail["schema_message"], "ZoneBattleRoundFlowNotify")
        self.assertEqual(detail["field_1"], 8)

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
        self.assertEqual(record["transport_layout"], "tgcp_4013_live_s2c")
        self.assertEqual(record["opcode"], 0x013D)
        self.assertEqual(record["magic_hex"], "0x55AA")
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

    def test_parse_record_handles_live_c2s_layout(self) -> None:
        packet = {
            "cmd": 0x4013,
            "direction": "c2s",
            "seq": 99,
            "first_frame": 29,
            "first_time": 0.0,
            "decrypted_body_hex": (
                "3b4986e8"
                "000103dc"
                "3963"
                "00000007"
                "08ce8a71"
            ),
        }
        record = proto.parse_record(packet)
        self.assertIsNotNone(record)
        self.assertEqual(record["transport_layout"], "tgcp_4013_live_c2s")
        self.assertEqual(record["transport_seq"], 0x3B4986E8)
        self.assertEqual(record["prefix_u32_hex"], "0x3B4986E8")
        self.assertEqual(record["raw_opcode_hex"], "0x000103DC")
        self.assertEqual(record["opcode"], 0x03DC)
        self.assertTrue(record["opcode_normalized"])
        self.assertEqual(record["magic_hex"], "0x3963")
        self.assertEqual(record["req_seq"], 7)
        self.assertEqual(record["root"]["fields"][0]["field"], 1)
        self.assertEqual(record["root"]["fields"][0]["value"], 1852750)

    def test_parse_record_handles_live_c2s_short_heartbeat_layout(self) -> None:
        packet = {
            "cmd": 0x4013,
            "direction": "c2s",
            "seq": 15,
            "first_frame": 25,
            "first_time": 0.0,
            "decrypted_body_hex": "000000400000013e000000000000010000000000000000000000747366346706",
        }
        record = proto.parse_record(packet)
        self.assertIsNotNone(record)
        self.assertEqual(record["transport_layout"], "tgcp_4013_live_c2s_short_heartbeat")
        self.assertEqual(record["transport_seq"], 0x40)
        self.assertEqual(record["opcode"], 0x013E)
        self.assertEqual(record["req_seq"], 1)
        self.assertEqual(record["payload_len"], 0)

    def test_parse_record_prefers_v14_c2s_layout(self) -> None:
        packet = {
            "cmd": 0x4013,
            "direction": "c2s",
            "seq": 100,
            "first_frame": 30,
            "first_time": 0.0,
            "decrypted_body_hex": (
                "00000001"
                "55aa"
                "0000001e"
                "0000"
                "00000001"
                "00401001"
                "000103dc"
                "3963"
                "00000007"
                "08ce8a71"
            ),
        }
        record = proto.parse_record(packet)
        self.assertIsNotNone(record)
        self.assertEqual(record["transport_layout"], "tgcp_4013_v14")
        self.assertEqual(record["transport_seq"], 1)
        self.assertEqual(record["session_id_hex"], "0x00401001")
        self.assertEqual(record["sub_id_hex"], "0x000103DC")
        self.assertEqual(record["opcode"], 0x03DC)
        self.assertTrue(record["opcode_normalized"])
        self.assertEqual(record["req_seq"], 7)
        self.assertEqual(record["payload_len"], 4)
        self.assertEqual(record["root"]["fields"][0]["field"], 1)
        self.assertEqual(record["root"]["fields"][0]["value"], 1852750)

    def test_parse_record_prefers_v14_s2c_layout(self) -> None:
        packet = {
            "cmd": 0x4013,
            "direction": "s2c",
            "seq": 101,
            "first_frame": 31,
            "first_time": 0.0,
            "decrypted_body_hex": (
                "00000002"
                "55aa"
                "0000001c"
                "0000"
                "00000001"
                "000003dd"
                "12345678"
                "3963"
                "0000000b"
                "0801"
            ),
        }
        record = proto.parse_record(packet)
        self.assertIsNotNone(record)
        self.assertEqual(record["transport_layout"], "tgcp_4013_v14")
        self.assertEqual(record["opcode"], 0x03DD)
        self.assertEqual(record["raw_opcode_hex"], "0x000003DD")
        self.assertEqual(record["session_id_hex"], "0x000003DD")
        self.assertEqual(record["sub_id_hex"], "0x12345678")
        self.assertEqual(record["subtype"], 0x12345678)
        self.assertEqual(record["req_seq"], 11)
        self.assertEqual(record["root"]["fields"][0]["field"], 1)
        self.assertEqual(record["root"]["fields"][0]["value"], 1)

    def test_parse_tgcp_control_packet_ack_extracts_session_key(self) -> None:
        record = proto.parse_tgcp_control_packet({
            "cmd": 0x1002,
            "direction": "s2c",
            "seq": 55,
            "header_extra_hex": "000030313233343536373839414243444546",
            "body_hex": "",
        })
        self.assertIsNotNone(record)
        self.assertEqual(record["tgcp_command_name"], "ACK")
        self.assertEqual(record["session_key_ascii"], "0123456789ABCDEF")
        self.assertEqual(record["session_key_hex"], "30313233343536373839414243444546")

    def test_parse_tgcp_control_packet_sstop_parses_code(self) -> None:
        record = proto.parse_tgcp_control_packet({
            "cmd": 0x5002,
            "direction": "s2c",
            "seq": 77,
            "header_extra_hex": "",
            "body_hex": (
                "00000012"
                "00000000"
                "7f000001"
                "2003"
                "00000004"
                "61626364"
            ),
        })
        self.assertIsNotNone(record)
        self.assertEqual(record["tgcp_command_name"], "SSTOP")
        sstop = record["sstop"]
        self.assertEqual(sstop["code"], 0x12)
        self.assertEqual(sstop["code_name"], "AUTH_REQUIRED")
        self.assertEqual(sstop["tconnd_ip"], "127.0.0.1")
        self.assertEqual(sstop["tconnd_port"], 8195)
        self.assertEqual(sstop["tconnd_id"], "abcd")


if __name__ == "__main__":
    unittest.main()
