from __future__ import annotations

import unittest

from rkpp_io import build_client_move_rows


class MoveModeTests(unittest.TestCase):
    def test_build_client_move_rows_extracts_client_move(self) -> None:
        row = {
            "captured_at": "2026-04-13 10:00:00",
            "flow_id": "flow-1",
            "direction": "s2c",
            "protocol_direction": "s2c",
            "seq": 100,
            "opcode": 0x0414,
            "opcode_hex": "0x0414",
            "opcode_name": "ZoneScenePlayActsNotify",
            "inner_message_id": 11,
        }
        parsed_info = {
            "record": {
                "opcode": 0x0414,
                "_decoded": {
                    "space_base_data": {"space_time_ms": 123, "operator_obj_id": 456},
                    "acts": [{
                        "client_move": {
                            "actor_id": 1,
                            "time_stamp": 2,
                            "to_pos": {"x": 3, "y": 4, "z": 5},
                            "to_rot": {"x": 6, "y": 7, "z": 8},
                            "speed": {"x": 9, "y": 10, "z": 11},
                            "acceleration": {"x": 12, "y": 13, "z": 14},
                            "ctrl_rot": {"x": 15, "y": 16, "z": 17},
                            "move_mode": 18,
                            "custom_mode": 19,
                            "ride_move": False,
                            "mate_point": "",
                            "mate_move_mode": 20,
                        },
                    }],
                },
            },
        }

        items = build_client_move_rows(7, row, parsed_info)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["row_index"], 7)
        self.assertEqual(items[0]["actor_id"], 1)
        self.assertEqual(items[0]["space_time_ms"], 123)
        self.assertEqual(items[0]["to_pos_x"], 3)
        self.assertEqual(items[0]["ctrl_rot_z"], 17)
        self.assertEqual(items[0]["mate_move_mode"], 20)

    def test_build_client_move_rows_skips_non_client_move_acts(self) -> None:
        row = {"opcode": 0x0414}
        parsed_info = {
            "record": {
                "opcode": 0x0414,
                "_decoded": {
                    "acts": [
                        {"sync_player_status": {"actor_id": 1}},
                        {"client_move": {"actor_id": 2, "to_pos": {"x": 1, "y": 2, "z": 3}}},
                        {"throw_catch_notify": {"caster_id": 3}},
                    ],
                },
            },
        }

        items = build_client_move_rows(1, row, parsed_info)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["act_index"], 1)
        self.assertEqual(items[0]["actor_id"], 2)


if __name__ == "__main__":
    unittest.main()
