from __future__ import annotations

from pathlib import Path
import unittest

import rkbpp_analyzer as analyzer
from rkbpp_reporter import BattleConsoleReporter


class DummyLogger:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def log(self, message: str) -> None:
        self.messages.append(message)


class AnalyzerDispatchTests(unittest.TestCase):
    def test_only_semantic_opcodes_stay_in_registry(self) -> None:
        self.assertIn(0x1324, analyzer._OPCODE_REGISTRY)
        self.assertIn(0x13F4, analyzer._OPCODE_REGISTRY)
        self.assertIn(0x1312, analyzer._OPCODE_REGISTRY)
        self.assertNotIn(0x132A, analyzer._OPCODE_REGISTRY)
        self.assertNotIn(0x132D, analyzer._OPCODE_REGISTRY)
        self.assertNotIn(0x1334, analyzer._OPCODE_REGISTRY)
        self.assertNotIn(0x133C, analyzer._OPCODE_REGISTRY)
        self.assertNotIn(0x13F6, analyzer._OPCODE_REGISTRY)

    def test_unregistered_opcode_uses_schema_fallback(self) -> None:
        record = {
            "opcode": 0x132A,
            "opcode_hex": "0x132A",
            "_decoded": {"player_uin": 12345, "reason": 1},
            "_schema_found": True,
            "_message_name": "ZoneBattleRoleLeaveNotify",
        }

        kind, summary = analyzer.RkbppAnalyzer._summarize(object(), record, None)

        self.assertEqual(kind, "schema_decoded")
        self.assertEqual(summary["opcode_hex"], "0x132A")
        self.assertEqual(summary["message"], "ZoneBattleRoleLeaveNotify")
        self.assertEqual(summary["schema_fields"], ["player_uin", "reason"])

    def test_schema_fallback_text_inlines_simple_fields(self) -> None:
        text = analyzer.RkbppAnalyzer._fmt_text(object(), "schema_decoded", {
            "opcode_hex": "0x132A",
            "opcode_name": "ZoneBattleRoleLeaveNotify",
            "schema_found": True,
            "decoded": {"player_uin": 12345, "reason": 1},
            "schema_fields": ["player_uin", "reason"],
        })

        self.assertIn("player_uin=12345", text)
        self.assertIn("reason=1", text)

    def test_schema_fallback_text_inlines_nested_act_name(self) -> None:
        text = analyzer.RkbppAnalyzer._fmt_text(object(), "schema_decoded", {
            "opcode_hex": "0x0414",
            "opcode_name": "ZoneScenePlayActsNotify",
            "schema_found": True,
            "decoded": {
                "acts": [{"client_move": {"actor_id": 1}}],
                "space_base_data": {"space_time_ms": 2},
            },
            "schema_fields": ["acts", "space_base_data"],
        })

        self.assertIn("acts[0]=client_move", text)

    def test_reporter_handles_schema_decoded_simple_opcode(self) -> None:
        logger = DummyLogger()
        reporter = BattleConsoleReporter(logger=logger)  # type: ignore[arg-type]

        reporter.handle(7, {}, {
            "record": {
                "opcode": 0x132A,
                "_decoded": {"player_uin": 12345, "reason": 1},
            },
            "summary_kind": "schema_decoded",
            "summary_obj": {},
        })

        self.assertTrue(any("12345" in message for message in logger.messages))

    def test_unknown_inner_message_falls_back_to_schema_summary(self) -> None:
        record = {
            "opcode": 0x0414,
            "opcode_hex": "0x0414",
            "_decoded": {"message_id": 11, "move_type": 2},
            "_schema_found": True,
            "_message_name": "client_move",
        }

        kind, summary = analyzer.RkbppAnalyzer._summarize(object(), record, {"message_id": 11})

        self.assertEqual(kind, "schema_decoded")
        self.assertEqual(summary["message"], "client_move")
        self.assertEqual(summary["inner_message_id"], 11)

    def test_key_update_resets_error_alert_state(self) -> None:
        inst = analyzer.RkbppAnalyzer(
            port=8195,
            logger=DummyLogger(),  # type: ignore[arg-type]
            writer=None,
            key_file=Path("test_key.txt"),
            csv_sink=None,
            preset_key=None,
            stop_after_key=False,
        )
        inst._consecutive_errors = 7
        inst._error_alerted = True

        flow = type("Flow", (), {"seen_acks": set(), "key": None, "flow_id": "flow-1"})()
        be21 = type(
            "Be21",
            (),
            {
                "cmd": 0x1002,
                "header_extra": b"\x00\x00" + b"0123456789ABCDEF",
                "seq": 123,
                "direction": "s2c",
            },
        )()

        original_write_key_file = analyzer.write_key_file
        analyzer.write_key_file = lambda *_args, **_kwargs: None
        try:
            analyzer.RkbppAnalyzer._handle_be21(inst, flow, be21, object(), None)
        finally:
            analyzer.write_key_file = original_write_key_file

        self.assertEqual(inst._consecutive_errors, 0)
        self.assertFalse(inst._error_alerted)
        self.assertEqual(flow.key, b"0123456789ABCDEF")


if __name__ == "__main__":
    unittest.main()
