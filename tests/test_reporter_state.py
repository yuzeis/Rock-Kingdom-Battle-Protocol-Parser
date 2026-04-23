from __future__ import annotations

import unittest

from rkpp_reporter import BattleConsoleReporter, BattlePhase


class DummyLogger:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def log(self, message: str) -> None:
        self.messages.append(message)


class ReporterStateTests(unittest.TestCase):
    def test_force_finish_resets_all_battle_state(self) -> None:
        reporter = BattleConsoleReporter(logger=DummyLogger())  # type: ignore[arg-type]
        reporter._phase = BattlePhase.ACTIVE
        reporter.opening_pair = {"friendly": {"pet_id": 1}}
        reporter.opening_1316 = [{"slot": 1}]
        reporter.opening_131a = [{"slot": 2}]
        reporter.active_friendly_slot = 3
        reporter.active_enemy_slot = 4

        reporter._on_force_finish(1, {}, {"detail": {"reason": 9}})

        self.assertEqual(reporter._phase, BattlePhase.WAITING_PAIR)
        self.assertIsNone(reporter.opening_pair)
        self.assertIsNone(reporter.opening_1316)
        self.assertIsNone(reporter.opening_131a)
        self.assertIsNone(reporter.active_friendly_slot)
        self.assertIsNone(reporter.active_enemy_slot)

    def test_battle_finish_resets_all_battle_state(self) -> None:
        reporter = BattleConsoleReporter(logger=DummyLogger())  # type: ignore[arg-type]
        reporter._phase = BattlePhase.ACTIVE
        reporter.opening_pair = {"friendly": {"pet_id": 1}}
        reporter.opening_1316 = [{"slot": 1}]
        reporter.opening_131a = [{"slot": 2}]
        reporter.active_friendly_slot = 3
        reporter.active_enemy_slot = 4

        reporter._on_battle_finish(1, {}, {"detail": {"result_code": 1}})

        self.assertEqual(reporter._phase, BattlePhase.WAITING_PAIR)
        self.assertIsNone(reporter.opening_pair)
        self.assertIsNone(reporter.opening_1316)
        self.assertIsNone(reporter.opening_131a)
        self.assertIsNone(reporter.active_friendly_slot)
        self.assertIsNone(reporter.active_enemy_slot)


if __name__ == "__main__":
    unittest.main()
