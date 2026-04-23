from __future__ import annotations

import unittest

import rkpp_live_tools as live_tools


class DummyLogger:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def log(self, message: str) -> None:
        self.messages.append(message)


class DummyAnalyzer:
    def __init__(self, *, key_hits: int = 0, seen: int = 0, parsed: int = 0, failed: int = 0) -> None:
        self.key_hits = key_hits
        self.business_frames_seen = seen
        self.parsed_business_records = parsed
        self.failed_business_records = failed


class LiveToolsExitTests(unittest.TestCase):
    def test_capture_key_uses_key_hit_exit_semantics(self) -> None:
        logger = DummyLogger()
        self.assertEqual(
            live_tools._session_exit_code(
                "capture-key",
                DummyAnalyzer(key_hits=1),
                preset_key=None,
                session_logger=logger,  # type: ignore[arg-type]
            ),
            0,
        )
        self.assertEqual(
            live_tools._session_exit_code(
                "capture-key",
                DummyAnalyzer(key_hits=0),
                preset_key=None,
                session_logger=logger,  # type: ignore[arg-type]
            ),
            1,
        )

    def test_provided_bad_key_returns_failure_exit_code(self) -> None:
        logger = DummyLogger()
        exit_code = live_tools._session_exit_code(
            "live-decode",
            DummyAnalyzer(seen=10, parsed=0, failed=10),
            preset_key=b"0123456789ABCDEF",
            session_logger=logger,  # type: ignore[arg-type]
        )
        self.assertEqual(exit_code, 2)
        self.assertTrue(any("no parsable business records" in msg for msg in logger.messages))

    def test_provided_key_with_some_parsed_records_stays_success(self) -> None:
        logger = DummyLogger()
        exit_code = live_tools._session_exit_code(
            "live-decode",
            DummyAnalyzer(seen=10, parsed=3, failed=7),
            preset_key=b"0123456789ABCDEF",
            session_logger=logger,  # type: ignore[arg-type]
        )
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
