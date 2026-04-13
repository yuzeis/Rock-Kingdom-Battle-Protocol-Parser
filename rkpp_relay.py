#!/usr/bin/env python3
# Copyright (C) 2026 花吹雪又一年
#
# This file is part of Roco-Kingdom-Protocol-Parser (RKPP).
# Licensed under the GNU Affero General Public License v3.0 only (AGPL-3.0-only).

"""HTTP relay for parsed opcode events.

Endpoints:
  GET /health  -> server stats
  GET /latest  -> recent opcode events as JSON
  GET /events  -> newline-delimited JSON stream for live consumers
"""
from __future__ import annotations

import json
import queue
import threading
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from rkpp_io import SessionLogger, build_client_move_rows, build_opcode_summary, now_text


class OpcodeRelayServer:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        logger: SessionLogger,
        history_size: int = 500,
        mode: str = "normal",
    ) -> None:
        self.host = host
        self.port = port
        self.logger = logger
        self.mode = mode
        self._history: deque[dict[str, Any]] = deque(maxlen=max(1, history_size))
        self._clients: set[queue.Queue[dict[str, Any] | None]] = set()
        self._lock = threading.Lock()
        self._event_count = 0
        self._requested_port = port
        self._httpd = self._make_server_with_fallback()
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="rkpp-opcode-relay", daemon=True)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        if self.port != self._requested_port:
            self.logger.log(
                f"[relay] requested port {self._requested_port} unavailable, fallback port={self.port}"
            )
        self._thread.start()
        self.logger.log(
            f"[relay] listening url={self.url} mode={self.mode} endpoints=/health,/latest,/events"
        )

    def close(self) -> None:
        with self._lock:
            clients = list(self._clients)
        for client in clients:
            client.put_nowait(None)
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=2.0)

    def handle(self, row_index: int, row: dict[str, Any], parsed_info: dict[str, Any]) -> None:
        events = self._build_events(row_index, row, parsed_info)
        if not events:
            return
        with self._lock:
            self._event_count += len(events)
            for event in events:
                self._history.append(event)
            clients = list(self._clients)
        for event in events:
            for client in clients:
                try:
                    client.put_nowait(event)
                except queue.Full:
                    pass

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "status": "ok",
                "mode": self.mode,
                "time": now_text(),
                "events": self._event_count,
                "history": len(self._history),
                "clients": len(self._clients),
            }

    def latest(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._history)
        return items[-max(0, limit):]

    def subscribe(self) -> queue.Queue[dict[str, Any] | None]:
        client: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=1000)
        with self._lock:
            self._clients.add(client)
        return client

    def unsubscribe(self, client: queue.Queue[dict[str, Any] | None]) -> None:
        with self._lock:
            self._clients.discard(client)

    def _build_events(self, row_index: int, row: dict[str, Any], parsed_info: dict[str, Any]) -> list[dict[str, Any]]:
        if self.mode == "move":
            return self._build_move_events(row_index, row, parsed_info)
        event = self._build_event(row_index, row, parsed_info)
        return [event] if event is not None else []

    def _build_event(self, row_index: int, row: dict[str, Any], parsed_info: dict[str, Any]) -> dict[str, Any] | None:
        summary = build_opcode_summary(row, parse_content=True)
        if summary is None:
            return None
        name = str(row.get("opcode_name") or "").strip()
        return {
            "row_index": row_index,
            "captured_at": row.get("captured_at"),
            "flow_id": row.get("flow_id"),
            "direction": row.get("protocol_direction") or row.get("direction"),
            "seq": row.get("seq"),
            "opencode": summary["opencode"],
            "opcode": row.get("opcode"),
            "opcode_name": name,
            "meaning": summary["meaning"],
            "summary_kind": parsed_info.get("summary_kind") or row.get("summary_kind"),
            "summary_text": row.get("summary_text"),
            "content": summary["content"] or {},
        }

    def _build_move_events(
        self,
        row_index: int,
        row: dict[str, Any],
        parsed_info: dict[str, Any],
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for item in build_client_move_rows(row_index, row, parsed_info):
            events.append({
                "row_index": item.get("row_index"),
                "act_index": item.get("act_index"),
                "captured_at": item.get("captured_at"),
                "flow_id": item.get("flow_id"),
                "direction": item.get("direction"),
                "seq": item.get("seq"),
                "opencode": item.get("opcode_hex") or item.get("opcode"),
                "opcode": item.get("opcode"),
                "opcode_name": item.get("opcode_name"),
                "inner_message_id": item.get("inner_message_id"),
                "summary_kind": "client_move",
                "summary_text": item.get("summary_text"),
                "space_time_ms": item.get("space_time_ms"),
                "operator_obj_id": item.get("operator_obj_id"),
                "actor_id": item.get("actor_id"),
                "time_stamp": item.get("time_stamp"),
                "to_pos": {
                    "x": item.get("to_pos_x"),
                    "y": item.get("to_pos_y"),
                    "z": item.get("to_pos_z"),
                },
                "to_rot": {
                    "x": item.get("to_rot_x"),
                    "y": item.get("to_rot_y"),
                    "z": item.get("to_rot_z"),
                },
                "speed": {
                    "x": item.get("speed_x"),
                    "y": item.get("speed_y"),
                    "z": item.get("speed_z"),
                },
                "acceleration": {
                    "x": item.get("acceleration_x"),
                    "y": item.get("acceleration_y"),
                    "z": item.get("acceleration_z"),
                },
                "ctrl_rot": {
                    "x": item.get("ctrl_rot_x"),
                    "y": item.get("ctrl_rot_y"),
                    "z": item.get("ctrl_rot_z"),
                },
                "move_mode": item.get("move_mode"),
                "custom_mode": item.get("custom_mode"),
                "stop_move": item.get("stop_move"),
                "ride_move": item.get("ride_move"),
                "mate_point": item.get("mate_point"),
                "mate_move_mode": item.get("mate_move_mode"),
                "content": item.get("content") or {},
            })
        return events

    def _make_server_with_fallback(self) -> ThreadingHTTPServer:
        last_exc: OSError | None = None
        for candidate in range(self.port, self.port + 11):
            self.port = candidate
            try:
                return self._make_server()
            except OSError as exc:
                last_exc = exc
                code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
                if code not in {10013, 10048, 13, 48, 98}:
                    raise
        assert last_exc is not None
        raise last_exc

    def _make_server(self) -> ThreadingHTTPServer:
        relay = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path == "/health":
                    self._send_json(relay.stats())
                    return
                if parsed.path == "/latest":
                    qs = parse_qs(parsed.query)
                    limit = int(qs.get("limit", ["50"])[0])
                    self._send_json(relay.latest(limit))
                    return
                if parsed.path == "/events":
                    self._stream_events()
                    return
                self.send_error(404, "not found")

            def _send_json(self, value: Any) -> None:
                body = json.dumps(value, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _stream_events(self) -> None:
                client = relay.subscribe()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    for item in relay.latest(50):
                        self._write_event(item)
                    while True:
                        item = client.get()
                        if item is None:
                            break
                        self._write_event(item)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    relay.unsubscribe(client)

            def _write_event(self, item: dict[str, Any]) -> None:
                line = json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
                self.wfile.write(line)
                self.wfile.flush()

        return ThreadingHTTPServer((self.host, self.port), Handler)
