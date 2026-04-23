#!/usr/bin/env python3
# Copyright (C) 2026 花吹雪又一年
#
# This file is part of Roco-Kingdom-Protocol-Parser (RKPP).
# Licensed under the GNU Affero General Public License v3.0 only (AGPL-3.0-only).
# You must retain the author attribution, this notice, the LICENSE file,
# and the NOTICE file in redistributions and derivative works.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the LICENSE
# file for more details.

"""I/O 工具集：时间戳、日志、CSV 输出、目录管理、离线 pcap 迭代。"""
from __future__ import annotations

import csv
import datetime as dt
import json
from pathlib import Path
from typing import Any, Iterable

from scapy.all import PcapReader  # type: ignore

SCRIPT_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# 时间戳
# ---------------------------------------------------------------------------

def now_text()  -> str: return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def now_stamp() -> str: return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


# ---------------------------------------------------------------------------
# SessionLogger：持久文件句柄，同步写屏幕 + 文件
# ---------------------------------------------------------------------------

class SessionLogger:
    """日志同时输出到屏幕和文件。使用持久文件句柄避免频繁 open/close。"""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = log_path.open("a", encoding="utf-8")

    def log(self, message: str) -> None:
        line = f"[{now_text()}] {message}"
        print(line, flush=True)
        self._fp.write(line + "\n")
        self._fp.flush()

    def close(self) -> None:
        if self._fp and not self._fp.closed:
            self._fp.close()

    def __enter__(self) -> SessionLogger:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# CsvSink：批量刷新写入 CSV
# ---------------------------------------------------------------------------

_FLUSH_INTERVAL = 50  # 每 N 行刷新一次


def _json_loads_maybe(text: Any) -> Any:
    if not isinstance(text, str) or not text:
        return text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def build_opcode_summary(row: dict[str, Any], *, parse_content: bool = False) -> dict[str, Any] | None:
    opencode = row.get("opcode_hex") or row.get("opcode")
    if not opencode:
        return None
    name = str(row.get("opcode_name") or "").strip()
    desc = str(row.get("opcode_desc") or "").strip()
    content = (
        row.get("decoded_json")
        or row.get("summary_json")
        or row.get("summary_text")
        or row.get("root_json")
        or ""
    )
    return {
        "opencode": opencode,
        "meaning": " | ".join(part for part in (name, desc) if part),
        "content": _json_loads_maybe(content) if parse_content else content,
    }


def _xyz_part(value: Any, axis: str) -> Any:
    return value.get(axis) if isinstance(value, dict) else None


def _client_move_summary_text(move: dict[str, Any]) -> str:
    pos = move.get("to_pos") if isinstance(move.get("to_pos"), dict) else {}
    return (
        f"client_move actor={move.get('actor_id')} "
        f"pos=({pos.get('x')},{pos.get('y')},{pos.get('z')}) "
        f"mode={move.get('move_mode')}"
    )


def build_client_move_rows(
    row_index: int,
    row: dict[str, Any],
    parsed_info: dict[str, Any],
) -> list[dict[str, Any]]:
    record = parsed_info.get("record") if isinstance(parsed_info, dict) else None
    if not isinstance(record, dict):
        return []
    if int(record.get("opcode", 0) or 0) != 0x0414:
        return []
    decoded = record.get("_decoded")
    if not isinstance(decoded, dict):
        return []
    acts = decoded.get("acts")
    if not isinstance(acts, list):
        return []

    base = decoded.get("space_base_data") if isinstance(decoded.get("space_base_data"), dict) else {}
    rows: list[dict[str, Any]] = []
    for act_index, act in enumerate(acts):
        if not isinstance(act, dict):
            continue
        move = act.get("client_move")
        if not isinstance(move, dict):
            continue
        item: dict[str, Any] = {
            "row_index": row_index,
            "act_index": act_index,
            "captured_at": row.get("captured_at"),
            "flow_id": row.get("flow_id"),
            "direction": row.get("protocol_direction") or row.get("direction"),
            "seq": row.get("seq"),
            "opcode": row.get("opcode"),
            "opcode_hex": row.get("opcode_hex"),
            "opcode_name": row.get("opcode_name"),
            "inner_message_id": row.get("inner_message_id"),
            "space_time_ms": base.get("space_time_ms"),
            "operator_obj_id": base.get("operator_obj_id"),
            "actor_id": move.get("actor_id"),
            "time_stamp": move.get("time_stamp"),
            "move_mode": move.get("move_mode"),
            "custom_mode": move.get("custom_mode"),
            "stop_move": move.get("stop_move"),
            "ride_move": move.get("ride_move"),
            "mate_point": move.get("mate_point"),
            "mate_move_mode": move.get("mate_move_mode"),
            "summary_text": _client_move_summary_text(move),
            "content": move,
        }
        for prefix in ("to_pos", "to_rot", "speed", "acceleration", "ctrl_rot"):
            value = move.get(prefix)
            item[f"{prefix}_x"] = _xyz_part(value, "x")
            item[f"{prefix}_y"] = _xyz_part(value, "y")
            item[f"{prefix}_z"] = _xyz_part(value, "z")
        rows.append(item)
    return rows


class _BufferedCsvWriter:
    def __init__(self, csv_path: Path, fieldnames: list[str]) -> None:
        self.csv_path = csv_path
        self._fieldnames = fieldnames
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = csv_path.open("w", encoding="utf-8-sig", newline="")
        self._writer = csv.DictWriter(self._fp, fieldnames=self._fieldnames)
        self._writer.writeheader()
        self._fp.flush()
        self._rows_since_flush = 0

    def write_row(self, row: dict[str, Any]) -> None:
        self._writer.writerow({field: row.get(field, "") for field in self._fieldnames})
        self._rows_since_flush += 1
        if self._rows_since_flush >= _FLUSH_INTERVAL:
            self.flush()

    def flush(self) -> None:
        if self._fp and not self._fp.closed:
            self._fp.flush()
        self._rows_since_flush = 0

    def close(self) -> None:
        if self._fp and not self._fp.closed:
            self.flush()
            self._fp.close()


class CsvSink:
    FIELDS: list[str] = [
        "captured_at", "frame_no", "packet_time",
        "flow_id", "client_ip", "client_port", "server_ip", "server_port",
        "direction", "stream_offset", "seq",
        "cmd", "cmd_hex", "tgcp_cmd_name", "hdr_len", "body_len",
        "header_extra_hex", "body_hex",
        "key_hex", "key_ascii",
        "decrypt_status", "iv_hex", "cipher_hex", "decrypted_body_hex",
        "transport_kind", "transport_layout", "transport_seq", "record_len",
        "session_id_hex", "sub_id_hex",
        "protocol_direction", "opcode", "opcode_hex", "raw_opcode", "raw_opcode_hex", "opcode_normalized",
        "opcode_name", "opcode_desc", "subtype",
        "magic_hex", "req_seq", "payload_len", "payload_trailer_len", "root_clean",
        "inner_message_id",
        "summary_kind", "summary_text", "summary_json",
        "decoded_json", "record_json", "root_json",
    ]
    OPCODE_FIELDS: list[str] = ["opencode", "meaning", "content"]

    def __init__(self, csv_path: Path) -> None:
        self.csv_path = csv_path
        self.opcode_csv_path = csv_path.with_name("opencode_summary.csv")
        self._main_writer = _BufferedCsvWriter(csv_path, self.FIELDS)
        self._opcode_writer = _BufferedCsvWriter(self.opcode_csv_path, self.OPCODE_FIELDS)

    def write_row(self, row: dict[str, Any]) -> None:
        self._main_writer.write_row(row)
        opcode_row = self._build_opcode_row(row)
        if opcode_row is not None:
            self._opcode_writer.write_row(opcode_row)

    def _build_opcode_row(self, row: dict[str, Any]) -> dict[str, Any] | None:
        return build_opcode_summary(row)

    def close(self) -> None:
        try:
            self._main_writer.close()
        finally:
            self._opcode_writer.close()

    def __enter__(self) -> CsvSink:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class MoveCsvSink:
    FIELDS: list[str] = [
        "row_index", "act_index",
        "captured_at", "flow_id", "direction", "seq",
        "opcode", "opcode_hex", "opcode_name", "inner_message_id",
        "space_time_ms", "operator_obj_id",
        "actor_id", "time_stamp",
        "to_pos_x", "to_pos_y", "to_pos_z",
        "to_rot_x", "to_rot_y", "to_rot_z",
        "speed_x", "speed_y", "speed_z",
        "acceleration_x", "acceleration_y", "acceleration_z",
        "ctrl_rot_x", "ctrl_rot_y", "ctrl_rot_z",
        "move_mode", "custom_mode", "stop_move",
        "ride_move", "mate_point", "mate_move_mode",
        "summary_text",
    ]

    def __init__(self, csv_path: Path) -> None:
        self.csv_path = csv_path
        self._writer = _BufferedCsvWriter(csv_path, self.FIELDS)

    def handle(self, row_index: int, row: dict[str, Any], parsed_info: dict[str, Any]) -> None:
        for item in build_client_move_rows(row_index, row, parsed_info):
            self._writer.write_row(item)

    def close(self) -> None:
        self._writer.close()

    def __enter__(self) -> MoveCsvSink:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# 目录管理
# ---------------------------------------------------------------------------

def make_output_dir(base: Path | None, prefix: str) -> Path:
    out = (base or SCRIPT_DIR) / f"{prefix}_{now_stamp()}"
    out.mkdir(parents=True, exist_ok=True)
    return out

def ensure_output_dir(path: Path | None, prefix: str) -> Path:
    if path is None:
        return make_output_dir(None, prefix)
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# 离线 pcap
# ---------------------------------------------------------------------------

def iter_offline_packets(path: Path) -> Iterable:
    with PcapReader(str(path)) as reader:
        for index, packet in enumerate(reader, 1):
            yield index, packet


# ---------------------------------------------------------------------------
# 交互式提示
# ---------------------------------------------------------------------------

def prompt_text(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")

def prompt_menu() -> str:
    while True:
        v = input("请选择功能 1=抓key 2=解包 3=战斗实时解析 4=opencode中转Server: ").strip()
        if v in {"1", "2", "3", "4"}:
            return v
        print("输入无效，请输入 1、2、3 或 4。")


def prompt_server_mode() -> str:
    while True:
        v = input("请选择4模式 1=常规模式 2=路径移动服务器: ").strip()
        if v == "1":
            return "normal"
        if v == "2":
            return "move"
        print("输入无效，请输入 1 或 2。")
