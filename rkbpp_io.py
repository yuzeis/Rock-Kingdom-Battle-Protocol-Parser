#!/usr/bin/env python3
# Copyright (C) 2026 花吹雪又一年
#
# This file is part of Rock Kingdom Battle Protocol Parser (RKBPP).
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


class CsvSink:
    FIELDS: list[str] = [
        "captured_at", "frame_no", "packet_time",
        "flow_id", "client_ip", "client_port", "server_ip", "server_port",
        "direction", "stream_offset", "seq",
        "cmd", "cmd_hex", "hdr_len", "body_len",
        "header_extra_hex", "body_hex",
        "key_hex", "key_ascii",
        "decrypt_status", "iv_hex", "cipher_hex", "decrypted_body_hex",
        "protocol_direction", "opcode", "opcode_hex", "opcode_name", "opcode_desc", "subtype",
        "magic_hex", "req_seq", "payload_len", "root_clean",
        "inner_message_id",
        "summary_kind", "summary_text", "summary_json",
        "decoded_json", "record_json", "root_json",
    ]
    OPCODE_FIELDS: list[str] = ["opencode", "meaning", "content"]

    def __init__(self, csv_path: Path) -> None:
        self.csv_path = csv_path
        self.opcode_csv_path = csv_path.with_name("opencode_summary.csv")
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        self._fp = csv_path.open("w", encoding="utf-8-sig", newline="")
        self._writer = csv.DictWriter(self._fp, fieldnames=self.FIELDS)
        self._writer.writeheader()
        self._opcode_fp = self.opcode_csv_path.open("w", encoding="utf-8-sig", newline="")
        self._opcode_writer = csv.DictWriter(self._opcode_fp, fieldnames=self.OPCODE_FIELDS)
        self._opcode_writer.writeheader()
        self._fp.flush()
        self._opcode_fp.flush()
        self._rows_since_flush = 0

    def write_row(self, row: dict[str, Any]) -> None:
        self._writer.writerow({f: row.get(f, "") for f in self.FIELDS})
        opcode_row = self._build_opcode_row(row)
        if opcode_row is not None:
            self._opcode_writer.writerow(opcode_row)
        self._rows_since_flush += 1
        if self._rows_since_flush >= _FLUSH_INTERVAL:
            self._fp.flush()
            self._opcode_fp.flush()
            self._rows_since_flush = 0

    def _build_opcode_row(self, row: dict[str, Any]) -> dict[str, Any] | None:
        return build_opcode_summary(row)

    def close(self) -> None:
        try:
            if self._fp and not self._fp.closed:
                self._fp.flush()
                self._fp.close()
        finally:
            if self._opcode_fp and not self._opcode_fp.closed:
                self._opcode_fp.flush()
                self._opcode_fp.close()

    def __enter__(self) -> CsvSink:
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
