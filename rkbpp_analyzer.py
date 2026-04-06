#!/usr/bin/env python3
# Copyright (C) 2026 Yuzeis
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

"""核心分析器：RkbppAnalyzer。

BE21帧 → AES解密 → proto解析 → opcode dispatch → CSV/listener 输出。
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable

from scapy.all import PcapWriter, TCP  # type: ignore

import rkbpp_proto as proto
from rkbpp_io import CsvSink, SessionLogger, now_text
from rkbpp_network import (Be21Packet, FlowState,
                           decrypt_4013_body, flow_key_from_packet,
                           packet_has_target_port, printable_ascii, write_key_file)

logger = logging.getLogger(__name__)

# 连续解密失败超过此阈值时发出告警
_ERROR_ALERT_THRESHOLD = 10


# ---------------------------------------------------------------------------
# Opcode dispatch 注册表
# ---------------------------------------------------------------------------

# 注册表条目: opcode -> (summary_kind, extractor_func)
# extractor_func 签名: (record, inner?) -> dict[str, Any]
_OPCODE_REGISTRY: dict[int, tuple[str, Callable[..., Any]]] = {}
_INNER_REGISTRY: dict[int, tuple[str, Callable[..., Any]]] = {}


def _register_opcode(opcode: int, kind: str):
    """装饰器: 注册 opcode 对应的 summarize 提取函数。"""
    def decorator(func: Callable[..., Any]):
        _OPCODE_REGISTRY[opcode] = (kind, func)
        return func
    return decorator


def _register_inner(message_id: int, kind: str):
    """装饰器: 注册 0x0414 inner message_id 对应的提取函数。"""
    def decorator(func: Callable[..., Any]):
        _INNER_REGISTRY[message_id] = (kind, func)
        return func
    return decorator


@_register_opcode(0x0102, "roster_init")
def _summarize_0102(record, _inner):
    return {"metadata": proto.extract_0102_metadata(record), "creatures": proto.extract_0102_creatures(record)}

@_register_opcode(0x1316, "state_update")
def _summarize_1316(record, _inner):
    return {"wrappers": proto.extract_state_wrappers_from_record(record)}

@_register_opcode(0x131A, "state_update")
def _summarize_131a(record, _inner):
    return {"wrappers": proto.extract_state_wrappers_from_record(record)}

@_register_opcode(0x130B, "client_skill_select")
def _summarize_130b(record, _inner):
    return {"detail": proto.extract_130b_skill_select(record)}

@_register_opcode(0x1322, "server_skill_declare")
def _summarize_1322(record, _inner):
    return {"detail": proto.extract_1322_skill_declare(record)}

@_register_opcode(0x1324, "action_resolve")
def _summarize_1324(record, _inner):
    return {"detail": proto.extract_1324_action(record)}

@_register_opcode(0x13F4, "special_refresh")
def _summarize_13f4(record, _inner):
    return {"detail": proto.extract_13f4_refresh(record)}

@_register_opcode(0x130C, "server_action_ack")
def _summarize_130c(record, _inner):
    return {"detail": proto.extract_130c_result(record)}

@_register_opcode(0x1314, "turn_control")
def _summarize_1314(record, _inner):
    return {"detail": proto.extract_1314_phase(record)}

@_register_opcode(0x01A9, "client_action")
def _summarize_01a9(record, _inner):
    return {"detail": proto.extract_01a9_action(record)}

@_register_opcode(0x0220, "snapshot_handle")
def _summarize_0220(record, _inner):
    return {"handle": proto.extract_0220_handle(record)}


@_register_inner(390, "inner390_pair")
def _summarize_inner390(inner):
    return {"detail": proto.parse_inner390_detail(inner["fields"])}

@_register_inner(200, "inner200_commit")
def _summarize_inner200(inner):
    return {"detail": proto.parse_inner200_detail(inner["fields"])}

@_register_inner(51, "inner51_event")
def _summarize_inner51(inner):
    return {"detail": proto.parse_inner51_detail(inner["fields"])}

@_register_inner(1, "inner1_effect")
def _summarize_inner1(inner):
    return {"detail": proto.parse_inner1_detail(inner["fields"])}


# ---------------------------------------------------------------------------
# 文本格式化注册表
# ---------------------------------------------------------------------------

_FMT_REGISTRY: dict[str, Callable[[dict[str, Any]], str]] = {}

def _register_fmt(kind: str):
    def decorator(func: Callable[[dict[str, Any]], str]):
        _FMT_REGISTRY[kind] = func
        return func
    return decorator


def _fmt_action_or_skill(d: dict[str, Any]) -> str:
    if d.get("skill_id") is not None:
        name = d.get("skill_name") or "未知技能"
        return f"{name}({d.get('skill_id')})"
    return str(d.get("action_name") or "未知动作")


@_register_fmt("roster_init")
def _fmt_roster_init(so):
    names = [it.get("name") for it in (so.get("creatures") or []) if it.get("name")]
    nick  = ((so.get("metadata") or {}).get("player") or {}).get("nickname")
    parts = ([f"player={nick}"] if nick else []) + (["roster=" + "/".join(str(n) for n in names[:6])] if names else [])
    return " | ".join(parts)

@_register_fmt("state_update")
def _fmt_state_update(so):
    ws = so.get("wrappers") or []
    parts = [
        f"{it.get('name') or it.get('pet_id')}:{it.get('current_hp')}/{it.get('battle_max_hp')}"
        if it.get("current_hp") is not None else str(it.get("name") or it.get("pet_id"))
        for it in ws[:4]
    ]
    return f"wrappers={len(ws)}" + (f" | {'; '.join(parts)}" if parts else "")

@_register_fmt("client_skill_select")
@_register_fmt("server_skill_declare")
def _fmt_skill_select(so):
    d = so.get("detail") or {}
    if d.get("action_name"):
        parts = [f"action={d.get('action_name')}"]
        if d.get("command_slot") is not None:
            parts.append(f"slot={d.get('command_slot')}")
        if d.get("payload_kind") is not None:
            parts.append(f"kind={d.get('payload_kind')}")
        return " | ".join(parts)
    return " | ".join(filter(None, [
        f"skill={d.get('skill_name') or '?'}", f"skill_id={d.get('skill_id')}",
        f"x100={d.get('skill_id_x100')}",
        f"slot={d.get('command_slot')}" if d.get("command_slot") is not None else None,
    ]))

@_register_fmt("action_resolve")
def _fmt_action_resolve(so):
    d = so.get("detail") or {}
    ps = d.get("primary_skill") or {}
    dm = d.get("damage_event") or {}
    en = d.get("energy_event") or {}
    parts = []
    if ps.get("skill_id"):
        parts.append(f"skill={ps.get('skill_name') or '?'}({ps.get('skill_id')})")
    if en.get("energy_delta") is not None or en.get("energy_after") is not None:
        parts.append(f"energy={en.get('energy_delta')}->{en.get('energy_after')}")
    if dm.get("damage"):
        parts.append(f"damage={dm.get('damage')}")
    if dm.get("target_hp_after"):
        parts.append(f"target_hp={dm.get('target_hp_after')}")
    if d.get("effect_ids"):
        parts.append("effects=" + "/".join(str(x) for x in d["effect_ids"][:6]))
    if d.get("has_defeat"):
        parts.append("defeat=1")
    return " | ".join(parts) if parts else "0x1324"

@_register_fmt("special_refresh")
def _fmt_special_refresh(so):
    d = so.get("detail") or {}
    parts = ([f"action={d.get('action_name')}"] if d.get("action_name") else [])
    if d.get("energy_delta") is not None or d.get("energy_after") is not None:
        parts.append(f"energy={d.get('energy_delta')}->{d.get('energy_after')}")
    if d.get("skill_options"):
        parts.append("skills=" + "; ".join(
            f"{it.get('slot')}:{it.get('skill_name') or '?'}({it.get('skill_id')})"
            for it in d["skill_options"][:6]
        ))
    return " | ".join(parts) if parts else "0x13F4"

@_register_fmt("server_action_ack")
def _fmt_action_ack(so):
    d = so.get("detail") or {}
    parts = ([f"action={d.get('action_name')}"] if d.get("action_name") else
             [f"skill_id={d.get('skill_id')}"] if d.get("skill_id") is not None else [])
    if d.get("current_hp") is not None:
        parts.append(f"hp={d.get('current_hp')}")
    if d.get("energy_after") is not None:
        parts.append(f"energy={d.get('energy_after')}")
    if d.get("state_wrappers"):
        parts.append(f"wrappers={len(d['state_wrappers'])}")
    return " | ".join(parts) if parts else "0x130C"

@_register_fmt("turn_control")
def _fmt_turn_control(so):
    return f"phase_code={(so.get('detail') or {}).get('phase_code')}"

@_register_fmt("inner390_pair")
def _fmt_inner390(so):
    d = so.get("detail") or {}
    f_ = d.get("friendly") or {}
    e_ = d.get("enemy") or {}
    return f"pair={f_.get('name') or f_.get('pet_id')} vs {e_.get('name') or e_.get('pet_id')}"

@_register_fmt("inner200_commit")
def _fmt_inner200(so):
    c = (so.get("detail") or {}).get("commit") or {}
    return f"flag={c.get('flag')} | code={c.get('code')} | event_time_ms={c.get('event_time_ms')}"

@_register_fmt("inner51_event")
def _fmt_inner51(so):
    d = so.get("detail") or {}
    return f"kind={d.get('kind')} | value2={d.get('value2')} | value3={d.get('value3')}"

@_register_fmt("inner1_effect")
def _fmt_inner1(so):
    d = so.get("detail") or {}
    h = d.get("header") or {}
    e = d.get("effect") or {}
    return f"actor={h.get('actor_token')} | effect_id={e.get('effect_id')} | code={e.get('code')} | amount={e.get('amount')}"

@_register_fmt("client_action")
def _fmt_client_action(so):
    info = so.get("detail") or {}
    ids = info.get("candidate_ids") or []
    return f"primary={info.get('primary_id')} | raw_kind={info.get('raw_kind')} | actor={info.get('actor_token')} | ids={'/'.join(str(x) for x in ids[:6])}"

@_register_fmt("snapshot_handle")
def _fmt_snapshot_handle(so):
    return f"handle={so.get('handle')}"


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class RkbppAnalyzer:
    def __init__(self, *, port: int, logger: SessionLogger, writer: PcapWriter | None,
                 key_file: Path, csv_sink: CsvSink | None,
                 preset_key: bytes | None, stop_after_key: bool,
                 analysis_listener: Any | None = None) -> None:
        self.port = port
        self.session_logger = logger
        self.writer = writer
        self.key_file = key_file
        self.csv_sink = csv_sink
        self.preset_key = preset_key
        self.stop_after_key = stop_after_key
        self.analysis_listener = analysis_listener
        self.should_stop = False
        self.packet_count = 0
        self.key_hits = 0
        self.decoded_rows = 0
        self.flows: dict[tuple[str, int, str, int], FlowState] = {}
        # 错误跟踪
        self._consecutive_errors = 0
        self._total_errors = 0
        self._error_alerted = False

    # ------------------------------------------------------------------
    # 包入口
    # ------------------------------------------------------------------

    def process_packet(self, packet, frame_no: int | None = None) -> None:
        if not packet_has_target_port(packet, self.port):
            return
        self.packet_count += 1
        if self.writer:
            self.writer.write(packet)
        if not packet.haslayer(TCP):
            return
        payload = bytes(packet[TCP].payload)
        if not payload:
            return
        fi = flow_key_from_packet(packet, self.port)
        if fi is None:
            return
        client_ip, direction, client_port, server_ip, server_port, flow_text = fi
        fk = (client_ip, client_port, server_ip, server_port)
        flow = self.flows.get(fk)
        if flow is None:
            flow = FlowState(
                flow_id=flow_text, client_ip=client_ip, client_port=client_port,
                server_ip=server_ip, server_port=server_port, key=self.preset_key,
            )
            self.flows[fk] = flow
            self.session_logger.log(f"[flow] new flow={flow.flow_id}")
            if self.preset_key:
                write_key_file(self.key_file, self.preset_key, flow.flow_id)
                self.session_logger.log(
                    f"[key] preset key active flow={flow.flow_id} key_hex={self.preset_key.hex()} "
                    f"key_ascii={printable_ascii(self.preset_key) or '<non-ascii>'}"
                )
        for be21 in flow.direction_state(direction).feed(int(packet[TCP].seq), payload):
            self._handle_be21(flow, be21, packet, frame_no)

    def _handle_be21(self, flow: FlowState, be21: Be21Packet, packet, frame_no: int | None) -> None:
        # Key 提取
        if be21.cmd == 0x1002 and len(be21.header_extra) >= 18:
            key = be21.header_extra[2:18]
            dedupe = (be21.seq, key.hex())
            if dedupe not in flow.seen_acks:
                flow.seen_acks.add(dedupe)
                flow.key = key
                self.key_hits += 1
                write_key_file(self.key_file, key, flow.flow_id)
                self.session_logger.log(
                    f"[ack_0x1002] flow={flow.flow_id} dir={be21.direction} seq={be21.seq} "
                    f"key_hex={key.hex()} key_ascii={printable_ascii(key) or '<non-ascii>'}"
                )
                if self.stop_after_key:
                    self.should_stop = True
        # 解析
        if self.csv_sink is not None or self.analysis_listener is not None:
            ri = self.decoded_rows
            row, parsed_info = self._decode_be21(flow, be21, packet, frame_no)
            if self.analysis_listener and parsed_info:
                self.analysis_listener.handle(ri, row, parsed_info)
            if self.csv_sink:
                self.csv_sink.write_row(row)
            self.decoded_rows += 1

    # ------------------------------------------------------------------
    # 解密 + 解析（改进的错误处理）
    # ------------------------------------------------------------------

    def _decode_be21(self, flow: FlowState, be21: Be21Packet, packet, frame_no: int | None
                     ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        row = self._build_base_row(flow, be21, packet, frame_no)

        if be21.cmd != 0x4013:
            row["decrypt_status"] = "not_4013"
            return row, None
        if flow.key is None:
            row["decrypt_status"] = "no_key"
            return row, None
        try:
            iv, plain = decrypt_4013_body(flow.key, be21.body)
        except ValueError as exc:
            # 解密失败——可能是 key 错误或数据截断
            self._record_error(f"decrypt_fail:{exc}", be21.seq)
            row["decrypt_status"] = f"decrypt_error:{exc}"
            return row, None

        row.update({
            "decrypt_status": "ok", "iv_hex": iv.hex(),
            "cipher_hex": be21.body[16:].hex(), "decrypted_body_hex": plain.hex(),
        })

        try:
            parsed_info = self._parse_decrypted(row, flow, be21, packet, frame_no, plain)
            self._consecutive_errors = 0  # 成功则重置连续错误计数
            return row, parsed_info
        except Exception as exc:
            self._record_error(f"parse_error:{exc}", be21.seq)
            row["decrypt_status"] = f"parse_error:{exc}"
            return row, None

    def _record_error(self, error_msg: str, seq: int) -> None:
        """记录错误并在连续失败时告警。"""
        self._consecutive_errors += 1
        self._total_errors += 1
        logger.warning("Packet seq=%s error: %s (consecutive=%d total=%d)",
                       seq, error_msg, self._consecutive_errors, self._total_errors)
        if self._consecutive_errors >= _ERROR_ALERT_THRESHOLD and not self._error_alerted:
            self._error_alerted = True
            self.session_logger.log(
                f"[ALERT] {self._consecutive_errors} consecutive decode errors — "
                f"key may be wrong or protocol changed. Total errors: {self._total_errors}"
            )

    def _build_base_row(self, flow: FlowState, be21: Be21Packet, packet, frame_no: int | None) -> dict[str, Any]:
        return {
            "captured_at": now_text(), "frame_no": frame_no or "",
            "packet_time": f"{float(packet.time):.6f}" if hasattr(packet, "time") else "",
            "flow_id": flow.flow_id, "client_ip": flow.client_ip, "client_port": flow.client_port,
            "server_ip": flow.server_ip, "server_port": flow.server_port,
            "direction": be21.direction, "stream_offset": be21.stream_offset,
            "seq": be21.seq, "cmd": be21.cmd, "cmd_hex": f"0x{be21.cmd:04X}",
            "hdr_len": be21.hdr_len, "body_len": be21.body_len,
            "header_extra_hex": be21.header_extra.hex(), "body_hex": be21.body.hex(),
            "key_hex": flow.key.hex() if flow.key else "",
            "key_ascii": printable_ascii(flow.key) if flow.key else "",
            **{k: "" for k in (
                "decrypt_status", "iv_hex", "cipher_hex", "decrypted_body_hex",
                "protocol_direction", "opcode", "opcode_hex", "subtype", "magic_hex",
                "req_seq", "payload_len", "root_clean", "inner_message_id",
                "summary_kind", "summary_text", "summary_json", "record_json", "root_json",
            )},
        }

    def _parse_decrypted(self, row: dict[str, Any], flow: FlowState, be21: Be21Packet,
                         packet, frame_no: int | None, plain: bytes) -> dict[str, Any] | None:
        pkt_dict = {
            "cmd": 0x4013, "cmd_hex": "0x4013", "direction": be21.direction,
            "seq": be21.seq, "body_len": be21.body_len,
            "header_extra_hex": be21.header_extra.hex(), "first_frame": frame_no,
            "first_time": float(packet.time) if hasattr(packet, "time") else None,
            "decrypted_body_hex": plain.hex(),
        }
        record = proto.parse_record(pkt_dict)
        if record is None:
            row["decrypt_status"] = "ok_unparsed"
            return None

        row.update({
            "protocol_direction": record.get("direction", ""),
            "opcode": record.get("opcode", ""),
            "opcode_hex": record.get("opcode_hex", ""),
            "subtype": record.get("subtype", ""),
            "magic_hex": record.get("magic_hex", ""),
            "req_seq": record.get("req_seq", ""),
            "payload_len": record.get("payload_len", ""),
            "root_clean": record.get("root", {}).get("clean", ""),
        })

        inner = None
        if record.get("opcode") == 0x0414:
            inner = proto.extract_inner_message(record["root"])
            if inner:
                row["inner_message_id"] = inner.get("message_id", "")

        sk, so = self._summarize(record, inner)
        row.update({
            "summary_kind": sk,
            "summary_text": self._fmt_text(sk, so),
            "summary_json": json.dumps(so, ensure_ascii=False),
            "record_json": json.dumps(dict(record), ensure_ascii=False),
            "root_json": json.dumps(record.get("root"), ensure_ascii=False),
        })
        return {"record": record, "inner": inner, "summary_kind": sk, "summary_obj": so}

    # ------------------------------------------------------------------
    # opcode dispatch（注册表驱动）
    # ------------------------------------------------------------------

    def _summarize(self, record: dict[str, Any], inner: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
        op = int(record.get("opcode", 0))

        # 0x0414 走 inner 注册表
        if op == 0x0414 and inner is not None:
            mid = inner.get("message_id")
            entry = _INNER_REGISTRY.get(mid)
            if entry:
                kind, func = entry
                return kind, func(inner)
            return "inner_unknown", {"message_id": mid}

        # 其他 opcode 走主注册表
        entry = _OPCODE_REGISTRY.get(op)
        if entry:
            kind, func = entry
            return kind, func(record, inner)

        return "opcode_only", {"opcode_hex": record.get("opcode_hex")}

    def _fmt_text(self, sk: str, so: dict[str, Any]) -> str:
        formatter = _FMT_REGISTRY.get(sk)
        if formatter:
            return formatter(so)
        return so.get("opcode_hex", "") or sk
