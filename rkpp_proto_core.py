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

"""Protocol parsing core: transport/layout parsing, proto-tree primitives, and inner-message parsing."""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

import Data  # CSV 名称映射，延迟到首次查询时加载

logger = logging.getLogger(__name__)

# ===========================================================================
# [1] 底层 proto 原语
# ===========================================================================

def read_varint(data: bytes, off: int) -> tuple[int, int]:
    value = shift = 0
    cur = off
    while cur < len(data):
        byte = data[cur]
        cur += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, cur
        shift += 7
        if shift > 63:
            raise ValueError(f"varint too large at offset 0x{off:X}")
    raise ValueError(f"unterminated varint at offset 0x{off:X}")


def maybe_utf8(blob: bytes) -> str | None:
    if not blob:
        return None
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return None if any(ord(c) < 0x20 and c not in "\r\n\t" for c in text) else text


def strip_tsf4g_padding(data: bytes) -> bytes:
    """移除腾讯 TSF4G 协议的尾部填充。"""
    marker = b"tsf4g"
    if data.rfind(marker) == len(data) - 6:
        pad = data[-1]
        # TSF4G 尾巴形如 "<校验/填充字节>tsf4g<N>"，N 是整个尾部长度。
        # 历史抓包中常见 N=6；实测 live-decode 中也会出现 N=8/9/18。
        if len(marker) + 1 <= pad <= 64 and len(data) >= pad:
            return data[:-pad]
        if pad == 1:
            return data[:-1]
        if 0 < pad <= 16 and len(data) >= pad and all(b == pad for b in data[-pad:]):
            return data[:-pad]
    return data


def tsf4g_trailer_len(data: bytes) -> int:
    """返回可识别的 TSF4G 尾部长度；无尾部时返回 0。"""
    marker = b"tsf4g"
    if data.rfind(marker) != len(data) - 6:
        return 0
    pad = data[-1]
    if len(marker) + 1 <= pad <= 64 and len(data) >= pad:
        return pad
    if pad == 1:
        return 1
    if 0 < pad <= 16 and len(data) >= pad and all(b == pad for b in data[-pad:]):
        return pad
    return 0


def normalize_c2s_opcode(opcode: int) -> tuple[int, bool]:
    """标准 c2s 帧可携带 0x0001xxxx 形式，语义表使用低 16 位 opcode。"""
    low16 = opcode & 0xFFFF
    if opcode > 0xFFFF and (opcode >> 16) == 0x0001 and low16:
        return low16, True
    return opcode, False


TGCP_COMMAND_NAMES: dict[int, str] = {
    0x1001: "SYN",
    0x1002: "ACK",
    0x2001: "AUTH_REQ",
    0x2002: "AUTH_RSP",
    0x4013: "DATA",
    0x5002: "SSTOP",
    0x6002: "BINGO",
    0x9001: "HEARTBEAT",
}

SSTOP_CODE_NAMES: dict[int, str] = {
    0x11: "AUTH_INVALID",
    0x12: "AUTH_REQUIRED",
}


def tgcp_command_name(cmd: int) -> str:
    return TGCP_COMMAND_NAMES.get(cmd, f"UNKNOWN_0x{cmd:04X}")


def sstop_code_name(code: int) -> str:
    return SSTOP_CODE_NAMES.get(code, f"UNKNOWN_0x{code:02X}")


def parse_sstop_body(body: bytes) -> dict[str, Any]:
    detail: dict[str, Any] = {"body_len": len(body)}
    if len(body) < 18:
        detail["parse_status"] = "truncated"
        detail["body_hex"] = body.hex()
        return detail
    code = int.from_bytes(body[0:4], "big")
    ex_error_code = int.from_bytes(body[4:8], "big")
    tconnd_ip_raw = body[8:12]
    tconnd_port = int.from_bytes(body[12:14], "big")
    tconnd_id_len = int.from_bytes(body[14:18], "big")
    detail.update({
        "code": code,
        "code_name": sstop_code_name(code),
        "ex_error_code": ex_error_code,
        "tconnd_ip_raw_hex": tconnd_ip_raw.hex(),
        "tconnd_ip": ".".join(str(b) for b in tconnd_ip_raw),
        "tconnd_port": tconnd_port,
        "tconnd_id_len": tconnd_id_len,
    })
    end = 18 + tconnd_id_len
    if tconnd_id_len < 0 or end > len(body):
        detail["parse_status"] = "truncated_tconnd_id"
        detail["body_hex"] = body.hex()
        return detail
    tconnd_id = body[18:end]
    tconnd_id_text = maybe_utf8(tconnd_id.rstrip(b"\x00"))
    detail["tconnd_id_hex"] = tconnd_id.hex()
    if tconnd_id_text is not None:
        detail["tconnd_id"] = tconnd_id_text
    detail["parse_status"] = "ok"
    if end < len(body):
        detail["trailing_hex"] = body[end:].hex()
    return detail


def parse_tgcp_control_packet(packet: dict[str, Any]) -> dict[str, Any] | None:
    cmd = int(packet.get("cmd", 0) or 0)
    if cmd == 0x4013:
        return None
    header_extra = bytes.fromhex(packet.get("header_extra_hex") or "")
    body = bytes.fromhex(packet.get("body_hex") or "")
    record: dict[str, Any] = {
        "record_type": "tgcp_control",
        "transport_kind": "tgcp_control",
        "transport_layout": "be21_control",
        "seq": packet.get("seq"),
        "direction": packet.get("direction"),
        "first_frame": packet.get("first_frame"),
        "first_time": packet.get("first_time"),
        "cmd": cmd,
        "cmd_hex": f"0x{cmd:04X}",
        "tgcp_command_name": tgcp_command_name(cmd),
        "header_extra_len": len(header_extra),
        "body_len": len(body),
        "header_extra_hex": header_extra.hex(),
        "body_hex": body.hex(),
    }
    if cmd == 0x1002 and len(header_extra) >= 18:
        key = header_extra[2:18]
        record["session_key_hex"] = key.hex()
        if all(32 <= b < 127 for b in key):
            record["session_key_ascii"] = key.decode("ascii", errors="ignore")
    elif cmd == 0x5002:
        record["sstop"] = parse_sstop_body(body)
    return record


def parse_special_payload(opcode: int, payload: bytes) -> tuple[str, dict[str, Any]] | None:
    """解析少量已确认不是 protobuf 线格式的定长控制帧。"""
    if opcode == 0x013D and len(payload) == 12:
        return "s2c_heartbeat_nty_binary", {
            "heartbeat_seq": int.from_bytes(payload[0:8], "little"),
            "server_logic_tick_ivl": int.from_bytes(payload[8:12], "little", signed=True),
        }
    if opcode == 0x013F and len(payload) == 40:
        return "s2c_heartbeat_result_binary", {
            "ret_info": {"ret_code": int.from_bytes(payload[0:4], "little")},
            "heartbeat_seq": int.from_bytes(payload[4:12], "little"),
            "server_time": int.from_bytes(payload[12:20], "little"),
            "trans_delay_time": int.from_bytes(payload[20:24], "little", signed=True),
            "avg_trans_delay_time": int.from_bytes(payload[24:28], "little", signed=True),
            "server_logic_frame": int.from_bytes(payload[28:36], "little"),
            "tail_u32": int.from_bytes(payload[36:40], "little"),
        }
    return None


def maybe_signed64(value: int) -> int:
    return value - (1 << 64) if value >= (1 << 63) else value


def parse_proto_message(
    data: bytes,
    *,
    depth: int = 0,
    max_depth: int = 10,
    max_fields: int = 5000,
) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    off, clean = 0, True
    while off < len(data):
        if len(fields) >= max_fields:
            clean = False
            break
        start = off
        try:
            tag, off = read_varint(data, off)
        except ValueError:
            clean = False
            break
        field_no, wire_type = tag >> 3, tag & 7
        entry: dict[str, Any] = {"field": field_no, "wire": wire_type, "offset": start}
        try:
            if wire_type == 0:
                entry["value"], off = read_varint(data, off)
            elif wire_type == 1:
                if off + 8 > len(data):
                    clean = False
                    break
                entry["raw_hex"] = data[off:off + 8].hex()
                off += 8
            elif wire_type == 2:
                blen, off = read_varint(data, off)
                if off + blen > len(data):
                    clean = False
                    break
                blob = data[off:off + blen]
                off += blen
                entry["len"] = blen
                entry["raw_hex"] = blob.hex()
                text = maybe_utf8(blob)
                if text is not None:
                    entry["text"] = text
                elif depth < max_depth and blob:
                    sub = parse_proto_message(
                        blob,
                        depth=depth + 1,
                        max_depth=max_depth,
                        max_fields=max_fields,
                    )
                    if sub["fields"] and sub["consumed"] == len(blob):
                        entry["sub"] = sub
            elif wire_type == 5:
                if off + 4 > len(data):
                    clean = False
                    break
                blob = data[off:off + 4]
                off += 4
                entry["raw_hex"] = blob.hex()
                entry["u32le"] = int.from_bytes(blob, "little")
            else:
                clean = False
                break
        except ValueError:
            clean = False
            break
        fields.append(entry)
    return {"fields": fields, "consumed": off, "clean": clean and off == len(data)}


def walk_messages(msg: dict[str, Any], path: str = "root") -> list[tuple[str, dict[str, Any]]]:
    out = [(path, msg)]
    per_field: dict[int, int] = defaultdict(int)
    for entry in msg["fields"]:
        sub = entry.get("sub")
        if sub is None:
            continue
        per_field[entry["field"]] += 1
        out.extend(walk_messages(sub, f"{path}.{entry['field']}[{per_field[entry['field']]}]"))
    return out


def field_groups(msg: dict[str, Any] | None) -> dict[int, list[dict[str, Any]]]:
    """Group parse-tree fields by field number, cached per message."""
    if msg is None:
        return {}
    cached = msg.get("_groups")
    if isinstance(cached, dict):
        return cached
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for entry in msg["fields"]:
        grouped[entry["field"]].append(entry)
    cached = dict(grouped)
    msg["_groups"] = cached
    return cached

def collect_varints(msg: dict[str, Any] | None, field_no: int) -> list[int]:
    return [e["value"] for e in field_groups(msg).get(field_no, []) if "value" in e]


def first_text(msg: dict[str, Any], field_no: int) -> str | None:
    for e in field_groups(msg).get(field_no, []):
        if e.get("text"):
            return e["text"]
    return None


def first_sub(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((e["sub"] for e in entries if e.get("sub") is not None), None)


def pick_first(values: list[int], *, low: int | None = None, high: int | None = None) -> int | None:
    for v in values:
        if (low is None or v >= low) and (high is None or v <= high):
            return v
    return values[0] if values else None


# ===========================================================================
# [2] 战斗协议
# ===========================================================================

STAT_NAMES = ["HP", "ATK", "DEF", "SPA", "SPD", "SPE"]
SIDE_NAMES = {1: "我方", 401: "敌方"}

# 特殊动作识别表
# COMMANDS 表：通过 c2s command_flag 和 command_slot 字段识别
SPECIAL_ACTION_COMMANDS: dict[tuple[int, int], str] = {
    (8, 7): "愿力强化", (3, 8): "能量瓶", (2, 9): "换人",
}
# SHAPES 表：通过 payload 内部 kind 和 branch 字段识别
SPECIAL_ACTION_SHAPES: dict[tuple[int, int], str] = {
    (8, 8): "愿力强化", (3, 4): "能量瓶", (2, 3): "换人",
}

# 愿力强化对应的特殊技能 ID
_WILLPOWER_SKILL_ID = 7700014

# 能量瓶触发条件：能量回满到 10 且 delta > 0
_ENERGY_BOTTLE_MAX = 10


# --- 名称查找 ---

def normalize_skill_id(v: int | None) -> int | None:
    if v is None:
        return None
    return v // 100 if v >= 100_000 and v % 100 == 0 else v

def skill_name(skill_id: int | None) -> str | None:
    return Data.get_skill_name(skill_id)

def type_name(type_id: int | None) -> str | None:
    return Data.get_attr_name(type_id)

def pet_name(pet_id: int | None) -> str | None:
    return Data.get_pet_name(pet_id)

def skill_meta(skill_id: int | None) -> dict[str, Any] | None:
    return Data.get_skill_meta(skill_id)

def buff_name(buff_id: int | None) -> str | None:
    meta = Data.get_buff_meta(buff_id)
    return meta.get("name") if isinstance(meta, dict) and isinstance(meta.get("name"), str) else None

def buffbase_name(buffbase_id: int | None) -> str | None:
    meta = Data.get_buffbase_meta(buffbase_id)
    return meta.get("editor_name") if isinstance(meta, dict) and isinstance(meta.get("editor_name"), str) else None

def side_name(side_id: int | None) -> str | None:
    return None if side_id is None else SIDE_NAMES.get(int(side_id))

def summarize_types(type_ids: list[int] | None) -> list[str]:
    if not type_ids:
        return []
    out: list[str] = []
    for type_id in type_ids:
        name = type_name(type_id)
        out.append(f"{name}({type_id})" if name else str(type_id))
    return out


def _attach_skill_meta(out: dict[str, Any], skill_id: int | None) -> None:
    if skill_id is None:
        return
    name = skill_name(skill_id)
    if name and not out.get("skill_name"):
        out["skill_name"] = name
    meta = skill_meta(skill_id)
    if not meta:
        return
    for src, dst in (
        ("desc", "skill_desc"),
        ("energy_cost", "skill_energy_cost"),
        ("target_type", "skill_target_type"),
        ("target_count", "skill_target_count"),
        ("skill_priority", "skill_priority"),
        ("damage_type", "skill_damage_type"),
        ("skill_feature", "skill_feature"),
        ("cd_round", "skill_cd_round"),
    ):
        if src in meta and dst not in out:
            out[dst] = meta[src]


def _attach_buff_meta(out: dict[str, Any], buff_id: int | None, *, prefix: str = "effect") -> None:
    if buff_id is None:
        return
    meta = Data.get_buff_meta(buff_id)
    if not isinstance(meta, dict):
        return
    name_key = f"{prefix}_name"
    desc_key = f"{prefix}_desc"
    if isinstance(meta.get("name"), str) and name_key not in out:
        out[name_key] = meta["name"]
    if isinstance(meta.get("desc"), str) and desc_key not in out:
        out[desc_key] = meta["desc"]
    if meta.get("type_id") is not None and f"{prefix}_type_id" not in out:
        out[f"{prefix}_type_id"] = meta["type_id"]


def _attach_buffbase_meta(out: dict[str, Any], buffbase_id: int | None, *, prefix: str = "effect_base") -> None:
    if buffbase_id is None:
        return
    name = buffbase_name(buffbase_id)
    if name and f"{prefix}_name" not in out:
        out[f"{prefix}_name"] = name


# --- 公共辅助：提取 actor/target side ---

def _extract_actor_target(msg: dict[str, Any], out: dict[str, Any]) -> None:
    """从一个包含 field 1=actor_side, field 2=target_side 的消息中提取双方信息。"""
    out["actor_side"] = pick_first(collect_varints(msg, 1))
    out["actor_side_name"] = side_name(out.get("actor_side"))
    out["target_side"] = pick_first(collect_varints(msg, 2))
    out["target_side_name"] = side_name(out.get("target_side"))


# --- 技能 / 属性提取 ---

def extract_skills(msg: dict[str, Any]) -> list[dict[str, Any]]:
    skills, seen = [], set()
    for entry in field_groups(msg).get(12, []):
        sub = entry.get("sub")
        if sub is None:
            continue
        for child in sub["fields"]:
            cs = child.get("sub")
            if cs is None:
                continue
            sid = pick_first(collect_varints(cs, 1), low=1_000_000)
            if sid is None:
                continue
            slot = pick_first(collect_varints(cs, 5), low=0, high=8) or 0
            pp   = pick_first(collect_varints(cs, 8), low=0, high=99)
            key  = (sid, slot, pp)
            if key in seen:
                continue
            seen.add(key)
            item = {"skill_id": sid, "equipped_slot": slot, "pp": pp}
            _attach_skill_meta(item, sid)
            skills.append(item)
    skills.sort(key=lambda it: (it["equipped_slot"] == 0, it["equipped_slot"], it["skill_id"]))
    return skills


def extract_stats(msg: dict[str, Any]) -> list[dict[str, Any]]:
    best: list[dict[str, Any]] = []
    for entry in field_groups(msg).get(14, []):
        sub = entry.get("sub")
        if sub is None:
            continue
        stats = []
        for idx in range(1, 7):
            sf = field_groups(sub).get(idx, [])
            if not sf:
                continue
            ss = sf[0].get("sub")
            if ss is None:
                continue
            base  = pick_first(collect_varints(ss, 1), low=0, high=9999)
            calc  = pick_first(collect_varints(ss, 3), low=0, high=99999)
            bonus = pick_first(collect_varints(ss, 6), low=0, high=99999)
            total = (calc + bonus) if calc is not None and bonus is not None else calc
            stats.append({"index": idx, "name": STAT_NAMES[idx - 1], "base": base,
                          "calc": calc, "bonus": bonus, "total": total})
        if len(stats) > len(best):
            best = stats
    return best


def extract_dynamic_skill_entries(dynamic_msg: dict[str, Any]) -> list[dict[str, Any]]:
    out, seen = [], set()
    for fn in (8, 73):
        for entry in field_groups(dynamic_msg).get(fn, []):
            sub = entry.get("sub")
            if sub is None:
                continue
            sid = pick_first(collect_varints(sub, 39), low=100_000)
            if sid is None:
                continue
            slot = pick_first(collect_varints(sub, 25), low=0, high=20) or 0
            aux26 = aux27 = None
            s26 = field_groups(sub).get(26, [])
            if s26 and s26[0].get("sub"):
                aux26 = pick_first(collect_varints(s26[0]["sub"], 2))
            s27 = field_groups(sub).get(27, [])
            if s27 and s27[0].get("sub"):
                aux27 = pick_first(collect_varints(s27[0]["sub"], 2))
            key = (sid, slot, fn)
            if key in seen:
                continue
            seen.add(key)
            item = {"skill_id": sid, "slot": slot, "aux26": aux26, "aux27": aux27, "source_field": fn}
            _attach_skill_meta(item, sid)
            out.append(item)
    out.sort(key=lambda it: (it["slot"], it["skill_id"]))
    return out


# --- 精灵 / 状态包装器 ---

def extract_creature(msg: dict[str, Any], *, path: str, record: dict[str, Any]) -> dict[str, Any] | None:
    name  = first_text(msg, 3)
    level = pick_first(collect_varints(msg, 10), low=1, high=100)
    if not name or level is None:
        return None
    slot  = pick_first(collect_varints(msg, 1), low=0, high=999)
    pid   = pick_first(collect_varints(msg, 2), low=1000)
    stats = extract_stats(msg)
    all_skills = extract_skills(msg)
    equipped   = [it for it in all_skills if 1 <= it["equipped_slot"] <= 4]
    out = {
        "name": name, "level": level, "slot": slot, "pet_id": pid,
        "types": collect_varints(msg, 6),
        "stats": stats, "max_hp": stats[0]["total"] if stats else None,
        "skills": all_skills,
        "equipped_skills": sorted(equipped, key=lambda it: (it["equipped_slot"], it["skill_id"])),
        "source_opcode": record["opcode"], "source_opcode_hex": record["opcode_hex"],
        "seq": record["seq"], "path": path,
    }
    pet_meta = Data.get_pet_meta(pid)
    if isinstance(pet_meta, dict):
        if pet_meta.get("base_id") is not None:
            out["base_id"] = pet_meta["base_id"]
        if pet_meta.get("pet_info_id") is not None:
            out["pet_info_id"] = pet_meta["pet_info_id"]
        if out.get("base_id") is not None:
            skill_pool = Data.get_pet_skill_meta(out["base_id"])
            if isinstance(skill_pool, dict):
                out["base_skill_pool"] = skill_pool.get("level_skills") or []
    return out


def extract_state_wrapper(msg: dict[str, Any], *, path: str, record: dict[str, Any]) -> dict[str, Any] | None:
    groups = field_groups(msg)
    se = next((e for e in groups.get(1, []) if e.get("sub")), None)
    ce = next((e for e in groups.get(2, []) if e.get("sub")), None)
    if se is None or ce is None:
        return None
    creature = extract_creature(ce["sub"], path=f"{path}.2[*]", record=record)
    if creature is None:
        return None
    dm = se["sub"]
    ds = collect_varints(dm, 6)
    return {
        "name": creature["name"], "level": creature["level"],
        "slot": creature["slot"], "pet_id": creature["pet_id"],
        "types": creature.get("types", []),
        "battle_stats":   ds[1:7]  if len(ds) >= 7  else [],
        "battle_max_hp":  ds[1]    if len(ds) >= 2  else None,
        "current_hp":     ds[25]   if len(ds) >= 26 else None,
        "dynamic_skills": extract_dynamic_skill_entries(dm),
        "source_opcode": record["opcode"], "source_opcode_hex": record["opcode_hex"],
        "seq": record["seq"], "first_frame": record.get("first_frame"),
        "first_time": record.get("first_time"), "path": path,
    }


def extract_state_wrappers_from_record(record: dict[str, Any]) -> list[dict[str, Any]]:
    wrappers = []
    for path, msg in walk_messages(record["root"]):
        w = extract_state_wrapper(msg, path=path, record=record)
        if w is not None:
            wrappers.append(w)
    return dedupe_state_wrappers(wrappers)


def dedupe_state_wrappers(wrappers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out, seen = [], set()
    for it in wrappers:
        key = (it.get("name"), it.get("level"), it.get("slot"), it.get("pet_id"),
               tuple(it.get("battle_stats") or []), it.get("battle_max_hp"), it.get("current_hp"))
        if key not in seen:
            seen.add(key)
            out.append(it)
    out.sort(key=lambda it: (it.get("slot") is None, int(it.get("slot") or 0), int(it.get("pet_id") or 0)))
    return out


# --- 记录解析 ---

def extract_inner_message(msg: dict[str, Any]) -> dict[str, Any] | None:
    if not msg["fields"]:
        return None
    fs = msg["fields"][0].get("sub")
    if fs is None or len(fs["fields"]) != 1:
        return None
    wrapper = fs["fields"][0]
    ws = wrapper.get("sub")
    return {"message_id": wrapper["field"], "fields": ws["fields"]} if ws else None


def _empty_root() -> dict[str, Any]:
    return {"fields": [], "consumed": 0, "clean": True}


def _build_payload_root(opcode: int, payload: bytes) -> tuple[dict[str, Any], str, dict[str, Any] | None]:
    special = parse_special_payload(opcode, payload)
    if special:
        return {"fields": [], "consumed": len(payload), "clean": True}, special[0], special[1]
    if not payload:
        return _empty_root(), "protobuf", None
    return parse_proto_message(payload), "protobuf", None


def _is_probable_live_s2c_opcode(opcode: int) -> bool:
    return 0 < opcode <= 0xFFFF


def _is_probable_live_c2s_raw_opcode(raw_opcode: int) -> bool:
    if raw_opcode <= 0:
        return False
    return (raw_opcode >> 16) in {0x0000, 0x0001} and (raw_opcode & 0xFFFF) != 0


def _parse_record_v14(body: bytes, common: dict[str, Any]) -> dict[str, Any] | None:
    if len(body) < 0x1E or body[4:6] != b"\x55\xaa" or body[24:26] != b"\x39\x63":
        return None
    reserved = int.from_bytes(body[10:12], "big")
    version = int.from_bytes(body[12:16], "big")
    record_len = int.from_bytes(body[6:10], "big")
    raw_payload = body[30:]
    trailer_len = tsf4g_trailer_len(raw_payload)
    no_trailer_len = len(body) - trailer_len
    if reserved != 0 or version not in {0, 1} or record_len != no_trailer_len - 4:
        return None

    transport_seq = int.from_bytes(body[0:4], "big")
    session_id = int.from_bytes(body[16:20], "big")
    sub_id = int.from_bytes(body[20:24], "big")
    req_seq = int.from_bytes(body[26:30], "big")
    payload = strip_tsf4g_padding(raw_payload)

    if common["direction"] == "c2s":
        raw_opcode = sub_id
        opcode, normalized = normalize_c2s_opcode(raw_opcode)
    else:
        raw_opcode = session_id
        opcode = session_id & 0xFFFF
        normalized = False

    root, payload_format, special_payload = _build_payload_root(opcode, payload)
    return {
        **common,
        "record_type": "business",
        "transport_kind": "tgcp_data",
        "transport_layout": "tgcp_4013_v14",
        "transport_seq": transport_seq,
        "record_len": record_len,
        "record_len_matches": True,
        "session_id": session_id,
        "session_id_hex": f"0x{session_id:08X}",
        "sub_id": sub_id,
        "sub_id_hex": f"0x{sub_id:08X}",
        "opcode": opcode,
        "opcode_hex": f"0x{opcode:04X}",
        "raw_opcode": raw_opcode,
        "raw_opcode_hex": f"0x{raw_opcode:08X}",
        "opcode_normalized": normalized,
        "subtype": sub_id,
        "magic": 0x3963,
        "magic_hex": "0x3963",
        "req_seq": req_seq,
        "payload_len": len(payload),
        "payload_trailer_len": trailer_len,
        "payload_format": payload_format,
        "special_payload": special_payload,
        "root": root,
    }


def _parse_record_live_s2c(body: bytes, common: dict[str, Any]) -> dict[str, Any] | None:
    if common["direction"] != "s2c" or len(body) < 10 or body[4:6] != b"\x55\xaa":
        return None
    opcode = int.from_bytes(body[0:4], "big")
    if not _is_probable_live_s2c_opcode(opcode):
        return None
    subtype = int.from_bytes(body[6:10], "big")
    raw_payload = body[10:]
    trailer_len = tsf4g_trailer_len(raw_payload)
    payload = strip_tsf4g_padding(raw_payload)
    root, payload_format, special_payload = _build_payload_root(opcode, payload)
    return {
        **common,
        "record_type": "business",
        "transport_kind": "tgcp_data",
        "transport_layout": "tgcp_4013_live_s2c",
        "opcode": opcode,
        "opcode_hex": f"0x{opcode:04X}",
        "subtype": subtype,
        "subtype_hex": f"0x{subtype:08X}",
        "magic": 0x55AA,
        "magic_hex": "0x55AA",
        "payload_len": len(payload),
        "payload_trailer_len": trailer_len,
        "payload_format": payload_format,
        "special_payload": special_payload,
        "root": root,
    }


def _parse_record_live_c2s(body: bytes, common: dict[str, Any]) -> dict[str, Any] | None:
    if common["direction"] != "c2s" or len(body) < 14 or body[8:10] != b"\x39\x63":
        return None
    prefix_u32 = int.from_bytes(body[0:4], "big")
    raw_opcode = int.from_bytes(body[4:8], "big")
    if not _is_probable_live_c2s_raw_opcode(raw_opcode):
        return None
    opcode, normalized = normalize_c2s_opcode(raw_opcode)
    req_seq = int.from_bytes(body[10:14], "big")
    raw_payload = body[14:]
    trailer_len = tsf4g_trailer_len(raw_payload)
    payload = strip_tsf4g_padding(raw_payload)
    root, payload_format, special_payload = _build_payload_root(opcode, payload)
    return {
        **common,
        "record_type": "business",
        "transport_kind": "tgcp_data",
        "transport_layout": "tgcp_4013_live_c2s",
        "transport_seq": prefix_u32,
        "prefix_u32": prefix_u32,
        "prefix_u32_hex": f"0x{prefix_u32:08X}",
        "opcode": opcode,
        "opcode_hex": f"0x{opcode:04X}",
        "raw_opcode": raw_opcode,
        "raw_opcode_hex": f"0x{raw_opcode:08X}",
        "opcode_normalized": normalized,
        "magic": 0x3963,
        "magic_hex": "0x3963",
        "req_seq": req_seq,
        "payload_len": len(payload),
        "payload_trailer_len": trailer_len,
        "payload_format": payload_format,
        "special_payload": special_payload,
        "root": root,
    }


def _parse_record_live_c2s_short_heartbeat(body: bytes, common: dict[str, Any]) -> dict[str, Any] | None:
    # Observed in live traffic as:
    #   00 00 00 40 00 00 01 3e 00 00 00 00 00 00 <req_seq_le16> ...
    if common["direction"] != "c2s" or len(body) < 16 or body.find(b"tsf4g", 8) < 0:
        return None
    opcode = int.from_bytes(body[6:8], "big")
    if opcode != 0x013E:
        return None
    req_seq = int.from_bytes(body[14:16], "little")
    leading_u32 = int.from_bytes(body[0:4], "big")
    return {
        **common,
        "record_type": "business",
        "transport_kind": "tgcp_data",
        "transport_layout": "tgcp_4013_live_c2s_short_heartbeat",
        "transport_seq": leading_u32,
        "prefix_u32": leading_u32,
        "prefix_u32_hex": f"0x{leading_u32:08X}",
        "opcode": opcode,
        "opcode_hex": f"0x{opcode:04X}",
        "format": "c2s_short_heartbeat",
        "req_seq": req_seq,
        "payload_len": 0,
        "root": _empty_root(),
    }


def parse_record(packet: dict[str, Any]) -> dict[str, Any] | None:
    if packet.get("cmd") != 0x4013 or not packet.get("decrypted_body_hex"):
        return None
    body = bytes.fromhex(packet["decrypted_body_hex"])
    common = {
        "seq": packet["seq"], "direction": packet["direction"],
        "first_frame": packet.get("first_frame"), "first_time": packet.get("first_time"),
    }
    record = (
        _parse_record_v14(body, common)
        or _parse_record_live_s2c(body, common)
        or _parse_record_live_c2s(body, common)
        or _parse_record_live_c2s_short_heartbeat(body, common)
    )
    if record is None and common["direction"] == "c2s" and len(body) >= 8:
        logger.debug(
            "unsupported c2s frame without recognized transport layout: seq=%s body_len=%d",
            common["seq"], len(body),
        )
    return record


# --- inner 消息解析器 ---

def parse_inner390_detail(inner_fields: list[dict[str, Any]]) -> dict[str, Any] | None:
    """inner message_id=390: 对战配对信息。"""
    cur = {"fields": inner_fields}
    pe = next((e for e in field_groups(cur).get(2, []) if e.get("sub")), None)
    if pe is None:
        return None
    pg = field_groups(pe["sub"])
    detail: dict[str, Any] = {"pair_ctx": pick_first(collect_varints(cur, 1))}
    for side, fn in (("friendly", 3), ("enemy", 4)):
        entries = pg.get(fn, [])
        if entries and entries[0].get("sub"):
            s = entries[0]["sub"]
            pid = pick_first(collect_varints(s, 2))
            base = {"pet_id": pid, "name": pet_name(pid), "side_flag": pick_first(collect_varints(s, 10))}
            for i in range(3, 7):
                base[f"arg{i}"] = pick_first(collect_varints(s, i))
            if side == "enemy":
                base["arg1"] = pick_first(collect_varints(s, 1))
            detail[side] = base
    return detail


def parse_inner200_detail(inner_fields: list[dict[str, Any]]) -> dict[str, Any] | None:
    """inner message_id=200: 提交确认。"""
    cur = {"fields": inner_fields}
    ce = next((e for e in field_groups(cur).get(2, []) if e.get("sub")), None)
    detail: dict[str, Any] = {"pair_ctx": pick_first(collect_varints(cur, 1))}
    if ce:
        c = ce["sub"]
        detail["commit"] = {
            "flag": pick_first(collect_varints(c, 1)),
            "arg2_ms_like": pick_first(collect_varints(c, 2)),
            "event_time_ms": pick_first(collect_varints(c, 3)),
            "code": pick_first(collect_varints(c, 4)),
        }
    return detail if detail.get("pair_ctx") is not None else None


def parse_inner51_detail(inner_fields: list[dict[str, Any]]) -> dict[str, Any] | None:
    """inner message_id=51: 事件通知。"""
    cur = {"fields": inner_fields}
    pe = next((e for e in field_groups(cur).get(2, []) if e.get("sub")), None)
    p = pe["sub"] if pe else None
    detail = {
        "token": pick_first(collect_varints(cur, 1)),
        "kind": pick_first(collect_varints(p, 1)) if p else None,
        "value2": pick_first(collect_varints(p, 2)) if p else None,
        "value3": pick_first(collect_varints(p, 3)) if p else None,
    }
    return detail if detail.get("token") is not None else None


def parse_inner1_detail(inner_fields: list[dict[str, Any]]) -> dict[str, Any] | None:
    """inner message_id=1: 效果/状态变更。"""
    cur = {"fields": inner_fields}
    pe = next((e for e in field_groups(cur).get(11, []) if e.get("sub")), None)
    if pe is None:
        return None
    pg = field_groups(pe["sub"])
    he = next((e for e in pg.get(1, []) if e.get("sub")), None)
    ee = next((e for e in pg.get(3, []) if e.get("sub")), None)
    detail: dict[str, Any] = {}
    if he:
        hs = he["sub"]
        detail["header"] = {
            "kind": pick_first(collect_varints(hs, 1)),
            "actor_token": pick_first(collect_varints(hs, 2)),
            "actor_aux": pick_first(collect_varints(hs, 3)),
            "actor_ref": pick_first(collect_varints(hs, 5)),
            "target_ctx": pick_first(collect_varints(hs, 6)),
            "arg10": pick_first(collect_varints(hs, 10)),
            "arg11": pick_first(collect_varints(hs, 11)),
        }
    if ee:
        es = ee["sub"]
        r31 = pick_first(collect_varints(es, 31))
        detail["effect"] = {
            "effect_id": pick_first(collect_varints(es, 1)),
            "code": pick_first(collect_varints(es, 4)),
            "arg10": pick_first(collect_varints(es, 10)),
            "amount": pick_first(collect_varints(es, 11)),
            "arg12": pick_first(collect_varints(es, 12)),
            "arg13": pick_first(collect_varints(es, 13)),
            "arg15": pick_first(collect_varints(es, 15)),
            "arg16": pick_first(collect_varints(es, 16)),
            "arg27": pick_first(collect_varints(es, 27)),
            "arg31_signed": maybe_signed64(r31) if r31 is not None else None,
            "arg32": pick_first(collect_varints(es, 32)),
        }
    return detail or None


# --- 技能引用 / 特殊动作 ---
