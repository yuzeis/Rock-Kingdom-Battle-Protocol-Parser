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

"""协议解析层：底层 proto 原语 + 战斗协议全部提取函数。

分两段：
  [1] 底层原语   read_varint / parse_proto_message / field_groups / ...
  [2] 战斗协议   extract_* / parse_inner* / parse_record / ...
"""
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
        if 0 < pad <= len(data):
            return data[:-pad]
    return data


def maybe_signed64(value: int) -> int:
    return value - (1 << 64) if value >= (1 << 63) else value


def parse_proto_message(data: bytes, *, depth: int = 0, max_depth: int = 10) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    off, clean = 0, True
    while off < len(data):
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
                    sub = parse_proto_message(blob, depth=depth + 1, max_depth=max_depth)
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
    """按 field number 分组。对同一 msg 多次调用时使用内部缓存。"""
    if msg is None:
        return {}
    # 检查缓存
    cached = msg.get("_grouped")
    if cached is not None:
        return cached
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for entry in msg["fields"]:
        grouped[entry["field"]].append(entry)
    # 转为普通 dict 存入缓存
    result = dict(grouped)
    msg["_grouped"] = result
    return result


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
    return None if skill_id is None else Data.get_maps()["skill"].get(int(skill_id))

def type_name(type_id: int | None) -> str | None:
    return None if type_id is None else Data.get_maps()["attr"].get(int(type_id))

def pet_name(pet_id: int | None) -> str | None:
    return None if pet_id is None else Data.get_maps()["pet"].get(int(pet_id))

def side_name(side_id: int | None) -> str | None:
    return None if side_id is None else SIDE_NAMES.get(int(side_id))

def summarize_types(type_ids: list[int] | None) -> list[str]:
    if not type_ids:
        return []
    return [f"{type_name(t)}({t})" if type_name(t) else str(t) for t in type_ids]


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
            skills.append({"skill_id": sid, "equipped_slot": slot, "pp": pp})
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
            out.append({"skill_id": sid, "slot": slot, "aux26": aux26, "aux27": aux27, "source_field": fn})
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
    return {
        "name": name, "level": level, "slot": slot, "pet_id": pid,
        "types": collect_varints(msg, 6),
        "stats": stats, "max_hp": stats[0]["total"] if stats else None,
        "skills": all_skills,
        "equipped_skills": sorted(equipped, key=lambda it: (it["equipped_slot"], it["skill_id"])),
        "source_opcode": record["opcode"], "source_opcode_hex": record["opcode_hex"],
        "seq": record["seq"], "path": path,
    }


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


def parse_record(packet: dict[str, Any]) -> dict[str, Any] | None:
    if packet.get("cmd") != 0x4013 or not packet.get("decrypted_body_hex"):
        return None
    body = bytes.fromhex(packet["decrypted_body_hex"])
    common = {
        "seq": packet["seq"], "direction": packet["direction"],
        "first_frame": packet.get("first_frame"), "first_time": packet.get("first_time"),
    }
    # s2c：magic 0x55AA at offset 4
    if packet["direction"] == "s2c" and len(body) >= 10 and body[4:6] == b"\x55\xaa":
        op = int.from_bytes(body[0:4], "big")
        sub = int.from_bytes(body[6:10], "big")
        payload = strip_tsf4g_padding(body[10:])
        return {
            **common, "opcode": op, "opcode_hex": f"0x{op:04X}", "subtype": sub,
            "payload_len": len(payload),
            "root": parse_proto_message(payload) if payload else {"fields": [], "consumed": 0, "clean": True},
        }
    # c2s：magic 0x3963 at offset 8（标准格式）
    if packet["direction"] == "c2s" and len(body) >= 14 and body[8:10] == b"\x39\x63":
        magic = int.from_bytes(body[0:4], "big")
        op = int.from_bytes(body[4:8], "big")
        req_seq = int.from_bytes(body[10:14], "big")
        payload = strip_tsf4g_padding(body[14:])
        return {
            **common, "opcode": op, "opcode_hex": f"0x{op:04X}",
            "magic": magic, "magic_hex": f"0x{magic:08X}", "req_seq": req_seq,
            "payload_len": len(payload),
            "root": parse_proto_message(payload) if payload else {"fields": [], "consumed": 0, "clean": True},
        }
    # c2s 兜底：无 0x3963 magic 的简化格式（记录日志以便排查）
    if packet["direction"] == "c2s" and len(body) >= 8:
        op = int.from_bytes(body[4:8], "big")
        payload = strip_tsf4g_padding(body)
        logger.debug(
            "c2s fallback parse: seq=%s opcode=0x%04X body_len=%d (no 0x3963 magic)",
            packet["seq"], op, len(body),
        )
        return {
            **common, "opcode": op, "opcode_hex": f"0x{op:04X}", "payload_len": len(payload),
            "root": parse_proto_message(payload) if payload else {"fields": [], "consumed": 0, "clean": True},
        }
    return None


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

def _extract_skill_ref(msg: dict[str, Any] | None, *, skill_field: int = 3) -> dict[str, Any]:
    if msg is None:
        return {}
    sx100 = pick_first(collect_varints(msg, skill_field), low=100_000)
    sid   = normalize_skill_id(sx100)
    actor = pick_first(collect_varints(msg, 1))
    target = pick_first(collect_varints(msg, 2))
    return {
        "actor_side": actor, "actor_side_name": side_name(actor),
        "target_side": target, "target_side_name": side_name(target),
        "skill_id_x100": sx100, "skill_id": sid, "skill_name": skill_name(sid),
    }


def _extract_special_action(msg: dict[str, Any] | None, *, command_flag: int | None = None,
                             command_slot: int | None = None) -> dict[str, Any] | None:
    if msg is None:
        return None
    groups = field_groups(msg)
    kind  = pick_first(collect_varints(msg, 1), low=0, high=99)
    branch = sub = None
    for fn in (8, 4, 3):
        sub = first_sub(groups.get(fn, []))
        if sub is not None:
            branch = fn
            break
    action = None
    if command_flag is not None and command_slot is not None:
        action = SPECIAL_ACTION_COMMANDS.get((int(command_flag), int(command_slot)))
    if action is None and kind is not None and branch is not None:
        action = SPECIAL_ACTION_SHAPES.get((int(kind), int(branch)))
    if action is None:
        return None
    detail: dict[str, Any] = {
        "action_kind": "special_action", "action_name": action,
        "payload_kind": kind, "payload_branch": branch,
        "command_flag": command_flag, "command_slot": command_slot,
    }
    if sub is not None:
        detail["battle_token"] = pick_first(collect_varints(sub, 1), low=100_000)
        for i in range(1, 6):
            detail[f"arg{i}"] = pick_first(collect_varints(sub, i))
    return detail


def _wrapper_has_skill(wrapper: dict[str, Any], target_id: int) -> bool:
    return any(int(sk.get("skill_id") or 0) == target_id for sk in (wrapper.get("dynamic_skills") or []))


def _infer_action_from_wrappers(wrappers: list[dict[str, Any]]) -> str | None:
    """通过检查 wrapper 中是否存在愿力强化技能 ID 来推断动作。"""
    return "愿力强化" if any(_wrapper_has_skill(w, _WILLPOWER_SKILL_ID) for w in wrappers) else None


# --- opcode 提取函数 ---

def _extract_skill_or_special(record: dict[str, Any], *,
                               extra_fields: dict[str, Any],
                               command_flag: int | None = None,
                               command_slot: int | None = None) -> dict[str, Any] | None:
    """130B 和 1322 共用的技能/特殊动作提取逻辑。"""
    root = record["root"]
    rg = field_groups(root)
    payload   = first_sub(rg.get(2, []))
    skill_msg = first_sub(field_groups(payload).get(2, [])) if payload else None
    if skill_msg:
        info = _extract_skill_ref(skill_msg, skill_field=1)
        if info.get("skill_id") is not None:
            info.update(extra_fields)
            info.update({"opcode": record.get("opcode"), "opcode_hex": record.get("opcode_hex")})
            return info
    info = _extract_special_action(payload, command_flag=command_flag, command_slot=command_slot)
    if info is None:
        return None
    info.update(extra_fields)
    info.update({"opcode": record.get("opcode"), "opcode_hex": record.get("opcode_hex")})
    return info


def extract_130b_skill_select(record: dict[str, Any]) -> dict[str, Any] | None:
    root = record["root"]
    cmd_slot = pick_first(collect_varints(root, 5), low=0, high=20)
    cmd_flag = pick_first(collect_varints(root, 1), low=0, high=20)
    return _extract_skill_or_special(
        record,
        extra_fields={
            "command_slot": cmd_slot, "command_flag": cmd_flag,
            "arg6": pick_first(collect_varints(root, 6)),
        },
        command_flag=cmd_flag, command_slot=cmd_slot,
    )


def extract_1322_skill_declare(record: dict[str, Any]) -> dict[str, Any] | None:
    root = record["root"]
    return _extract_skill_or_special(
        record,
        extra_fields={"battle_token": pick_first(collect_varints(root, 1))},
    )


def extract_130c_result(record: dict[str, Any]) -> dict[str, Any] | None:
    root = record["root"]
    rg = field_groups(root)
    container = first_sub(rg.get(10, []))
    state_msg = first_sub(field_groups(container).get(2, [])) if container else None
    skill_ctn = first_sub(rg.get(11, []))
    skill_msg = first_sub(field_groups(skill_ctn).get(2, [])) if skill_ctn else None
    info: dict[str, Any] = _extract_skill_ref(skill_msg, skill_field=1) if skill_msg else {}
    btok_msg = first_sub(field_groups(container).get(1, [])) if container else None
    info.update({
        "battle_token": pick_first(collect_varints(btok_msg, 1)),
        "current_hp":   pick_first(collect_varints(state_msg, 3),  low=0, high=99999) if state_msg else None,
        "energy_after": pick_first(collect_varints(state_msg, 26), low=0, high=99)    if state_msg else None,
        "result_code":  pick_first(collect_varints(first_sub(rg.get(1, [])), 1), low=0, high=999),
        "opcode": record.get("opcode"), "opcode_hex": record.get("opcode_hex"),
    })
    # 尝试从 skill_ctn 提取特殊动作（用 for 循环代替列表推导式副作用）
    if info.get("action_name") is None:
        sp = _extract_special_action(skill_ctn)
        if sp:
            for k, v in sp.items():
                info.setdefault(k, v)
    wrappers = info.get("state_wrappers") or extract_state_wrappers_from_record(record)
    if wrappers:
        info["state_wrappers"] = wrappers
    # 通过 wrappers 推断愿力强化
    if info.get("action_name") is None:
        inferred = _infer_action_from_wrappers(wrappers or [])
        if inferred:
            info["action_kind"] = "special_action"
            info["action_name"] = inferred
    return info or None


def _extract_1324_entry(sub: dict[str, Any]) -> dict[str, Any]:
    sg = field_groups(sub)
    et = pick_first(collect_varints(sub, 1))
    out: dict[str, Any] = {
        "type": et,
        "index": pick_first(collect_varints(sub, 2)),
        "phase_arg": pick_first(collect_varints(sub, 14)),
        "state_arg": pick_first(collect_varints(sub, 26)),
        "extra_arg": pick_first(collect_varints(sub, 27)),
        "event_ordinal": pick_first(collect_varints(sub, 39)),
    }
    if et == 1:
        out["kind"] = "skill_cast"
        out.update(_extract_skill_ref(first_sub(sg.get(3, [])), skill_field=3))
        ir_sub = first_sub(sg.get(12, []))
        detail = first_sub(field_groups(ir_sub).get(2, [])) if ir_sub else None
        if detail:
            rd = pick_first(collect_varints(detail, 25))
            out["energy_delta"] = maybe_signed64(rd) if rd is not None else None
            out["energy_after"] = pick_first(collect_varints(detail, 26), low=0, high=99)
    elif et == 4:
        out["kind"] = "damage"
        out.update(_extract_skill_ref(first_sub(sg.get(6, [])), skill_field=3))
        dmg = hp = None
        ir = first_sub(sg.get(12, []))
        if ir:
            for child in field_groups(ir).get(2, []):
                cs = child.get("sub")
                if cs is None:
                    continue
                if pick_first(collect_varints(cs, 11)) is not None or pick_first(collect_varints(cs, 13)) is not None:
                    dmg = cs
                elif pick_first(collect_varints(cs, 3)) is not None:
                    hp = cs
        if dmg:
            ro = pick_first(collect_varints(dmg, 12))
            out["damage"] = pick_first(collect_varints(dmg, 11)) or pick_first(collect_varints(dmg, 13))
            out["overflow"] = maybe_signed64(ro) if ro is not None else None
            out["damage_target_side"] = pick_first(collect_varints(dmg, 1))
            out["damage_target_side_name"] = side_name(out.get("damage_target_side"))
        if hp:
            out["target_side"] = pick_first(collect_varints(hp, 1)) or out.get("target_side")
            out["target_side_name"] = side_name(out.get("target_side"))
            out["target_hp_after"] = pick_first(collect_varints(hp, 3), low=0, high=99999)
    elif et == 2:
        out["kind"] = "effect_apply"
        em = first_sub(sg.get(4, []))
        if em:
            _extract_actor_target(em, out)
            out["effect_id"] = pick_first(collect_varints(em, 3))
            out["effect_stage"] = pick_first(collect_varints(em, 4))
        ir = first_sub(sg.get(12, []))
        related = []
        if ir:
            for child in field_groups(ir).get(3, []):
                cs = child.get("sub")
                if not cs:
                    continue
                sx = pick_first(collect_varints(cs, 2), low=100_000)
                sid = normalize_skill_id(sx)
                owner = pick_first(collect_varints(cs, 1))
                related.append({
                    "owner_side": owner,
                    "owner_side_name": side_name(owner),
                    "skill_id_x100": sx, "skill_id": sid, "skill_name": skill_name(sid),
                    "arg3": pick_first(collect_varints(cs, 3)),
                    "arg4": pick_first(collect_varints(cs, 4)),
                })
        if related:
            out["related_skills"] = related
    elif et == 3:
        out["kind"] = "effect_stage"
        em = first_sub(sg.get(5, []))
        if em:
            _extract_actor_target(em, out)
            out["effect_id"] = pick_first(collect_varints(em, 3))
            out["effect_base"] = pick_first(collect_varints(em, 6))
    elif et == 7:
        out["kind"] = "defeat"
        dm = first_sub(sg.get(9, []))
        if dm:
            _extract_actor_target(dm, out)
            out["defeat_arg"] = pick_first(collect_varints(dm, 3))
    elif et == 10:
        out["kind"] = "effect_link"
        lm = first_sub(sg.get(15, []))
        if lm:
            _extract_actor_target(lm, out)
            out["effect_id"] = pick_first(collect_varints(lm, 3))
    return out


def extract_1324_action(record: dict[str, Any]) -> dict[str, Any] | None:
    container = first_sub(field_groups(record["root"]).get(1, []))
    if container is None:
        return None
    cg = field_groups(container)
    entries = [_extract_1324_entry(e["sub"]) for e in cg.get(2, []) if e.get("sub")]
    effect_ids = sorted({int(it["effect_id"]) for it in entries if it.get("effect_id") is not None})
    return {
        "packet_state": pick_first(collect_varints(container, 1)),
        "packet_phase": pick_first(collect_varints(container, 3)),
        "packet_index": pick_first(collect_varints(container, 5)),
        "entries": entries,
        "primary_skill": next((it for it in entries if it.get("skill_id")), None),
        "energy_event":  next((it for it in entries if it.get("kind") == "skill_cast"), None),
        "damage_event":  next((it for it in entries if it.get("kind") == "damage"), None),
        "effect_ids": effect_ids,
        "has_defeat": any(it.get("kind") == "defeat" for it in entries),
        "opcode": record.get("opcode"), "opcode_hex": record.get("opcode_hex"),
    }


def extract_1314_phase(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase_code": pick_first(collect_varints(first_sub(field_groups(record["root"]).get(1, [])), 1), low=0, high=999),
        "opcode": record.get("opcode"), "opcode_hex": record.get("opcode_hex"),
    }


def extract_13f4_refresh(record: dict[str, Any]) -> dict[str, Any] | None:
    container = first_sub(field_groups(record["root"]).get(1, []))
    if container is None:
        return None
    cg = field_groups(container)
    detail: dict[str, Any] = {
        "packet_state": pick_first(collect_varints(container, 1)),
        "packet_phase": pick_first(collect_varints(container, 3)),
        "packet_index": pick_first(collect_varints(container, 5)),
        "skill_options": [],
    }
    for entry in cg.get(2, []):
        sub = entry.get("sub")
        if sub is None:
            continue
        et = pick_first(collect_varints(sub, 1))
        if et == 14:
            meta = first_sub(field_groups(sub).get(19, []))
            if meta:
                detail["battle_token"] = pick_first(collect_varints(meta, 1), low=100_000)
                for i in range(2, 6):
                    detail[f"arg{i}"] = pick_first(collect_varints(meta, i))
            or_ = first_sub(field_groups(sub).get(12, []))
            if or_:
                for se in field_groups(or_).get(3, []):
                    ss = se.get("sub")
                    if not ss:
                        continue
                    sx = pick_first(collect_varints(ss, 2), low=100_000)
                    sid = normalize_skill_id(sx)
                    if sid:
                        detail["skill_options"].append({
                            "skill_id_x100": sx, "skill_id": sid,
                            "skill_name": skill_name(sid),
                            "slot": pick_first(collect_varints(ss, 10), low=0, high=20),
                        })
        elif et == 6:
            ir = first_sub(field_groups(sub).get(12, []))
            info = first_sub(field_groups(ir).get(2, [])) if ir else None
            if info:
                rd = pick_first(collect_varints(info, 25))
                detail["energy_delta"] = maybe_signed64(rd) if rd is not None else None
                detail["energy_after"] = pick_first(collect_varints(info, 26), low=0, high=99)
    detail["skill_options"].sort(key=lambda it: (it.get("slot") is None, int(it.get("slot") or 0), int(it.get("skill_id") or 0)))
    if not detail["skill_options"] and detail.get("energy_delta") is None and detail.get("energy_after") is None:
        return None
    # 启发式：能量回满到最大值且增加 → 能量瓶
    if detail.get("energy_after") == _ENERGY_BOTTLE_MAX and (detail.get("energy_delta") or 0) > 0:
        detail["action_name"] = "能量瓶"
    return detail


def extract_0102_creatures(record: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for outer in field_groups(record["root"]).get(2, []):
        os_ = outer.get("sub")
        if os_ is None:
            continue
        for re_ in field_groups(os_).get(4, []):
            rh = re_.get("raw_hex")
            if not rh:
                continue
            blob = bytes.fromhex(rh)
            off = 0
            while off < len(blob):
                try:
                    tag, off = read_varint(blob, off)
                    length, off = read_varint(blob, off)
                except ValueError:
                    break
                fn, wt = tag >> 3, tag & 7
                if fn != 1 or wt != 2 or off + length > len(blob):
                    break
                eb = blob[off:off + length]
                off += length
                c = extract_creature(parse_proto_message(eb), path="root.2[*].4[*].1[*]", record=record)
                if c and c.get("slot") not in (None, 0):
                    out.append(c)
    dedup: dict[int, dict[str, Any]] = {}
    for c in out:
        s = c.get("slot")
        if s is not None:
            dedup[int(s)] = c
    return [dedup[s] for s in sorted(dedup)]


def extract_0102_metadata(record: dict[str, Any]) -> dict[str, Any]:
    rg = field_groups(record["root"])
    outer = next((e for e in rg.get(2, []) if e.get("sub")), None)
    if outer is None:
        return {}
    os_ = outer["sub"]
    os_g = field_groups(os_)
    pe = next((e for e in os_g.get(1, []) if e.get("sub")), None)
    player: dict[str, Any] = {}
    if pe:
        ps = pe["sub"]
        player = {
            "user_id": pick_first(collect_varints(ps, 1)),
            "uin_or_openid": first_text(ps, 2),
            "nickname": first_text(ps, 3),
        }
    f2e = next((e for e in os_g.get(2, []) if e.get("sub")), None)
    config: dict[str, Any] = {}
    if f2e:
        f2s = f2e["sub"]
        config = {
            "field_keys": sorted(field_groups(f2s).keys()),
            "pet_ids": collect_varints(f2s, 29),
            "active_pet_id": pick_first(collect_varints(f2s, 26)),
        }
    return {"player": player, "config": config}


def extract_0220_handle(record: dict[str, Any]) -> int | None:
    r1 = next((e for e in field_groups(record["root"]).get(1, []) if e.get("sub")), None)
    if r1 is None:
        return None
    r12 = next((e for e in field_groups(r1["sub"]).get(2, []) if e.get("sub")), None)
    return pick_first(collect_varints(r12["sub"], 1)) if r12 else None


# --- 01A9 提取（原位于 rkbpp_analyzer.py） ---

def extract_01a9_action(record: dict[str, Any]) -> dict[str, Any]:
    """提取 0x01A9 客户端操作的候选 ID 列表。"""
    out: dict[str, Any] = {"candidate_ids": []}
    for oe in field_groups(record["root"]).get(4, []):
        outer = oe.get("sub")
        if outer is None:
            continue
        pe = next((e for e in field_groups(outer).get(2, []) if e.get("sub")), None)
        if pe is None:
            continue
        payload = pe["sub"]
        ids: list[int] = []
        for fn in (1, 2):
            item = next((e for e in field_groups(payload).get(fn, []) if e.get("sub")), None)
            if item:
                for f in (1, 2, 3):
                    ids.extend(collect_varints(item["sub"], f))
        out.update({
            "candidate_ids": [int(v) for v in ids],
            "actor_token": pick_first(collect_varints(outer, 1)),
            "raw_kind": pick_first(collect_varints(outer, 4)),
        })
        if ids:
            out["primary_id"] = int(ids[0])
        break
    return out
