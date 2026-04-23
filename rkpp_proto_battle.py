#!/usr/bin/env python3
# Copyright (C) 2026 Hua Chui Xue You Yi Nian
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

"""Battle protocol semantic extraction helpers."""
from __future__ import annotations

from typing import Any

from rkpp_proto_core import (
    _ENERGY_BOTTLE_MAX,
    _WILLPOWER_SKILL_ID,
    _attach_buff_meta,
    _attach_buffbase_meta,
    _attach_skill_meta,
    _extract_actor_target,
    buff_name,
    collect_varints,
    extract_creature,
    extract_state_wrappers_from_record,
    field_groups,
    first_sub,
    first_text,
    maybe_signed64,
    normalize_skill_id,
    parse_proto_message,
    pick_first,
    read_varint,
    side_name,
    skill_name,
)

def _extract_skill_ref(msg: dict[str, Any] | None, *, skill_field: int = 3) -> dict[str, Any]:
    if msg is None:
        return {}
    sx100 = pick_first(collect_varints(msg, skill_field), low=100_000)
    sid   = normalize_skill_id(sx100)
    actor = pick_first(collect_varints(msg, 1))
    target = pick_first(collect_varints(msg, 2))
    out = {
        "actor_side": actor, "actor_side_name": side_name(actor),
        "target_side": target, "target_side_name": side_name(target),
        "skill_id_x100": sx100, "skill_id": sid, "skill_name": skill_name(sid),
    }
    _attach_skill_meta(out, sid)
    return out


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

def _schema_payload(record: dict[str, Any], expected_message: str) -> dict[str, Any] | None:
    decoded = record.get("_decoded")
    if isinstance(decoded, dict) and decoded:
        message_name = record.get("_message_name")
        if message_name in (None, "", expected_message):
            return decoded

    try:
        import rkpp_analysis as analysis

        result = analysis.decode_record(record)
    except Exception:
        return None

    if not result or result.get("message_name") != expected_message or not result.get("schema_found"):
        return None
    decoded = result.get("decoded")
    return decoded if isinstance(decoded, dict) else None


def _enum_value(value: Any) -> int | None:
    if isinstance(value, dict):
        return _enum_value(value.get("value"))
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _enum_name(value: Any) -> str | None:
    return value.get("name") if isinstance(value, dict) and isinstance(value.get("name"), str) else None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _first_value(value: Any) -> Any:
    items = _as_list(value)
    return items[0] if items else None


def _schema_quality(detail: dict[str, Any], *, message: str, found: bool,
                    level: str = "battle_semantic") -> dict[str, Any]:
    detail.update({
        "schema_message": message,
        "schema_found": found,
        "parse_quality": "schema_postprocess" if found else "raw_field_postprocess",
        "semantic_level": level,
    })
    return detail


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
    semantic_keys = ("battle_token", "current_hp", "energy_after", "result_code",
                     "skill_id", "skill_name", "skill_id_x100", "action_name",
                     "action_kind", "state_wrappers")
    return info if any(info.get(key) is not None for key in semantic_keys) else None


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
            _attach_buff_meta(out, out.get("effect_id"))
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
                _attach_skill_meta(related[-1], sid)
        if related:
            out["related_skills"] = related
    elif et == 3:
        out["kind"] = "effect_stage"
        em = first_sub(sg.get(5, []))
        if em:
            _extract_actor_target(em, out)
            out["effect_id"] = pick_first(collect_varints(em, 3))
            out["effect_base"] = pick_first(collect_varints(em, 6))
            _attach_buff_meta(out, out.get("effect_id"))
            _attach_buffbase_meta(out, out.get("effect_base"))
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
            _attach_buff_meta(out, out.get("effect_id"))
    return out


def extract_1324_action(record: dict[str, Any]) -> dict[str, Any] | None:
    container = first_sub(field_groups(record["root"]).get(1, []))
    if container is None:
        return None
    return _extract_perform_cmd(container, record)


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


# --- 01A9 提取（原位于 rkpp_analyzer.py） ---

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


# ===========================================================================
# [3] Phase 3 新增战斗协议提取函数
# ===========================================================================

# --- 0x1316 BattleEnterNotify 增强 ---

def extract_1316_enter(record: dict[str, Any]) -> dict[str, Any]:
    """0x1316 BattleEnterNotify: schema-first battle enter summary."""
    decoded = _schema_payload(record, "ZoneBattleEnterNotify")
    if decoded is not None:
        init_info = decoded.get("init_info") if isinstance(decoded.get("init_info"), dict) else {}
        npc_ids = [_enum_value(v) for v in _as_list(decoded.get("npc_id"))]
        battle_cfg_ids = [_enum_value(v) for v in _as_list(init_info.get("battle_cfg_id"))]
        battle_state = init_info.get("battle_state")
        detail: dict[str, Any] = {
            "battle_mode":       _enum_value(decoded.get("battle_mode")),
            "round":             _enum_value(decoded.get("round")),
            "series_index":      _enum_value(decoded.get("series_index")),
            "round_time":        _enum_value(decoded.get("round_time")),
            "npc_id":            _first_value(npc_ids),
            "npc_ids":           [v for v in npc_ids if v is not None],
            "is_reconnect":      bool(decoded.get("is_reconnect") or False),
            "enter_battle_type": _enum_value(decoded.get("enter_battle_type")),
            "weather_id":        _enum_value(decoded.get("weather_id")),
            "weather_expire_round": _enum_value(decoded.get("weather_expire_round")),
            "water_battle_type": _enum_value(decoded.get("water_battle_type")),
            "max_round":         _enum_value(decoded.get("max_round")),
            "rotate":            _enum_value(decoded.get("rotate")),
            "creater_uin":       _enum_value(decoded.get("creater_uin")),
            "data_seq_num":      _enum_value(decoded.get("data_seq_num")),
            "battle_id":         _enum_value(init_info.get("battle_id")),
            "battle_cfg_id":     _first_value(battle_cfg_ids),
            "battle_cfg_ids":    [v for v in battle_cfg_ids if v is not None],
            "battle_start_time": _enum_value(init_info.get("battle_start_time")),
            "battle_state":      _enum_value(battle_state),
            "battle_state_name": _enum_name(battle_state),
        }
        if isinstance(decoded.get("battle_center"), dict):
            detail["battle_center"] = decoded["battle_center"]
        detail["wrappers"] = extract_state_wrappers_from_record(record)
        return _schema_quality(detail, message="ZoneBattleEnterNotify", found=True)
    root = record["root"]
    rg = field_groups(root)
    detail: dict[str, Any] = {
        "battle_mode":       pick_first(collect_varints(root, 1)),
        "round":             pick_first(collect_varints(root, 2)),
        "series_index":      pick_first(collect_varints(root, 3)),
        "round_time":        pick_first(collect_varints(root, 4)),
        "npc_id":            pick_first(collect_varints(root, 9)),
        "is_reconnect":      bool(pick_first(collect_varints(root, 10)) or 0),
        "enter_battle_type": pick_first(collect_varints(root, 11)),
        "weather_id":        pick_first(collect_varints(root, 13)),
        "max_round":         pick_first(collect_varints(root, 15)),
        "creater_uin":       pick_first(collect_varints(root, 17)),
        "data_seq_num":      pick_first(collect_varints(root, 18)),
    }
    # init_info (field 6) 提取 battle_id
    init_sub = first_sub(rg.get(6, []))
    if init_sub:
        detail["battle_id"]      = pick_first(collect_varints(init_sub, 1))
        detail["battle_cfg_id"]  = pick_first(collect_varints(init_sub, 2))
    # state wrappers
    detail["wrappers"] = extract_state_wrappers_from_record(record)
    return _schema_quality(detail, message="ZoneBattleEnterNotify", found=False)


# --- 0x131A BattleRoundStartNotify 增强 ---

def extract_131a_round_start(record: dict[str, Any]) -> dict[str, Any]:
    """0x131A BattleRoundStartNotify: schema-first round start summary."""
    decoded = _schema_payload(record, "ZoneBattleRoundStartNotify")
    if decoded is not None:
        state_type = decoded.get("state_type")
        state_info = decoded.get("state_info") if isinstance(decoded.get("state_info"), dict) else {}
        perform_cmd = decoded.get("perform_cmd") if isinstance(decoded.get("perform_cmd"), dict) else None
        npc_escape = [_enum_value(v) for v in _as_list(state_info.get("npc_escape"))]
        detail: dict[str, Any] = {
            "state_type":      _enum_value(state_type),
            "state_type_name": _enum_name(state_type),
            "has_npc_delay":   bool(decoded.get("has_npc_delay") or False),
            "guide_id":        _enum_value(decoded.get("guide_id")),
            "battle_id":       _enum_value(state_info.get("battle_id")),
            "round":           _enum_value(state_info.get("round")),
            "series_index":    _enum_value(state_info.get("series_index")),
            "round_time":      _enum_value(state_info.get("round_time")),
            "npc_escape":      _first_value(npc_escape),
            "npc_escape_list": [v for v in npc_escape if v is not None],
            "has_perform":     perform_cmd is not None,
        }
        if perform_cmd is not None:
            detail["is_battle_finished"] = bool(perform_cmd.get("is_battle_finished") or False)
            detail["perform_round"] = _enum_value(perform_cmd.get("round"))
            detail["perform_seq_num"] = _enum_value(perform_cmd.get("seq_num"))
        detail["wrappers"] = extract_state_wrappers_from_record(record)
        return _schema_quality(detail, message="ZoneBattleRoundStartNotify", found=True)
    root = record["root"]
    rg = field_groups(root)
    detail: dict[str, Any] = {
        "state_type":   pick_first(collect_varints(root, 1)),
        "has_npc_delay": bool(pick_first(collect_varints(root, 5)) or 0),
        "guide_id":     pick_first(collect_varints(root, 6)),
    }
    # state_info (field 2)
    state_sub = first_sub(rg.get(2, []))
    if state_sub:
        detail["battle_id"]    = pick_first(collect_varints(state_sub, 1))
        detail["round"]        = pick_first(collect_varints(state_sub, 2))
        detail["series_index"] = pick_first(collect_varints(state_sub, 3))
        detail["round_time"]   = pick_first(collect_varints(state_sub, 5))
        detail["npc_escape"]   = pick_first(collect_varints(state_sub, 11))
    # perform_cmd (field 3) — 有时回合开始自带 perform
    pcmd = first_sub(rg.get(3, []))
    if pcmd:
        detail["has_perform"] = True
        detail["is_battle_finished"] = bool(pick_first(collect_varints(pcmd, 1)) or 0)
    # state wrappers
    detail["wrappers"] = extract_state_wrappers_from_record(record)
    return _schema_quality(detail, message="ZoneBattleRoundStartNotify", found=False)


# --- 0x132C BattleFinishNotify ---

BATTLE_RESULT_MAP: dict[int, str] = {
    0: "NULL", 2: "WIN", 4: "LOSE", 10: "MONSTER_RUNAWAY", 12: "RUNAWAY",
    260: "RUNAWAY_ROLE_MAGIC", 18: "WIN_DEFEAT", 34: "WIN_CATCH",
    66: "WIN_HP", 68: "LOSE_HP", 132: "MONSTER_ESCAPE", 516: "MONSTER_ESCAPE2",
}

def extract_132c_finish(record: dict[str, Any]) -> dict[str, Any]:
    """0x132C BattleFinishNotify: schema-first battle finish summary."""
    decoded = _schema_payload(record, "ZoneBattleFinishNotify")
    if decoded is not None:
        settle = decoded.get("settle_info") if isinstance(decoded.get("settle_info"), dict) else {}
        result = settle.get("result")
        result_code = _enum_value(result)
        ret = decoded.get("ret_info") if isinstance(decoded.get("ret_info"), dict) else {}
        pet_infos = []
        for item in _as_list(decoded.get("pet_info")):
            if not isinstance(item, dict):
                continue
            pet_infos.append({
                "pet_gid":       _enum_value(item.get("pet_gid")),
                "remain_hp":     _enum_value(item.get("remain_hp")),
                "remain_energy": _enum_value(item.get("remain_energy")),
                "mod_energy":    _enum_value(item.get("mod_energy")),
                "battle_max_hp": _enum_value(item.get("battle_max_hp")),
                "uin":           _enum_value(item.get("uin")),
            })
        detail: dict[str, Any] = {
            "evolution_complete": bool(decoded.get("evolution_complete") or False),
            "will_leave_visit":  bool(decoded.get("will_leave_visit") or False),
            "pvp_score":         _enum_value(decoded.get("pvp_score")),
            "total_pvp_score":   _enum_value(decoded.get("total_pvp_score")),
            "max_pvp_score":     _enum_value(decoded.get("max_pvp_score")),
            "create_battle_ret": _enum_value(decoded.get("create_battle_ret")),
            "result_code":       result_code,
            "result_name":       BATTLE_RESULT_MAP.get(result_code, f"UNKNOWN({result_code})") if result_code is not None else None,
            "result_enum_name":  _enum_name(result),
            "battle_conf_type":     _enum_value(settle.get("battle_conf_type")),
            "battle_opposite_type": _enum_value(settle.get("battle_opposite_type")),
            "battle_conf_id":       _enum_value(settle.get("battle_conf_id")),
            "is_surrender":         bool(settle.get("is_surrender") or False),
            "battle_id":            _enum_value(settle.get("battle_id")),
            "rounds":               _enum_value(settle.get("rounds")),
            "seconds":              _enum_value(settle.get("seconds")),
            "escape_style":         _enum_value(settle.get("escape_style")),
            "seen_monster_ids": [
                v for v in (_enum_value(item) for item in _as_list(decoded.get("seen_monster_id")))
                if v is not None
            ],
        }
        if ret:
            detail["ret_code"] = _enum_value(ret.get("ret_code"))
            detail["ret_msg"] = ret.get("ret_msg")
        if pet_infos:
            detail["finish_pet_infos"] = pet_infos
        return _schema_quality(detail, message="ZoneBattleFinishNotify", found=True)
    root = record["root"]
    rg = field_groups(root)
    detail: dict[str, Any] = {
        "evolution_complete": bool(pick_first(collect_varints(root, 7)) or 0),
        "will_leave_visit":  bool(pick_first(collect_varints(root, 10)) or 0),
        "pvp_score":         pick_first(collect_varints(root, 14)),
    }
    # settle_info (field 1)
    settle = first_sub(rg.get(1, []))
    if settle:
        result_code = pick_first(collect_varints(settle, 6))
        detail["result_code"]   = result_code
        detail["result_name"]   = BATTLE_RESULT_MAP.get(result_code, f"UNKNOWN({result_code})") if result_code is not None else None
        detail["battle_conf_type"]     = pick_first(collect_varints(settle, 1))
        detail["battle_opposite_type"] = pick_first(collect_varints(settle, 2))
        detail["battle_conf_id"]       = pick_first(collect_varints(settle, 7))
        detail["is_surrender"]         = bool(pick_first(collect_varints(settle, 14)) or 0)
        detail["battle_id"]            = pick_first(collect_varints(settle, 19))
        detail["rounds"]               = pick_first(collect_varints(settle, 37))
        detail["seconds"]              = pick_first(collect_varints(settle, 38))
        detail["escape_style"]         = pick_first(collect_varints(settle, 10))
    # seen_monster_id (field 3)
    detail["seen_monster_ids"] = collect_varints(root, 3)
    # ret_info (field 4)
    ret = first_sub(rg.get(4, []))
    if ret:
        detail["ret_code"] = pick_first(collect_varints(ret, 1))
        detail["ret_msg"]  = first_text(ret, 2)
    # pet_info (field 8) — 战后宠物状态
    pet_infos = []
    for e in rg.get(8, []):
        sub = e.get("sub")
        if not sub:
            continue
        pet_infos.append({
            "pet_gid":       pick_first(collect_varints(sub, 1)),
            "remain_hp":     pick_first(collect_varints(sub, 2)),
            "remain_energy": pick_first(collect_varints(sub, 3)),
            "battle_max_hp": pick_first(collect_varints(sub, 5)),
        })
    if pet_infos:
        detail["finish_pet_infos"] = pet_infos
    return _schema_quality(detail, message="ZoneBattleFinishNotify", found=False)


# --- 0x13FC PvpPerformStartNotify ---

def extract_13fc_pvp_perform(record: dict[str, Any]) -> dict[str, Any] | None:
    """0x13FC (5116) PvpPerformStartNotify：PVP 表演通知（结构同 1324）。"""
    container = first_sub(field_groups(record["root"]).get(1, []))
    if container is None:
        return None
    return _extract_perform_cmd(container, record)


# --- 0x13F3 PrePlayNotify ---

def extract_13f3_preplay(record: dict[str, Any]) -> dict[str, Any] | None:
    """0x13F3 (5107) PrePlayNotify：预演通知（结构同 1324）。"""
    container = first_sub(field_groups(record["root"]).get(1, []))
    if container is None:
        return None
    return _extract_perform_cmd(container, record)


# --- 共用 perform_cmd 提取（1324/13FC/13F3 共享） ---

def _extract_perform_cmd(container: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    """从 BattlePerformCmd 容器中提取完整信息，供 1324/13FC/13F3 共用。"""
    cg = field_groups(container)
    entries = [_extract_1324_entry(e["sub"]) for e in cg.get(2, []) if e.get("sub")]
    effect_ids = sorted({int(it["effect_id"]) for it in entries if it.get("effect_id") is not None})
    effect_names = [buff_name(effect_id) or str(effect_id) for effect_id in effect_ids]
    packet_state = pick_first(collect_varints(container, 1))
    packet_phase = pick_first(collect_varints(container, 3))
    packet_index = pick_first(collect_varints(container, 5))
    return {
        "packet_state":       packet_state,
        "packet_phase":       packet_phase,
        "packet_index":       packet_index,
        "entries":            entries,
        "primary_skill":      next((it for it in entries if it.get("skill_id")), None),
        "energy_event":       next((it for it in entries if it.get("kind") == "skill_cast"), None),
        "damage_event":       next((it for it in entries if it.get("kind") == "damage"), None),
        "effect_ids":         effect_ids,
        "effect_names":       effect_names,
        "has_defeat":         any(it.get("kind") == "defeat" for it in entries),
        "opcode":             record.get("opcode"),
        "opcode_hex":         record.get("opcode_hex"),
    }


# --- 0x1312 RoundFlowNotify ---

def extract_1312_round_flow(record: dict[str, Any]) -> dict[str, Any]:
    """0x1312 RoundFlowNotify: schema if available, otherwise raw field summary."""
    decoded = _schema_payload(record, "ZoneBattleRoundFlowNotify")
    if decoded is not None:
        detail = dict(decoded)
        detail["wrappers"] = extract_state_wrappers_from_record(record)
        return _schema_quality(detail, message="ZoneBattleRoundFlowNotify", found=True)
    root = record["root"]
    # 该消息 schema 缺失，尝试通用提取
    detail: dict[str, Any] = {}
    for fn in range(1, 10):
        vals = collect_varints(root, fn)
        if vals:
            detail[f"field_{fn}"] = vals[0] if len(vals) == 1 else vals
    detail["wrappers"] = extract_state_wrappers_from_record(record)
    return _schema_quality(
        detail,
        message="ZoneBattleRoundFlowNotify",
        found=False,
        level="raw_field_dump_with_wrappers",
    )
