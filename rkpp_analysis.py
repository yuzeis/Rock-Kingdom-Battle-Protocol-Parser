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

"""Schema-driven protocol decoding helpers.

The module loads Data/opcode.json and Data/proto_schema.json lazily, translates
field-number proto trees into named dictionaries, and enriches known ids with
local CSV names.
"""
from __future__ import annotations

import json
import logging
import struct
from pathlib import Path
from typing import Any

import Data

logger = logging.getLogger(__name__)

_SCHEMA_DIR = Path(__file__).resolve().parent / "Data"

_VARINT_PACKED_TYPES = {
    "int32", "int64", "uint32", "uint64", "sint32", "sint64", "bool",
}
_FIXED32_PACKED_TYPES = {"fixed32", "sfixed32", "float"}
_FIXED64_PACKED_TYPES = {"fixed64", "sfixed64", "double"}

# ---------------------------------------------------------------------------
# 全局懒加载缓存
# ---------------------------------------------------------------------------

_opcode_map: dict[str, dict] | None = None
_schema: dict[str, dict] | None = None


def _repair_json_text(text: str) -> tuple[str, int]:
    repaired_lines: list[str] = []
    repairs = 0
    for raw_line in text.splitlines(keepends=True):
        if raw_line.endswith("\r\n"):
            line_ending = "\r\n"
            line = raw_line[:-2]
        elif raw_line.endswith("\n"):
            line_ending = "\n"
            line = raw_line[:-1]
        else:
            line_ending = ""
            line = raw_line

        if line.count('"') % 2 == 1:
            stripped = line.rstrip()
            suffix_spaces = line[len(stripped):]
            if stripped.endswith(","):
                line = stripped[:-1] + '",' + suffix_spaces
            else:
                line = stripped + '"' + suffix_spaces
            repairs += 1

        repaired_lines.append(line + line_ending)
    return "".join(repaired_lines), repairs


def _load_json_file(path: Path, *, default: dict[str, Any], label: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        logger.exception("Failed to read %s at %s", label, path)
        return default

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        repaired_text, repairs = _repair_json_text(text)
        if repairs > 0:
            try:
                data = json.loads(repaired_text)
            except json.JSONDecodeError:
                logger.exception(
                    "Failed to load %s at %s even after repairing %d malformed lines",
                    label, path, repairs,
                )
                return default
            logger.warning(
                "Loaded %s at %s after repairing %d malformed JSON lines (first error line=%d col=%d)",
                label, path, repairs, exc.lineno, exc.colno,
            )
            return data

        logger.exception("Failed to load %s at %s", label, path)
        return default


def _ensure_loaded() -> tuple[dict[str, dict], dict[str, dict]]:
    global _opcode_map, _schema
    if _opcode_map is None:
        op_path = _SCHEMA_DIR / "opcode.json"
        if op_path.exists():
            _opcode_map = _load_json_file(op_path, default={}, label="opcode.json")
            logger.info("Loaded opcode.json: %d entries", len(_opcode_map))
        else:
            logger.warning("opcode.json not found at %s", op_path)
            _opcode_map = {}
    if _schema is None:
        sc_path = _SCHEMA_DIR / "proto_schema.json"
        if sc_path.exists():
            _schema = _load_json_file(
                sc_path,
                default={"messages": {}, "enums": {}},
                label="proto_schema.json",
            )
            logger.info("Loaded proto_schema.json: %d messages, %d enums",
                        len(_schema.get("messages", {})), len(_schema.get("enums", {})))
        else:
            logger.warning("proto_schema.json not found at %s", sc_path)
            _schema = {"messages": {}, "enums": {}}
    return _opcode_map, _schema


def _lookup_skill_name(skill_map: dict[int, str], value: Any) -> str | None:
    if not isinstance(value, int) or value <= 0:
        return None
    direct = skill_map.get(value)
    if direct:
        return direct
    if value % 100 == 0:
        return skill_map.get(value // 100)
    return None


def _skill_meta(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, int) or value <= 0:
        return None
    return Data.get_skill_meta(value)


def _enrich_known_id_names(obj: Any) -> Any:
    """Attach pet/skill names to schema-decoded JSON without changing raw IDs."""
    try:
        maps = Data.get_maps()
    except Exception:
        logger.exception("Failed to load Data maps for semantic id enrichment")
        return obj

    pet_map = maps.get("pet", {})
    skill_map = maps.get("skill", {})
    attr_map = maps.get("attr", {})
    pet_name_fields = {
        "pet_id": "pet_name",
        "active_pet_id": "active_pet_name",
        "conf_id": "conf_name",
        "petbase_id": "petbase_name",
        "base_id": "base_name",
        "monster_id": "monster_name",
        "monsterID": "monster_name",
    }
    attr_list_fields = {
        "types": "type_names",
        "unit_type": "unit_type_names",
        "attr_enum_break_set": "attr_enum_break_names",
    }
    buff_name_fields = {
        "buff_id": "buff_name",
        "connect_buff": "connect_buff_name",
        "field_buff": "field_buff_name",
    }
    skill_list_fields = {
        "active_skills": "active_skill_names",
    }
    buff_list_fields = {
        "buff_base_ids": "buff_base_names",
    }

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for id_key, name_key in pet_name_fields.items():
                raw = value.get(id_key)
                if isinstance(raw, int) and raw > 1000 and name_key not in value:
                    name = Data.get_pet_name(raw) or pet_map.get(raw)
                    if name:
                        value[name_key] = name

            raw_skill = value.get("skill_id")
            if "skill_name" not in value:
                name = _lookup_skill_name(skill_map, raw_skill)
                if name:
                    value["skill_name"] = name
            skill_meta = _skill_meta(raw_skill)
            if skill_meta:
                if isinstance(skill_meta.get("desc"), str) and skill_meta.get("desc") and "skill_desc" not in value:
                    value["skill_desc"] = skill_meta["desc"]
                for src, dst in (
                    ("energy_cost", "skill_energy_cost"),
                    ("target_type", "skill_target_type"),
                    ("target_count", "skill_target_count"),
                    ("skill_priority", "skill_priority"),
                    ("damage_type", "skill_damage_type"),
                    ("skill_feature", "skill_feature"),
                    ("cd_round", "skill_cd_round"),
                ):
                    if src in skill_meta and dst not in value:
                        value[dst] = skill_meta[src]

            extra_skill_fields = (
                "edition_skill_id", "machine_skill_id", "blood_skill_COMMON",
                "blood_skill_GRASS", "blood_skill_FIRE", "blood_skill_WATER",
                "blood_skill_LIGHT", "blood_skill_STONE", "blood_skill_ICE",
                "blood_skill_DRAGON", "blood_skill_ELECTRIC", "blood_skill_TOXIC",
                "blood_skill_INSECT", "blood_skill_FIGHT", "blood_skill_WING",
                "blood_skill_MOE", "blood_skill_GHOST", "blood_skill_DEMON",
                "blood_skill_MECHANIC", "blood_skill_PHANTOM",
            )
            for field_name in extra_skill_fields:
                raw_extra = value.get(field_name)
                if not isinstance(raw_extra, int):
                    continue
                extra_name_key = field_name + "_name"
                if extra_name_key in value:
                    continue
                extra_name = _lookup_skill_name(skill_map, raw_extra)
                if extra_name:
                    value[extra_name_key] = extra_name

            raw_type = value.get("type_id")
            if isinstance(raw_type, int) and "type_name" not in value:
                name = Data.get_attr_name(raw_type) or attr_map.get(raw_type)
                if name:
                    value["type_name"] = name

            for id_key, name_key in attr_list_fields.items():
                raw = value.get(id_key)
                if isinstance(raw, list) and name_key not in value:
                    names = [
                        (Data.get_attr_name(item) or attr_map.get(item)) if isinstance(item, int) else None
                        for item in raw
                    ]
                    if any(names):
                        value[name_key] = [
                            name if name is not None else str(item)
                            for item, name in zip(raw, names)
                        ]

            for id_key, name_key in buff_name_fields.items():
                raw = value.get(id_key)
                if not isinstance(raw, int) or name_key in value:
                    continue
                meta = Data.get_buff_meta(raw)
                if meta and isinstance(meta.get("name"), str):
                    value[name_key] = meta["name"]
                    if id_key == "buff_id":
                        if isinstance(meta.get("desc"), str) and meta.get("desc") and "buff_desc" not in value:
                            value["buff_desc"] = meta["desc"]
                        if meta.get("type_id") is not None and "buff_type_id" not in value:
                            value["buff_type_id"] = meta.get("type_id")

            for id_key, name_key in skill_list_fields.items():
                raw = value.get(id_key)
                if not isinstance(raw, list) or name_key in value:
                    continue
                names = [
                    _lookup_skill_name(skill_map, item) if isinstance(item, int) else None
                    for item in raw
                ]
                if any(names):
                    value[name_key] = [
                        name if name is not None else str(item)
                        for item, name in zip(raw, names)
                    ]

            for id_key, name_key in buff_list_fields.items():
                raw = value.get(id_key)
                if not isinstance(raw, list) or name_key in value:
                    continue
                names = []
                for item in raw:
                    if not isinstance(item, int):
                        names.append(str(item))
                        continue
                    meta = Data.get_buffbase_meta(item)
                    names.append(meta.get("editor_name") if isinstance(meta, dict) else str(item))
                if any(name for name in names if isinstance(name, str) and name):
                    value[name_key] = names

            pet_id = value.get("pet_id")
            if isinstance(pet_id, int):
                pet_meta = Data.get_pet_meta(pet_id)
                if isinstance(pet_meta, dict):
                    if pet_meta.get("base_id") is not None and "pet_base_id" not in value:
                        value["pet_base_id"] = pet_meta["base_id"]
                    if pet_meta.get("pet_info_id") is not None and "pet_info_id" not in value:
                        value["pet_info_id"] = pet_meta["pet_info_id"]

            base_id = value.get("base_id")
            if isinstance(base_id, int) and "base_skill_pool" not in value:
                skill_meta = Data.get_pet_skill_meta(base_id)
                if isinstance(skill_meta, dict):
                    level_skills = skill_meta.get("level_skills")
                    if isinstance(level_skills, list):
                        value["base_skill_pool"] = level_skills

            monster_id = value.get("monster_id") or value.get("monsterID")
            if isinstance(monster_id, int) and "monster_active_skills" not in value:
                monster_meta = Data.get_monster_meta(monster_id)
                if isinstance(monster_meta, dict) and isinstance(monster_meta.get("active_skills"), list):
                    value["monster_active_skills"] = monster_meta["active_skills"]

            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(obj)
    return obj


# ---------------------------------------------------------------------------
# Opcode 查询
# ---------------------------------------------------------------------------

def lookup_opcode(opcode: int) -> dict[str, Any]:
    """查询 opcode 的名称、分类、方向等信息。

    Returns:
        {name, full_name, desc_cn, direction, category}  或空 dict
    """
    op_map, _ = _ensure_loaded()
    info = dict(op_map.get(str(opcode), {}))
    pb_meta = Data.get_opcode_pb_meta(opcode)
    if pb_meta:
        info.setdefault("name", pb_meta.get("message"))
        info.setdefault("full_name", pb_meta.get("full_name"))
        info.setdefault("category", pb_meta.get("package"))
        info["pb_message"] = pb_meta.get("message")
        info["pb_full_name"] = pb_meta.get("full_name")
        info["pb_proto_file"] = pb_meta.get("proto_file")
        info["pb_type"] = pb_meta.get("type")
    return info


def opcode_name(opcode: int) -> str | None:
    """返回 opcode 对应的消息名，不存在则返回 None。"""
    info = lookup_opcode(opcode)
    return info.get("name")


# ---------------------------------------------------------------------------
# Schema-driven 解码
# ---------------------------------------------------------------------------

def decode_by_schema(
    raw_msg: dict[str, Any],
    message_name: str,
    *,
    max_depth: int = 8,
    _depth: int = 0,
) -> dict[str, Any]:
    """将 parse_proto_message 的 field-number 树，按 schema 翻译为带字段名的 dict。

    Args:
        raw_msg: parse_proto_message 返回的 {"fields": [...], "consumed": ..., "clean": ...}
        message_name: schema 中的 message 名 (如 "ZoneBattleCmdPushbackReq")
        max_depth: 最大递归深度
    Returns:
        带字段名的 dict，未知字段以 "field_{n}" 保留
    """
    _, schema = _ensure_loaded()
    msgs = schema.get("messages", {})
    enums = schema.get("enums", {})

    msg_def = msgs.get(message_name)
    if msg_def is None:
        # 没有 schema 定义，返回原始 field dump
        return _raw_dump(raw_msg)

    field_defs = msg_def.get("fields", {})
    result: dict[str, Any] = {}

    # 按 field number 分组
    grouped: dict[int, list[dict]] = {}
    for entry in raw_msg.get("fields", []):
        fn = entry.get("field", 0)
        grouped.setdefault(fn, []).append(entry)

    for fn_str, fdef in field_defs.items():
        fn = int(fn_str)
        entries = grouped.pop(fn, [])
        if not entries:
            continue

        fname = fdef["name"]
        ftype = fdef.get("type", "")
        is_repeated = fdef.get("repeated", False)
        is_msg = fdef.get("message", False)
        is_enum = fdef.get("enum", False)
        wire = fdef.get("wire", -1)

        values = []
        for entry in entries:
            val = _decode_entry(entry, ftype, is_msg, is_enum, is_repeated, msgs, enums,
                                max_depth=max_depth, depth=_depth)
            if is_repeated and isinstance(val, list) and entry.get("wire") == 2 and not is_msg:
                values.extend(val)
            else:
                values.append(val)

        if is_repeated:
            result[fname] = values
        else:
            result[fname] = values[0] if len(values) == 1 else values

    # 未定义的字段保留为 field_N
    for fn, entries in grouped.items():
        if fn == 0:
            continue
        key = f"field_{fn}"
        vals = [_decode_entry_raw(e) for e in entries]
        result[key] = vals if len(vals) > 1 else vals[0]

    return result


def _decode_entry(
    entry: dict[str, Any],
    ftype: str,
    is_msg: bool,
    is_enum: bool,
    is_repeated: bool,
    msgs: dict,
    enums: dict,
    *,
    max_depth: int,
    depth: int,
) -> Any:
    """解码单个 field entry。"""
    wire = entry.get("wire", -1)
    ftype = _normalize_type(ftype)

    # Varint
    if wire == 0:
        val = entry.get("value")
        if val is None:
            return None
        # 枚举翻译
        if is_enum:
            enum_def = _lookup_enum(enums, ftype).get("values", {})
            ename = enum_def.get(str(val))
            return {"value": val, "name": ename} if ename else val
        # bool
        if ftype == "bool":
            return bool(val)
        # sint32/sint64 zigzag
        if ftype.startswith("sint"):
            return (val >> 1) ^ -(val & 1)
        if ftype == "int32":
            return _signed_from_bits(val, 32)
        if ftype == "int64":
            return _signed_from_bits(val, 64)
        if ftype == "uint32":
            return val & 0xFFFFFFFF
        return val

    # 64-bit fixed
    if wire == 1:
        raw_hex = entry.get("raw_hex", "")
        if len(raw_hex) == 16:
            raw_bytes = bytes.fromhex(raw_hex)
            if ftype == "double":
                return struct.unpack("<d", raw_bytes)[0]
            if ftype in ("sfixed64", "int64"):
                return struct.unpack("<q", raw_bytes)[0]
            return struct.unpack("<Q", raw_bytes)[0]
        return raw_hex

    # Length-delimited
    if wire == 2:
        # 嵌套 message
        if is_msg and entry.get("sub") and depth < max_depth:
            return decode_by_schema(
                entry["sub"], ftype, max_depth=max_depth, _depth=depth + 1
            )
        # string
        if ftype == "string":
            return entry.get("text") or entry.get("raw_hex", "")
        # bytes
        if ftype == "bytes":
            return entry.get("raw_hex", "")
        # 可能是 packed repeated
        if is_repeated and not is_msg:
            packed = _decode_packed(entry.get("raw_hex", ""), ftype, is_enum, enums)
            if packed is not None:
                return packed
        if entry.get("text"):
            return entry["text"]
        if entry.get("sub") and depth < max_depth:
            return decode_by_schema(
                entry["sub"], ftype, max_depth=max_depth, _depth=depth + 1
            )
        return entry.get("raw_hex", "")

    # 32-bit fixed
    if wire == 5:
        raw_hex = entry.get("raw_hex", "")
        if len(raw_hex) == 8:
            raw_bytes = bytes.fromhex(raw_hex)
            if ftype == "float":
                return struct.unpack("<f", raw_bytes)[0]
            if ftype in ("sfixed32", "int32"):
                return struct.unpack("<i", raw_bytes)[0]
            return entry.get("u32le", int.from_bytes(raw_bytes, "little"))
        return raw_hex

    return _decode_entry_raw(entry)


def _normalize_type(ftype: str) -> str:
    if not ftype:
        return ""
    for prefix in (".Next.", "Next.", ".dataconfig.", "dataconfig."):
        if ftype.startswith(prefix):
            return ftype[len(prefix):]
    if ftype.startswith("."):
        return ftype[1:]
    return ftype


def _lookup_enum(enums: dict, ftype: str) -> dict:
    ftype = _normalize_type(ftype)
    if ftype in enums:
        return enums[ftype]
    short = ftype.rsplit(".", 1)[-1]
    return enums.get(short, {})


def _signed_from_bits(value: int, bits: int) -> int:
    mask = (1 << bits) - 1
    value &= mask
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _read_varint_from(data: bytes, off: int) -> tuple[int, int]:
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
            raise ValueError("packed varint too large")
    raise ValueError("unterminated packed varint")


def _decode_packed(raw_hex: str, ftype: str, is_enum: bool, enums: dict) -> list[Any] | None:
    if not raw_hex:
        return []
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError:
        return None

    ftype = _normalize_type(ftype)
    if is_enum or ftype in _VARINT_PACKED_TYPES:
        values: list[Any] = []
        off = 0
        try:
            while off < len(data):
                raw, off = _read_varint_from(data, off)
                if is_enum:
                    enum_def = _lookup_enum(enums, ftype).get("values", {})
                    name = enum_def.get(str(raw))
                    values.append({"value": raw, "name": name} if name else raw)
                elif ftype == "bool":
                    values.append(bool(raw))
                elif ftype == "sint32" or ftype == "sint64":
                    values.append((raw >> 1) ^ -(raw & 1))
                elif ftype == "int32":
                    values.append(_signed_from_bits(raw, 32))
                elif ftype == "int64":
                    values.append(_signed_from_bits(raw, 64))
                elif ftype == "uint32":
                    values.append(raw & 0xFFFFFFFF)
                else:
                    values.append(raw)
        except ValueError:
            return None
        return values

    if ftype in _FIXED32_PACKED_TYPES:
        if len(data) % 4:
            return None
        values = []
        for off in range(0, len(data), 4):
            chunk = data[off:off + 4]
            if ftype == "float":
                values.append(struct.unpack("<f", chunk)[0])
            elif ftype == "sfixed32":
                values.append(struct.unpack("<i", chunk)[0])
            else:
                values.append(struct.unpack("<I", chunk)[0])
        return values

    if ftype in _FIXED64_PACKED_TYPES:
        if len(data) % 8:
            return None
        values = []
        for off in range(0, len(data), 8):
            chunk = data[off:off + 8]
            if ftype == "double":
                values.append(struct.unpack("<d", chunk)[0])
            elif ftype == "sfixed64":
                values.append(struct.unpack("<q", chunk)[0])
            else:
                values.append(struct.unpack("<Q", chunk)[0])
        return values

    return None


def _decode_entry_raw(entry: dict[str, Any]) -> Any:
    """兜底：返回 entry 中最有意义的值。"""
    if "value" in entry:
        return entry["value"]
    if "text" in entry:
        return entry["text"]
    if "sub" in entry:
        return _raw_dump(entry["sub"])
    if "raw_hex" in entry:
        return entry["raw_hex"]
    return None


def _raw_dump(msg: dict[str, Any]) -> dict[str, Any]:
    """将未知 message 转为 {field_N: value} 格式。"""
    result: dict[str, Any] = {}
    grouped: dict[int, list] = {}
    for entry in msg.get("fields", []):
        grouped.setdefault(entry.get("field", 0), []).append(entry)
    for fn, entries in grouped.items():
        key = f"field_{fn}"
        vals = [_decode_entry_raw(e) for e in entries]
        result[key] = vals if len(vals) > 1 else vals[0]
    return result


# ---------------------------------------------------------------------------
# 高层 API：完整解码一条 record
# ---------------------------------------------------------------------------

def decode_record(record: dict[str, Any]) -> dict[str, Any] | None:
    """对一条已解析的 record（由 parse_record 产出），按 schema 完整解码。

    Returns:
        {
            "opcode": ..., "opcode_hex": ..., "opcode_info": {...},
            "decoded": { ... schema-decoded payload ... },
        }
    """
    opcode = record.get("opcode")
    if opcode is None:
        return None

    info = lookup_opcode(opcode)
    msg_name = info.get("name")
    root = record.get("root")
    special_payload = record.get("special_payload")
    if root is None or msg_name is None:
        return {
            "opcode": opcode,
            "opcode_hex": record.get("opcode_hex"),
            "opcode_info": info,
            "schema_found": False,
            "message_name": msg_name,
            "pb_message_name": info.get("pb_message"),
            "pb_full_name": info.get("pb_full_name"),
            "pb_proto_file": info.get("pb_proto_file"),
            "decoded": _enrich_known_id_names(_raw_dump(root)) if root else {},
        }

    if isinstance(special_payload, dict):
        return {
            "opcode": opcode,
            "opcode_hex": record.get("opcode_hex"),
            "opcode_info": info,
            "schema_found": False,
            "message_name": msg_name,
            "pb_message_name": info.get("pb_message"),
            "pb_full_name": info.get("pb_full_name"),
            "pb_proto_file": info.get("pb_proto_file"),
            "decoded": _enrich_known_id_names(dict(special_payload)),
        }

    _, schema = _ensure_loaded()
    msgs = schema.get("messages", {})

    # 尝试在 schema 中查找 message 定义
    decoded = {}
    if msg_name in msgs:
        decoded = decode_by_schema(root, msg_name)
    else:
        decoded = _raw_dump(root) if root else {}
    decoded = _enrich_known_id_names(decoded)

    return {
        "opcode": opcode,
        "opcode_hex": record.get("opcode_hex"),
        "opcode_info": info,
        "schema_found": msg_name in msgs,
        "message_name": msg_name,
        "pb_message_name": info.get("pb_message"),
        "pb_full_name": info.get("pb_full_name"),
        "pb_proto_file": info.get("pb_proto_file"),
        "decoded": decoded,
    }
