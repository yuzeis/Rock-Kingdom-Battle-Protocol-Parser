#!/usr/bin/env python3
"""Build RKPP runtime data indexes from decoded world data.

This is an offline helper. RKPP runtime code reads only Data/*.json and does
not depend on the source Roco-Kingdom-World-Data-main directory.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_ROOT = PROJECT_ROOT.parent / "Roco-Kingdom-World-Data-main"
DEFAULT_OUT_DIR = PROJECT_ROOT / "Data"

BIN_DATA_DIR = Path("Bin") / "BinDataCompressed"
PB_DIR = Path("PB")
PROTO_OUT_DIR = PB_DIR / "proto_out"


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(value, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")


def _rows(source_root: Path, name: str) -> dict[str, Any]:
    path = source_root / BIN_DATA_DIR / f"{name}.json"
    data = _load_json(path)
    rows = data.get("RocoDataRows", {})
    if not isinstance(rows, dict):
        return {}
    return rows


def _pick(row: dict[str, Any], *keys: str) -> dict[str, Any]:
    return {key: row[key] for key in keys if key in row}


def _non_empty_dict(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def _normalize_skill_id(value: Any) -> int | None:
    if not isinstance(value, int) or value <= 0:
        return None
    return value // 100 if value >= 100_000 and value % 100 == 0 else value


def build_attr_map(source_root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, row in _rows(source_root, "ATTRIBUTE_CONF").items():
        if not isinstance(row, dict):
            continue
        attr_id = row.get("attribute")
        if not isinstance(attr_id, int):
            continue
        out[str(attr_id)] = _non_empty_dict({
            "id": attr_id,
            "name": row.get("attribute_name") or row.get("editor_name"),
            "editor_name": row.get("editor_name"),
            "is_percent": bool(row.get("is_percent_attr")),
            "ui_type": row.get("attr_ui_type"),
            "is_ui_show": row.get("is_ui_show"),
        })
    return out


def build_skill_map(source_root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    fields = (
        "id", "name", "desc", "energy_cost", "dam_para", "type",
        "skill_dam_type", "skill_feature", "damage_type", "contact_type",
        "skill_priority", "target_type", "target_count", "cd_round",
        "hit_para", "skill_result", "res_id", "describe_type",
        "target_blood_limit", "monitor_data_version",
    )
    for row in _rows(source_root, "SKILL_CONF").values():
        if not isinstance(row, dict) or not isinstance(row.get("id"), int):
            continue
        out[str(row["id"])] = _non_empty_dict(_pick(row, *fields))
    return out


def build_buff_map(source_root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    fields = (
        "id", "name", "desc", "editor_name", "buff_base_ids",
        "buff_list_priority", "buff_groupsigns", "type_id", "add_des",
        "add_icon", "type", "add_max", "buff_group_reduce",
        "is_clean_when_rest", "connect_buff", "field_buff",
        "buff_trigger_priority",
    )
    for row in _rows(source_root, "BUFF_CONF").values():
        if not isinstance(row, dict) or not isinstance(row.get("id"), int):
            continue
        out[str(row["id"])] = _non_empty_dict(_pick(row, *fields))
    return out


def build_buffbase_map(source_root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    fields = (
        "id", "editor_name", "buffbase_order", "show_letters",
        "client_trigger_type", "buffbase_param",
    )
    for row in _rows(source_root, "BUFFBASE_CONF").values():
        if not isinstance(row, dict) or not isinstance(row.get("id"), int):
            continue
        out[str(row["id"])] = _non_empty_dict(_pick(row, *fields))
    return out


def build_pet_map(source_root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for row in _rows(source_root, "PET_CONF").values():
        if not isinstance(row, dict) or not isinstance(row.get("id"), int):
            continue
        out[str(row["id"])] = _non_empty_dict(_pick(row, "id", "name", "base_id", "pet_info_id"))
    return out


def build_monster_map(source_root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    fields = (
        "id", "name", "base_id", "level", "monster_level_script", "new_level",
        "difficulty", "nature_id", "attr_enum_break_set", "individuality",
        "hp_max_upper_mag", "phy_attack_upper_mag", "spe_attack_upper_mag",
        "phy_defence_upper_mag", "spe_defence_upper_mag", "speed_upper_mag",
        "level_skill_id", "mf_behavior_tree_fight", "pre_type", "pre_num",
        "monster_bornmagic",
    )
    for row in _rows(source_root, "MONSTER_CONF").values():
        if not isinstance(row, dict) or not isinstance(row.get("id"), int):
            continue
        meta = _pick(row, *fields)
        active_skills = [
            sid for sid in (
                _normalize_skill_id(row.get("active_skill1")),
                _normalize_skill_id(row.get("active_skill2")),
                _normalize_skill_id(row.get("active_skill3")),
                _normalize_skill_id(row.get("active_skill4")),
            )
            if sid is not None
        ]
        if active_skills:
            meta["active_skills"] = active_skills
        out[str(row["id"])] = _non_empty_dict(meta)
    return out


def build_pet_skill_map(source_root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for row in _rows(source_root, "LEVEL_SKILL_CONF").values():
        if not isinstance(row, dict) or not isinstance(row.get("id"), int):
            continue
        level_skills = []
        for item in row.get("level") or []:
            if not isinstance(item, dict):
                continue
            skill_id = _normalize_skill_id(item.get("param"))
            if skill_id is None:
                continue
            entry = _pick(item, "level_point", "stage", "level_gain_skill")
            entry["skill_id"] = skill_id
            level_skills.append(_non_empty_dict(entry))

        machine_skills = []
        for item in row.get("machine_skill_group") or []:
            if not isinstance(item, dict):
                continue
            skill_id = _normalize_skill_id(item.get("machine_skill_id"))
            if skill_id is None:
                continue
            machine_skills.append(_non_empty_dict({
                "skill_id": skill_id,
                "name": item.get("machine_skill_name"),
            }))

        meta = {
            "id": row["id"],
            "editor_name": row.get("editor_name"),
            "level_skills": level_skills,
            "machine_skills": machine_skills,
            "blood_skill_level_point": row.get("blood_skill_level_point"),
        }
        for key, value in row.items():
            if key.startswith("blood_skill_") and isinstance(value, int) and value > 0:
                sid = _normalize_skill_id(value)
                if sid is not None:
                    meta[key] = sid
        out[str(row["id"])] = _non_empty_dict(meta)
    return out


def build_monster_skillbank_map(source_root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for row in _rows(source_root, "MONSTER_SKILLBANK_CONF").values():
        if not isinstance(row, dict) or not isinstance(row.get("id"), int):
            continue
        levels = row.get("level")
        if not isinstance(levels, list):
            continue
        entries = []
        for item in levels:
            if not isinstance(item, dict):
                continue
            skill_id = _normalize_skill_id(item.get("skill_id"))
            if skill_id is None:
                continue
            entries.append(_non_empty_dict({
                "level_limit": item.get("level_limit"),
                "skill_id": skill_id,
            }))
        if not entries:
            continue
        out[str(row["id"])] = _non_empty_dict({
            "id": row["id"],
            "skills": entries,
        })
    return out


def build_special_move_map(source_root: Path) -> dict[str, Any]:
    out: dict[str, Any] = {}
    fields = (
        "id", "monsterID", "mutation_diff_type", "name",
        "skill_trigger_type", "type_param", "edition_skill_id",
        "description", "trigger_description",
    )
    for row in _rows(source_root, "SPECIAL_MOVE_CONF").values():
        if not isinstance(row, dict) or not isinstance(row.get("id"), int):
            continue
        meta = _pick(row, *fields)
        if isinstance(meta.get("edition_skill_id"), int):
            meta["edition_skill_id"] = _normalize_skill_id(meta["edition_skill_id"])
        out[str(row["id"])] = _non_empty_dict(meta)
    return out


def _proto_type(name: str) -> str:
    if name.endswith("Req"):
        return "Req"
    if name.endswith("Rsp"):
        return "Rsp"
    if name.endswith("Notify") or name.endswith("Nty"):
        return "Notify"
    if name.endswith("Ack"):
        return "Ack"
    return "Other"


def build_pb_indexes(source_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    message_index: dict[str, Any] = {}
    proto_dir = source_root / PROTO_OUT_DIR
    package_re = re.compile(r"^\s*package\s+([A-Za-z0-9_.]+)\s*;")
    message_re = re.compile(r"^\s*message\s+([A-Za-z0-9_]+)\s*\{")

    for proto_path in sorted(proto_dir.glob("*.proto")):
        package = ""
        text = proto_path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            package_match = package_re.match(line)
            if package_match:
                package = package_match.group(1)
                continue
            message_match = message_re.match(line)
            if not message_match:
                continue
            name = message_match.group(1)
            full_name = f"{package}.{name}" if package else name
            meta = {
                "name": name,
                "full_name": full_name,
                "package": package,
                "proto_file": proto_path.name,
            }
            message_index[name] = meta
            message_index[full_name] = meta
            message_index[f".{full_name}"] = meta

    proto_json = _load_json(source_root / PB_DIR / "proto.json")
    opcode_map: dict[str, Any] = {}
    for opcode, full_name in proto_json.items():
        if not isinstance(full_name, str):
            continue
        name = full_name.rsplit(".", 1)[-1]
        meta = dict(message_index.get(full_name) or message_index.get(name) or {})
        opcode_map[str(opcode)] = _non_empty_dict({
            "opcode": int(opcode),
            "message": name,
            "full_name": full_name,
            "package": meta.get("package"),
            "proto_file": meta.get("proto_file"),
            "type": _proto_type(name),
        })
    return opcode_map, message_index


def build_bundle(source_root: Path, out_dir: Path) -> None:
    if not source_root.exists():
        raise SystemExit(f"source root not found: {source_root}")

    bundle = {
        "attr_map.json": build_attr_map(source_root),
        "skill_map.json": build_skill_map(source_root),
        "buff_map.json": build_buff_map(source_root),
        "buffbase_map.json": build_buffbase_map(source_root),
        "pet_map.json": build_pet_map(source_root),
        "monster_map.json": build_monster_map(source_root),
        "pet_skill_map.json": build_pet_skill_map(source_root),
        "monster_skillbank_map.json": build_monster_skillbank_map(source_root),
        "special_move_map.json": build_special_move_map(source_root),
    }
    opcode_pb_map, pb_message_index = build_pb_indexes(source_root)
    bundle["opcode_pb_map.json"] = opcode_pb_map
    bundle["pb_message_index.json"] = pb_message_index

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "format": "rkpp-data-bundle-v1",
        "source_kind": "offline-import",
        "files": {
            name: len(value) if isinstance(value, dict) else None
            for name, value in bundle.items()
        },
    }
    bundle["data_manifest.json"] = manifest

    for name, value in bundle.items():
        _write_json(out_dir / name, value)
        count = len(value) if isinstance(value, dict) else "?"
        print(f"wrote {out_dir / name} ({count} entries)")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build RKPP Data/*.json indexes")
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()
    build_bundle(args.source_root.resolve(), args.out_dir.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
