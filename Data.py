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

"""CSV 数据加载模块（精灵属性 / 精灵名 / 技能名）。

提供 get_maps() 线程安全的懒加载单例，避免多次重复读取 CSV 文件。
"""
from __future__ import annotations

import csv
import threading
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR   = SCRIPT_DIR / "Data"
ATTR_CSV   = DATA_DIR / "Attr.csv"
PET_CSV    = DATA_DIR / "Pet.csv"
SKILL_CSV  = DATA_DIR / "Skill.csv"


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------

def _safe_int(text: str | None) -> int | None:
    if text is None:
        return None
    s = text.strip()
    try:
        return int(s, 10) if s else None
    except ValueError:
        return None


def _read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        rows: list[dict[str, str]] = []
        for row in reader:
            norm = {str(k).strip(): (v or "").strip() for k, v in row.items() if k is not None}
            if any(norm.values()):
                rows.append(norm)
        return rows


def _build_id_name_map(rows: list[dict[str, str]], *, id_field: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for row in rows:
        eid = _safe_int(row.get(id_field))
        name = (row.get("name") or "").strip()
        if eid is not None and name:
            out[eid] = name
    return out


def _load_all_maps() -> dict[str, dict[int, str]]:
    return {
        "attr":  _build_id_name_map(_read_rows(ATTR_CSV),  id_field="attr_id"),
        "pet":   _build_id_name_map(_read_rows(PET_CSV),   id_field="pet_id"),
        "skill": _build_id_name_map(_read_rows(SKILL_CSV), id_field="skill_id"),
    }


# ---------------------------------------------------------------------------
# 线程安全懒加载单例
# ---------------------------------------------------------------------------

_cache: dict[str, dict[int, str]] | None = None
_lock = threading.Lock()


def get_maps() -> dict[str, dict[int, str]]:
    """首次调用时读取 CSV，后续直接返回缓存。线程安全。"""
    global _cache
    if _cache is not None:
        return _cache
    with _lock:
        # Double-checked locking
        if _cache is None:
            _cache = _load_all_maps()
        return _cache


def invalidate_cache() -> None:
    """热重载 / 测试时调用，使下次 get_maps() 重新读取文件。"""
    global _cache
    with _lock:
        _cache = None
