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

"""Compatibility facade for protocol parsing helpers.

The implementation is split into:
  - rkpp_proto_core.py: transport/layout parsing and proto-tree primitives
  - rkpp_proto_battle.py: battle-oriented semantic extraction helpers
"""
from rkpp_proto_core import *  # noqa: F401,F403
from rkpp_proto_battle import *  # noqa: F401,F403
from rkpp_proto_battle import _extract_perform_cmd  # noqa: F401
