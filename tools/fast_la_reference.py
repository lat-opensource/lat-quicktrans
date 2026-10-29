#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT

import re
from pathlib import Path


def parse_bit_fields(path):
    text = Path(path).read_text(encoding="utf-8")
    pattern = re.compile(
        r"\{\s*([A-Z0-9_]+),\s*"
        r"\{(-?\d+),\s*(-?\d+)\},\s*"
        r"\{(-?\d+),\s*(-?\d+)\}\s*\},"
    )
    fields = {}

    for match in pattern.finditer(text):
        name = match.group(1).lower()
        ranges = []
        first = (int(match.group(2)), int(match.group(3)))
        second = (int(match.group(4)), int(match.group(5)))

        if first[0] >= 0:
            ranges.append(first)
        if second[0] >= 0:
            ranges.append(second)
        fields[name] = ranges

    return fields
