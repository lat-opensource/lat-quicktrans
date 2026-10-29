#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT

import pathlib
import sys


def main() -> int:
    source = pathlib.Path(sys.argv[1]).read_text()
    forbidden = "ft_template_needs_store_tb_boundary"

    if forbidden in source:
        print("ordinary stores must not force Quicktrans TB boundaries",
              file=sys.stderr)
        return 1

    required = (
        "ft_set_insn_start_data(i, fields->address);",
        "ft_set_insn_end_off(i, emitted << 2);",
    )
    missing = [snippet for snippet in required if source.count(snippet) < 2]
    if missing:
        print("multi-instruction signal unwind metadata is incomplete: " +
              ", ".join(missing), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
