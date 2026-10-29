#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 LATX Project Authors
#
# SPDX-License-Identifier: MIT

import pathlib
import sys


def main() -> int:
    source_path = pathlib.Path(sys.argv[1])
    source = source_path.read_text()
    integration = source + "\n" + (source_path.parent / "emit-exit.inc.c").read_text()
    integration += "\n" + (source_path.parent / "emit-template.inc.c").read_text()
    required_counts = {
        "#include \"latx-ras.h\"": 1,
        "lsenv->tr_data->pc_next = ret_addr;": 2,
        "ft_emit_lats_soft_ras_push(tb, &out, ret_addr);": 2,
        "ft_emit_lats_soft_ras_pop(tb, &out, la_t1);": 2,
        "FT_LA_LU52I_D_EMIT(out, reg, reg, -0x700);": 1,
        "ft_emit_lats_tb_addr(out, tb);": 2,
    }
    missing = [
        f"{snippet} (need {count})"
        for snippet, count in required_counts.items()
        if integration.count(snippet) < count
    ]
    if missing:
        print("LATS software RAS integration is incomplete: " +
              ", ".join(missing), file=sys.stderr)
        return 1

    if integration.count("#ifndef QUICKTRANS_LATU") < 2:
        print("LATS software RAS must remain outside the LATU ABI",
              file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
