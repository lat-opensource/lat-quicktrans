#!/usr/bin/env python3

import pathlib
import sys


def require(text, needle, message):
    if needle not in text:
        raise SystemExit(message)


def main():
    source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    start = source.index("static int ft_emit_rdtsc_template(")
    end = source.index("static int ft_emit_movnti_template(", start)
    body = source[start:end]

    require(body, "#ifdef CONFIG_SOFTMMU",
            "RDTSC must have a system-mode implementation")
    system_body, user_body = body.rsplit("#else", 1)
    require(system_body, "helper_rdtsc",
            "system-mode RDTSC lost its helper fallback")
    require(system_body, "option_opt_rdtsc_rdtscp",
            "system-mode RDTSC is not controlled by the legacy option")
    require(system_body, "CONFIG_TSC_X25 scaling",
            "system-mode RDTSC lost the legacy x25 scale")
    require(system_body, "FT_LA_SLLI_D_EMIT",
            "system-mode RDTSC lost the x16 and x8 shifts")
    require(system_body, "#if !defined(QUICKTRANS_LATU) && !defined(CONFIG_LATX_RR)",
            "the LATS host-counter path must exclude LATU and record/replay")
    require(system_body, "FT_LA_RDTIME_D_EMIT",
            "enabled system-mode RDTSC must read the host counter")
    require(system_body, "FT_LA_ADD_D_EMIT",
            "enabled system-mode RDTSC lost the low frequency bit")
    require(system_body, "offsetof(CPUX86State, tsc_aux)",
            "system-mode RDTSCP must load TSC_AUX")
    require(user_body, "FT_LA_RDTIME_D_EMIT",
            "non-system RDTSC lost its direct counter implementation")


if __name__ == "__main__":
    main()
