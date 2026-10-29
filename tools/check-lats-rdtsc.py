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
    system_body, user_body = body.split("#else", 1)
    require(system_body, "helper_rdtsc",
            "system-mode RDTSC must use the virtual TSC helper")
    require(system_body, "offsetof(CPUX86State, tsc_aux)",
            "system-mode RDTSCP must load TSC_AUX")
    if "FT_LA_RDTIME_D_EMIT" in system_body:
        raise SystemExit("system-mode RDTSC must not read the host counter")
    require(user_body, "FT_LA_RDTIME_D_EMIT",
            "non-system RDTSC lost its direct counter implementation")


if __name__ == "__main__":
    main()
