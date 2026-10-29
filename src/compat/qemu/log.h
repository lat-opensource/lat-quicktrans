/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/*
 * Minimal QEMU log compatibility layer for decoder-only standalone use.
 */
#ifndef QUICKTRANS_COMPAT_QEMU_LOG_H
#define QUICKTRANS_COMPAT_QEMU_LOG_H

#include <stdarg.h>
#include <stdio.h>

static inline void qemu_log_mask(int mask, const char *fmt, ...)
{
    (void)mask;
    (void)fmt;
}

#endif
