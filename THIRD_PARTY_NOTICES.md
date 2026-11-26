# Third-party notices

Quicktrans is licensed under the MIT License except where a file carries a
different SPDX license expression.

## Capstone

`include/quicktrans/detail/x86.h` contains definitions derived from the
Capstone disassembly framework and local modifications. The Capstone portions
are licensed under BSD-3-Clause; the local modifications are licensed under
MIT. The complete BSD-3-Clause terms are in `LICENSES/BSD-3-Clause.txt`.

Capstone was designed and implemented by Nguyen Anh Quynh
<aquynh@gmail.com>.

Copyright (c) 2013, COSEINC. All rights reserved.

## LATU vector AES implementation

The following files are distributed under GNU GPL version 2 only
(`GPL-2.0-only`).

- `src/emitter/fast_translator/emit-vpaes.inc.c` adapts the vector AES
  implementation from LATU's `target/i386/latx/translator/tr-vpaes.c` at
  commit `009c0358f2b9a0bd56b4dc597142fc5d44828192`.
  Copyright (c) 2021-2026 LAT Project Authors.
- `src/emitter/fast_translator/emit-vpaes-entry.inc.c` is the Quicktrans
  integration code that includes that implementation for LATU.
  Copyright (c) 2026 LATX Project Authors.

Both files ship with the source distribution. The integrated translator
compiles this code when `QUICKTRANS_LATU` is defined and both
`CONFIG_SOFTMMU` and `CONFIG_LATX_AVX_OPT` are undefined. The standalone
`libquicktrans` build excludes the integrated translator. The full GPLv2
text is in `LICENSES/GPL-2.0-only.txt` in the source tree and in
`GPL-2.0-only.txt` alongside this notice after installation.
