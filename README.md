# Quicktrans

Quicktrans provides an x86 decoder, translation templates, and a LoongArch
code generator for integration with LATX runtimes.

## Build and test

A C compiler, Python 3, Meson and Ninja are required.

```sh
meson setup build
ninja -C build
ninja -C build test
```

The standalone library is `build/libquicktrans.so`. It exposes decoding,
template extraction and instruction-buffer APIs. The full translator needs
host CPU state, memory access, exception recovery and TB linking interfaces;
it is compiled by the embedding LATX runtime, not by the standalone library.

Public headers are in `include/quicktrans`. Headers under `detail` are internal
and may change with the embedding interface. Decoder sources are in
`src/decoder`, templates in `src/templates`, and the integrated translator in
`src/emitter/fast_translator`. The `meson/latx` fragment supplies host build inputs.

The build regenerates `include/quicktrans/detail/fast-la-emit.h` from the
reference instruction descriptions. Keep generated code and references in sync.

## License

Quicktrans is distributed under the MIT License. Capstone-derived definitions
retain their BSD-3-Clause terms. See `LICENSE`, `LICENSES/BSD-3-Clause.txt`, and
`THIRD_PARTY_NOTICES.md`; all copyright and attribution notices are retained.
