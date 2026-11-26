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

Quicktrans uses the MIT License except where individual files specify other
terms. Capstone-derived definitions retain their BSD-3-Clause terms.

Two files under `src/emitter/fast_translator/` use GPL-2.0-only.
`emit-vpaes.inc.c` adapts the vector AES implementation from LATU's
`tr-vpaes.c`. `emit-vpaes-entry.inc.c` integrates it into the LATU translator.
Both ship in the source tree. They are compiled only for the LATU user-mode
translator when `CONFIG_LATX_AVX_OPT` is undefined. The default standalone
`libquicktrans` build excludes them.

See [third-party notices](THIRD_PARTY_NOTICES.md) for attribution and the
[MIT](LICENSE), [BSD-3-Clause](LICENSES/BSD-3-Clause.txt), and
[GPLv2](LICENSES/GPL-2.0-only.txt) files for the full terms.

## Host integration

See [embedding instructions](docs/embedding-latx.md) and the
[translator ABI](docs/translator-abi.md) for required host contracts.
