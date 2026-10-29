# Meson integration fragment for embedding quicktrans in LATX-style trees.
#
# Usage from target/i386/latx/meson.build:
#
#   subdir('quicktrans/meson/latx')
#
# Then use the quicktrans_latx_* variables below from the parent build files.

quicktrans_root = join_paths(meson.current_source_dir(), '..', '..')

quicktrans_latx_include_directories = [
  include_directories(
    '../../../../../../linux-user',
    '../../../../../../linux-user/x86_64',
    '../../../../../../linux-user/host/loongarch',
    '../../../..',
    '../../../include',
    '../../include',
    '../../include/quicktrans/detail',
    '../../src/decoder',
    '../../src/templates',
    '../../src/emitter/fast_translator',
  ),
]

quicktrans_latx_c_args = [
  '-DNEED_CPU_H',
  '-DCONFIG_TARGET="x86_64-linux-user-config-target.h"',
  '-DCONFIG_DEVICES="x86_64-linux-user-config-devices.h"',
]

quicktrans_latx_library_sources = files(
  '../../src/failure.c',
  '../../src/stats.c',
  '../../src/decoder/fast_decoder.c',
  '../../src/templates/fast_decoder_template.c',
  '../../src/decoder/fast_decoder_sse.c',
  '../../src/emitter/fast_translator/fast-translator.c',
)

# The embedding tree creates the actual library once target-specific generated
# headers and include directories are known.

quicktrans_latx_fast_translator_check_sources = files(
  '../../src/emitter/fast_translator/fast-translator.c',
  '../../src/emitter/fast_translator/constraints.inc.c',
  '../../src/emitter/fast_translator/emit-alu.inc.c',
  '../../src/emitter/fast_translator/emit-atomic-div.inc.c',
  '../../src/emitter/fast_translator/emit-bit.inc.c',
  '../../src/emitter/fast_translator/emit-core.inc.c',
  '../../src/emitter/fast_translator/emit-dispatch.inc.c',
  '../../src/emitter/fast_translator/emit-env.inc.c',
  '../../src/emitter/fast_translator/emit-exit.inc.c',
  '../../src/emitter/fast_translator/emit-flags.inc.c',
  '../../src/emitter/fast_translator/emit-gpr.inc.c',
  '../../src/emitter/fast_translator/emit-grp1.inc.c',
  '../../src/emitter/fast_translator/emit-helper.inc.c',
  '../../src/emitter/fast_translator/emit-memory.inc.c',
  '../../src/emitter/fast_translator/emit-misc.inc.c',
  '../../src/emitter/fast_translator/emit-shift.inc.c',
  '../../src/emitter/fast_translator/emit-simd.inc.c',
  '../../src/emitter/fast_translator/emit-stack.inc.c',
  '../../src/emitter/fast_translator/emit-string.inc.c',
  '../../src/emitter/fast_translator/emit-template.inc.c',
  '../../src/emitter/fast_translator/emit-x87.inc.c',
  '../../src/emitter/fast_translator/fields.inc.c',
  '../../src/emitter/fast_translator/operand-address.inc.c',
  '../../src/emitter/fast_translator/template-class.inc.c',
  '../../src/emitter/fast_translator/template-info.inc.c',
)

quicktrans_latx_fast_decoder_template = files(
  '../../src/templates/fast_decoder_template.c',
)
quicktrans_latx_constraints_source = files(
  '../../src/emitter/fast_translator/constraints.inc.c',
)
quicktrans_latx_fast_la_emit_h = files(
  '../../include/quicktrans/detail/fast-la-emit.h',
)
quicktrans_latx_generate_fast_la_emit = files(
  '../../tools/generate-fast-la-emit.py',
)

quicktrans_latx_check_fast_template_constraints = files(
  '../../tools/check-fast-template-constraints.py',
)
quicktrans_latx_check_fast_la_emit = files(
  '../../tools/check-fast-la-emit.py',
)
quicktrans_latx_check_fast_la_opcodes = files(
  '../../tools/check-fast-la-opcodes.py',
)

quicktrans_latx_inst_template = files(
  '../../tools/reference/inst_template.json',
)
quicktrans_latx_ir2_assemble = files(
  '../../tools/reference/ir2-assemble.c',
)
quicktrans_latx_format_table_h = files(
  '../../tools/reference/format-table.h',
)
