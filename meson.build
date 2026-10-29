project(
  'quicktrans',
  'c',
  version: '0.1.0',
  meson_version: '>=0.49.0',
  default_options: [
    'c_std=gnu11',
    'warning_level=2',
  ],
)

python = find_program('python3')
source_root = meson.current_source_dir()

run_command(
  python,
  'tools/generate-fast-la-emit.py',
  'tools/reference/inst_template.json',
  'tools/reference/ir2-assemble.c',
  'include/quicktrans/detail/fast-la-emit.h',
  check: true,
)

quicktrans_include_directories = include_directories(
  'include',
  'include/quicktrans/detail',
  'src/compat',
  'src/decoder',
  'src/templates',
)

quicktrans_c_args = [
  '-DQUICKTRANS_BUILD',
  '-fvisibility=hidden',
  '-Wno-unused-function',
  '-Wno-unused-parameter',
  '-Wno-missing-field-initializers',
]

quicktrans_sources = files(
  'src/quicktrans.c',
  'src/failure.c',
  'src/stats.c',
  'src/decoder/fast_decoder.c',
  'src/decoder/fast_decoder_sse.c',
  'src/templates/fast_decoder_template.c',
  'src/emitter/emitter.c',
)

quicktrans_library = shared_library(
  'quicktrans',
  quicktrans_sources,
  include_directories: quicktrans_include_directories,
  c_args: quicktrans_c_args,
  version: meson.project_version(),
  soversion: '0',
  install: true,
)

install_subdir(
  'include/quicktrans',
  install_dir: get_option('includedir'),
)

install_data(
  'LICENSE',
  'LICENSES/BSD-3-Clause.txt',
  'THIRD_PARTY_NOTICES.md',
  install_dir: join_paths(get_option('datadir'), 'licenses', 'quicktrans'),
)

quicktrans_smoke = executable(
  'quicktrans_smoke',
  'tests/smoke.c',
  include_directories: quicktrans_include_directories,
  link_with: quicktrans_library,
)
test('quicktrans_smoke', quicktrans_smoke)

quicktrans_fast_decoder_hot = executable(
  'quicktrans_fast_decoder_hot',
  'tests/fast_decoder_hot.c',
  'src/decoder/fast_decoder.c',
  'src/decoder/fast_decoder_sse.c',
  'src/templates/fast_decoder_template.c',
  include_directories: quicktrans_include_directories,
  c_args: quicktrans_c_args,
)
test('quicktrans_fast_decoder_hot', quicktrans_fast_decoder_hot)

fast_translator_check_sources = files(
  'src/emitter/fast_translator/fast-translator.c',
  'src/emitter/fast_translator/constraints.inc.c',
  'src/emitter/fast_translator/emit-alu.inc.c',
  'src/emitter/fast_translator/emit-atomic-div.inc.c',
  'src/emitter/fast_translator/emit-bit.inc.c',
  'src/emitter/fast_translator/emit-core.inc.c',
  'src/emitter/fast_translator/emit-dispatch.inc.c',
  'src/emitter/fast_translator/emit-env.inc.c',
  'src/emitter/fast_translator/emit-exit.inc.c',
  'src/emitter/fast_translator/emit-flags.inc.c',
  'src/emitter/fast_translator/emit-gpr.inc.c',
  'src/emitter/fast_translator/emit-grp1.inc.c',
  'src/emitter/fast_translator/emit-helper.inc.c',
  'src/emitter/fast_translator/emit-host-abi.inc.c',
  'src/emitter/fast_translator/emit-memory.inc.c',
  'src/emitter/fast_translator/emit-misc.inc.c',
  'src/emitter/fast_translator/emit-pattern-cache.inc.c',
  'src/emitter/fast_translator/emit-shift.inc.c',
  'src/emitter/fast_translator/emit-simd.inc.c',
  'src/emitter/fast_translator/emit-stack.inc.c',
  'src/emitter/fast_translator/emit-string.inc.c',
  'src/emitter/fast_translator/emit-template.inc.c',
  'src/emitter/fast_translator/emit-x87-helper.inc.c',
  'src/emitter/fast_translator/emit-x87.inc.c',
  'src/emitter/fast_translator/fields.inc.c',
  'src/emitter/fast_translator/operand-address.inc.c',
  'src/emitter/fast_translator/template-class.inc.c',
  'src/emitter/fast_translator/template-info.inc.c',
)

test(
  'quicktrans_template_constraints',
  python,
  args: [
    files('tools/check-fast-template-constraints.py'),
    files('src/templates/fast_decoder_template.c'),
    files('src/emitter/fast_translator/constraints.inc.c'),
  ],
)

test(
  'quicktrans_la_emit',
  python,
  args: [
    files('tools/check-fast-la-emit.py'),
    files('tools/reference/inst_template.json'),
    files('tools/reference/ir2-assemble.c'),
    join_paths(source_root, 'include/quicktrans/detail'),
  ],
)

test(
  'quicktrans_la_opcodes',
  python,
  args: [
    files('tools/check-fast-la-opcodes.py'),
    fast_translator_check_sources,
    files('include/quicktrans/detail/fast-la-emit.h'),
    files('tools/reference/format-table.h'),
  ],
)

test(
  'quicktrans_namespaced_includes',
  python,
  args: files('tools/check-namespaced-includes.py'),
)

test(
  'quicktrans_primary_failure_classification',
  python,
  args: [
    files('tools/check-primary-failure-classification.py'),
    files('src/emitter/fast_translator/fast-translator.c'),
  ],
)

test(
  'quicktrans_emitter_dispatch',
  python,
  args: [
    files('tests/test-emitter-dispatch.py'),
    files('src/emitter/fast_translator/emit-dispatch.inc.c'),
    files('src/emitter/fast_translator/emit-template.inc.c'),
  ],
)

test(
  'quicktrans_fast_store_tb_policy',
  python,
  args: [
    files('tools/check-fast-store-tb-policy.py'),
    files('src/emitter/fast_translator/fast-translator.c'),
  ],
)

test(
  'quicktrans_primary_flag_reduction',
  python,
  args: [
    files('tests/test-primary-flag-reduction.py'),
    files('src/emitter/fast_translator/fast-translator.c'),
  ],
)

test(
  'quicktrans_option_instptn',
  python,
  args: [
    files('tests/test-option-instptn.py'),
    files('src/emitter/fast_translator/fast-translator.c'),
  ],
)

test(
  'quicktrans_inst_pattern_cache',
  python,
  args: [
    files('tests/test-inst-pattern-cache.py'),
    files('src/emitter/fast_translator/emit-pattern-cache.inc.c'),
    files('src/emitter/fast_translator/emit-template.inc.c'),
  ],
)

test(
  'quicktrans_lats_soft_ras',
  python,
  args: [
    files('tools/check-lats-soft-ras.py'),
    files('src/emitter/fast_translator/fast-translator.c'),
  ],
)

test(
  'quicktrans_lats_direct_link',
  python,
  args: [
    files('tools/check-lats-direct-link.py'),
    files('src/emitter/fast_translator/emit-exit.inc.c'),
    files('src/emitter/fast_translator/emit-template.inc.c'),
  ],
)

test(
  'quicktrans_lats_rdtsc',
  python,
  args: [
    files('tools/check-lats-rdtsc.py'),
    files('src/emitter/fast_translator/emit-gpr.inc.c'),
  ],
)

test(
  'quicktrans_latu_tu_abi',
  python,
  args: [
    files('tools/check-latu-tu-abi.py'),
    files('src/emitter/fast_translator/emit-exit.inc.c'),
    files('src/emitter/fast_translator/emit-template.inc.c'),
  ],
)

code_space_test = executable(
  'test-code-space',
  'tests/test-code-space.c',
  include_directories: quicktrans_include_directories,
)
test('quicktrans_code_space', code_space_test)

code_space_threads_test = executable(
  'test-code-space-threads',
  'tests/test-code-space-threads.c',
  include_directories: quicktrans_include_directories,
  dependencies: dependency('threads'),
)
test('quicktrans_code_space_threads', code_space_threads_test)
