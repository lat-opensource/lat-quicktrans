# 在 LATX 树中嵌入 quicktrans

目标：让 `lat-ft` 和未来的 `lat-sys` 共享同一个 quicktrans 子模块，避免在两个
工程里继续复制 `fast_decoder` / `fast_translator` 源码。

## 推荐子模块位置

在 LATX 工程中把 quicktrans 放到：

```text
target/i386/latx/quicktrans
```

示例：

```sh
cd /path/to/lat-ft
git submodule add /path/to/quicktrans target/i386/latx/quicktrans
git submodule update --init --recursive
```

如果之后 quicktrans 有正式远端仓库，把本地路径换成远端 URL 即可。

## 文件命名策略

quicktrans 内部按独立项目分层：

```text
src/decoder
src/templates
src/emitter
```

但核心文件名保持 LATX 原名：

```text
fast_decoder.c
fast_decoder_sse.c
fast_decoder_template.c
fast-translator.c
constraints.inc.c
emit-*.inc.c
fields.inc.c
template-info.inc.c
```

这样 quicktrans 内部仍保留原始文件名，lat-ft / lat-sys 则通过
宿主 target 循环创建的 `quicktrans_latx_<target>` 库链接进来，不需要把 quicktrans
的 `.c` 文件直接加到宿主 source set 里。quicktrans 自己仍能独立编译成
`libquicktrans.so`。

## Meson 接入

quicktrans 提供了一个专供 LATX 嵌入的 Meson 片段：

```text
target/i386/latx/quicktrans/meson/latx/meson.build
```

在 `target/i386/latx/meson.build` 中尽早加入：

```meson
subdir('quicktrans/meson/latx')
```

该片段导出以下变量，供宿主 target 循环创建库：

```meson
quicktrans_latx_library_sources
quicktrans_latx_include_directories
quicktrans_latx_c_args
quicktrans_latx_check_fast_*
```

在宿主顶层 `meson.build` 的 `foreach target : target_dirs` 中，等 `target_inc`、
`c_args` 和 syscall 生成头都确定后创建 quicktrans 库：

```meson
quicktrans_latx_target_sources = []

target_syscall_nr_sources = \
  syscall_nr_generators[abi].process(base_dir / abi / config_target['TARGET_SYSTBL'],
                                     extra_args : config_target['TARGET_SYSTBL_ABI'])
arch_srcs += target_syscall_nr_sources
quicktrans_latx_target_sources += target_syscall_nr_sources

quicktrans_latx_library = static_library(
  'quicktrans_latx_' + target,
  quicktrans_latx_library_sources + quicktrans_latx_target_sources,
  build_by_default: false,
  c_args: c_args + quicktrans_latx_c_args,
  include_directories: target_inc + quicktrans_latx_include_directories,
)
arch_deps += declare_dependency(
  link_with: quicktrans_latx_library,
  include_directories: quicktrans_latx_include_directories,
)
```

这样 `fast-translator.c` 会被编进 quicktrans 的静态库，宿主通过 dependency 链接
库和 include path。它不会链接独立安装的 `.so`。

## 移除宿主 IR1 fast decoder 源

在 `target/i386/latx/ir1/meson.build` 中，把原来的：

```meson
i386_ss.add(when: 'CONFIG_LATX', if_true: files(
  'ir1.c',
  'fast_decoder.c',
  'fast_decoder_template.c',
  'fast_decoder_sse.c',
))
```

改成：

```meson
i386_ss.add(when: 'CONFIG_LATX', if_true: files(
  'ir1.c',
))
```

随后删除宿主 `ir1/` 下的 `fast_decoder*.c` 文件。`ir1.c` 仍留在宿主
LATX 工程里，`fast_decoder_get*()` 等符号由 quicktrans 的 LATX 库链入。

## 移除宿主 fast translator 源

删除整个 `target/i386/latx/fast_translator/` 目录，并从
`target/i386/latx/meson.build` 移除对应的 `subdir()`。同时删除已迁走的
detail 头文件、旧 consistency-check 脚本和重复模块文档。

`latx_fast_decode_translate_tb_primary()`、`latx_fast_decode_tb_for_tu_explore()`
等 fast translator 符号由 quicktrans 的 `quicktrans_latx` 静态库提供。

## 生成 fast LA 编码头

Quicktrans 在配置时覆盖自己的
`include/quicktrans/detail/fast-la-emit.h`。生成器只使用 Quicktrans 已跟踪的
reference 输入，不依赖宿主的 `convert.py`：

```meson
r = run_command(
  'python3',
  quicktrans_latx_generate_fast_la_emit,
  quicktrans_latx_inst_template,
  quicktrans_latx_ir2_assemble,
  quicktrans_latx_fast_la_emit_h,
  check: true)
```

## 替换一致性检查

`target/i386/latx/meson.build` 中原有的 fast path 检查可以改为使用
quicktrans 变量：

```meson
r = run_command(
  'python3',
  quicktrans_latx_check_fast_la_opcodes,
  quicktrans_latx_fast_translator_check_sources,
  quicktrans_latx_fast_la_emit_h,
  quicktrans_latx_format_table_h,
  check: true)
message('quicktrans check-fast-la-opcodes.py ->',
        r.stdout().strip(), r.stderr().strip())

r = run_command(
  'python3',
  quicktrans_latx_check_fast_la_emit,
  quicktrans_latx_inst_template,
  quicktrans_latx_ir2_assemble,
  join_paths(quicktrans_root, 'include/quicktrans/detail'),
  check: true)
message('quicktrans check-fast-la-emit.py ->',
        r.stdout().strip(), r.stderr().strip())

r = run_command(
  'python3',
  quicktrans_latx_check_fast_template_constraints,
  quicktrans_latx_fast_decoder_template,
  quicktrans_latx_constraints_source,
  check: true)
message('quicktrans check-fast-template-constraints.py ->',
        r.stdout().strip(), r.stderr().strip())
```

宿主工程也可以先保留原来的检查脚本；但为了让 lat-ft 和 lat-sys 真正共享同一
套快速路径，建议最终统一使用 quicktrans 里的脚本和 reference 输入。

## 不建议从 quicktrans 取的文件

以下仍应留在宿主 LATX 工程中：

- `ir1.c`：Capstone shadow/primary 接入点，和宿主 IR1 buffer 生命周期绑定。
- `latx-config.c` / `latx-options.c`：环境变量、feature flag 和宿主配置绑定。
- `translator/`：normal translator oracle 和 fallback，不属于 quicktrans 子模块。
- `target/i386/tcg/translate.c`：QEMU 参考实现，不属于 quicktrans 子模块。

## lat-sys 接入建议

`lat-sys` 也按相同位置挂载 quicktrans：

```text
target/i386/latx/quicktrans
```

如果 `lat-sys` 的目录不同，只要在它的 Meson 中 `subdir()` 到
`quicktrans/meson/latx`，再在 target 循环里使用同一组 `quicktrans_latx_*`
变量创建并链接库即可。

## Debug-only instrumentation

`CONFIG_LATX_DEBUG` controls the primary translator's diagnostic skip/split
options, instruction and register traces, code dumps, stage timing and emit
cache profiling, plus x87 helper traces and direct-exit diagnostic switches.
LATX's `configure --enable-debug` defines this macro. In release builds these
options are compiled out, so setting their environment variables has no effect.
The release enable predicates are constant false and trace entry points are
empty; optimized release binaries contain neither their environment lookups
nor diagnostic state.

Strict translation failures, architectural checks, optimization switches and
the public statistics/profile interfaces remain available. Tests that require
`LATX_FT_PRIMARY_TB_TRACE`, `LATX_FT_PRIMARY_STAGE_STATS`, or forced debug
skip/split behavior must use a debug build and record that build mode with
the results. Do not compare its timing directly with historical release data.
