# Quicktrans Translator ABI

Quicktrans is shared by three LATX execution environments. They use the same
x86 decoder and most of the same LoongArch emitter, but their live register and
architectural-state contracts are not identical. A host must select the ABI at
compile time; runtime probing is not supported.

## ABI Selection

| Host translator | Required definitions | ABI family |
|-----------------|----------------------|------------|
| LATU linux-user | `QUICKTRANS_LATU`, no `CONFIG_SOFTMMU` | LATU |
| LATS linux-user | no `QUICKTRANS_LATU`, no `CONFIG_SOFTMMU` | LATS |
| LATS system | no `QUICKTRANS_LATU`, `CONFIG_SOFTMMU` | LATS system |

`QUICKTRANS_LATU` belongs in LATU's per-target build arguments. LATS must not
define it: LATS user mode and system mode share the LATS architectural-state
layout even though only system mode defines `CONFIG_SOFTMMU`.

## State Contract

| State | LATU linux-user | LATS linux-user | LATS system |
|-------|-----------------|-----------------|-------------|
| x86 GPRs | LATU `reg-map.h` fixed LoongArch registers | LATS `reg-map.h` fixed LoongArch registers | LATS `reg-map.h` fixed LoongArch registers |
| CPU env | host ABI env pointer reconstructed by `ft_emit_cpu_env_ptr()` | same interface | persistent system env register through the same interface |
| Arithmetic flags | live LBT flags; persistent flags and DF metadata also carried in `la_a6` | live LBT flags, persistent condition value in `env->cc_src`, operation in `env->cc_op` | same as LATS user mode |
| Direction flag | bit 10 of `la_a6` | `env->df`, encoded as `1` for forward and `-1` for reverse | `env->df`, same encoding |
| SIMD state | XMM0-XMM15 in the low 128 bits of separate LoongArch vector registers | same mapping | same mapping |
| x87 state | `env` plus shared LBT TOP/tag software state | same shared x87 implementation | same shared x87 implementation |
| Guest memory | direct guest virtual address | direct guest virtual address | HAMT-managed CPL3 accesses use guest VA; privileged/helper boundaries use the system mapping contract |
| Helper boundary | save mapped GPRs and LATU flag metadata, call helper, restore LATU state | save mapped GPRs and `cc_src`/`cc_op`, call helper, restore LATS state | additionally obey DMW/ASID and system context-switch exit rules |
| TB exit/link | LATU `canlink`/`lazypc` metadata and context-switch stubs | LATS `jmp_insn_offset`/`jmp_reset_offset`/`next_pc` link slots | The same LATS link-slot ABI, plus system cross-page and context-switch rules |

LATU reserves `canlink == LATX_CANLINK_EIP_STORED` for a generated exit that
has already stored `env->eip`. The CPU execution loop must neither link that
exit nor overwrite the stored PC from `lazypc`. This state is separate from
`lazypc` because `-1` is a valid old-translator PC displacement.

## Translation-unit Branches

The three hosts share TU decoding, graph construction, and flag analysis, but
they do not share the generated branch ABI.

LATU records an internal branch in `tb->tu_jmp[]`. A full internal JCC emits
two branches followed by an unlink stub; an internal JMP emits one branch and
one unlink stub. Each unlink exit starts with `PCADDI a0, 0`. LATU later
rewrites that instruction so `a0` identifies the original branch when a TU is
unlinked. Quicktrans keeps these stubs at the end of their owning TB instead
of moving them to the end of the TU. Moving a translated TB would also require
relocating every PC-relative helper, indirect-goto, and static-code call in
that TB. Keeping the stubs inline preserves those addresses and the existing
LATU signal-unlink contract.

Only a successor present in the current TU tree is eligible for an internal
branch. A TB found only in the global hash table is an external successor. If
a JCC has fewer than two internal successors, LATU clears both `tu_jmp` slots
and emits its normal two-exit `canlink`/`lazypc` form. External CALL, JMP, and
RET paths likewise retain the ordinary LATU direct-link or indirect-goto ABI.

LATS linux-user and system mode do not use LATU unlink stubs. Quicktrans emits
LATS branch slots, then the host calls `latx_fast_patch_tu_tb_branches()` after
all TB addresses are final. A successor outside the current TU remains a
normal LATS dispatcher or link-slot exit.

The table describes ownership, not permission to access state directly from
instruction emitters. Code outside the ABI adapter should use the interfaces
below.

The supported x86 CPU contract ends at SSE4.2; Quicktrans does not maintain
architectural YMM state. The upper 128 bits of a physical LASX register are
therefore not guest state. An SSE instruction that writes an XMM register must
emit only the required 128-bit or scalar operation and must not save and
restore that LASX upper half. Each XMM register has its own physical vector
register, and helper/TB boundaries save and restore its low 128 bits.

## Shared Emitter Interface

Translator differences are isolated in
`src/emitter/fast_translator/emit-host-abi.inc.c`:

- `ft_emit_save_condition_flags()` and
  `ft_emit_restore_condition_flags()` implement helper/syscall boundaries.
- `ft_emit_set_direction_flag()` implements CLD and STD.
- `ft_emit_direction_step()` provides the signed string-index adjustment.
- `ft_emit_collect_rflags()` and `ft_emit_apply_popfq()` implement the
  persistent portion of PUSHFQ and POPFQ.
- `ft_emit_data_store()` implements translation-time selection for scalar
  guest stores. LATU and LATS system mode always return to the shared direct
  store path. LATS linux-user also emits a direct store by default, but queries
  `page_store_data_mixed_promoted(guest_pc)` while translating. Only an x86
  instruction promoted by the linux-user SIGSEGV path emits a call to
  `page_store_data_mixed()`. Generated code does not contain a runtime
  direct/mixed-page state test.
- Ordinary stores do not terminate a LATS TB. Quicktrans records the guest PC
  and generated-code end offset for every instruction, so signal unwind can
  identify a faulting store inside a multi-instruction TB. LATS marks each
  successfully generated Quicktrans TB, uses the unadjusted signal PC for
  this unwind, and redirects promotion through the normal LAT epilogue. The
  epilogue saves every mapped GPR, vector register, x87 register, and LBT flag
  before LATS flushes stale links and retranslates the promoted instruction.
  Old-translator TBs do not carry this marker and retain the existing page
  unprotect/invalidation path.
- `ft_emit_host_sha_reg_args()` and `ft_emit_host_sha_mem_args()` adapt SHA
  helper arguments. LATU helpers receive `env` before three vector pointers.
  LATS helpers receive only the three vector pointers. LATS
  `helper_sha256rnds2()` additionally receives the low two 32-bit words of
  XMM0, while LATU uses `helper_sha256rnds2_xmm0()` to read XMM0 from `env`.
  The LATS call uses `la_t4` for the helper address because LATS maps the
  generic `la_t0` scratch alias to physical `$a4`, which carries the fifth
  helper argument.
- `ft_addr_scratch0()` and `ft_addr_scratch1()` centralize the registers used
  by the shared ModRM/SIB address emitter. Instruction implementations must not
  select address scratch registers locally.
- `ft_emit_lats_direct_link_exit()` implements the common LATS linux-user and
  system direct-link slot. LATU keeps its separate link metadata contract.
- LATS linux-user indirect calls, jumps, and returns enter the host
  `intb_lookup` static code directly. LATS system mode retains its interrupt-
  aware dispatcher exit until the `int_opt=2` check is emitted in QuickTrans.

Direct host calls classify pointer arguments explicitly. `CPUX86State *env`
is a host pointer and is included in the `ft_emit_host_call()` pointer mask.
A `target_ulong` memory operand is a guest virtual address and is not included
in that mask. In LATS system mode, HAMT owns the CPL3 guest-VA mapping; applying
the DMW host-pointer conversion to that argument would change its meaning.

FXSAVE and FXRSTOR use the existing host architectural helpers, not a fallback
translator. The helper boundary saves all mapped GPR, XMM, flag, and x87 TOP
state. It preserves the computed guest VA in a host-stack slot across calls.
Soft-fpu mode passes the exact 80-bit env representation directly. Hard-fpu
mode converts the internal 64-bit approximation to 80-bit before the helper
and converts the resulting state back to 64-bit before restoring live mapped
registers. FXSAVE is also a system store TB boundary because it may write the
entire 512-byte legacy state area.

The instruction emitters call one interface for all three translators. The
adapter uses `QUICKTRANS_LATU` only where the LATU register ABI differs. System
mode behavior that is genuinely absent from both linux-user translators uses
`CONFIG_SOFTMMU` at the syscall, exception, memory, and exit boundaries.

Instruction fetch is also shared. `ft_decode_x86_window()` reads through
QEMU's `cpu_ldq_code()`, `cpu_ldl_code()`, `cpu_lduw_code()`, and
`cpu_ldub_code()` interfaces. Do not replace these with a direct guest pointer
in one host mode: the code-load interfaces preserve linux-user fault handling
and LATS-system MMU/HAMT instruction-fetch rules. A normal 15-byte window uses
four increasing-address reads. At the end of a 4K x86 page, Quicktrans first
decodes only the bytes remaining in that page. It reads the next page and
retries only when those bytes are insufficient, so a short page-ending
instruction does not fault merely because the following page is unmapped.

When adding a new ABI-sensitive operation, prefer extending this adapter with a
semantic function over adding another conditional inside an instruction
emitter. Use a local `#ifdef` only when no useful common semantic interface can
be expressed.

## Integration Checks

Every quicktrans change that touches the adapter must be built and tested in
all three configurations:

1. LATU linux-user with `QUICKTRANS_LATU`.
2. LATS linux-user without `QUICKTRANS_LATU` and with TU disabled at runtime.
3. LATS system mode without `QUICKTRANS_LATU`, with `CONFIG_SOFTMMU`, quicktrans
   enabled, and TU disabled at runtime.

Do not use a fallback translator to turn an ABI failure into a passing result.
The relevant primary quicktrans path must complete the test.

For diagnosis, `LATX_FT_DEBUG_SKIP_IDS` accepts a comma-separated list of x86
instruction IDs. It complements the existing single-ID, template-kind, PC,
range, x87-family, and SIMD-family skip controls. These switches are for
binary isolation only; a final regression must run without them and report
zero fallback translations.

LATS system mode currently enters HAMT DMW with the fixed hardware ASID
`0xf`. Concurrent QEMU processes should use separate physical CPUs and
staggered HAMT/KVM startup, but long-running train workloads have shown that
this only reduces cross-process interference; it does not eliminate it. The
system SPEC runner preserves each parallel failure and reruns it without other
guests. Final correctness results must come from a passing serial attempt.
