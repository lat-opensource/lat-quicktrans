/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* x87 state conversion and soft-fpu helper boundaries. */

#include "fpu/softfloat.h"

/* Legacy LATU hard-FPU mode may leave tags stale. This deliberately keeps
 * its unchecked stack policy, not the checked QT policy or soft-FPU modes.
 */
static bool ft_x87_latu_legacy_no_tag(void)
{
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    return option_soft_fpu == 0 && !option_fputag;
#else
    return false;
#endif
}

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
/* Keep do_fstenv's existing field widths, constants and write order. Only
 * the tag policy changes; differences from legacy padding/pointers remain.
 * The entry points capture the generated-code return address before calling
 * this serializer, so partial guest-memory faults retain the original PC.
 */
static void ft_x87_latu_store_env32(CPUX86State *env, target_ulong ptr,
                                    unsigned int tag, uintptr_t ra)
{
    unsigned int status = (env->fpus & ~0x3800) |
                          ((env->fpstt & 7) << 11);
    cpu_stl_data_ra(env, ptr, env->fpuc, ra);
    cpu_stl_data_ra(env, ptr + 4, status, ra);
    cpu_stl_data_ra(env, ptr + 8, tag, ra);
    cpu_stl_data_ra(env, ptr + 12, 0, ra);
    cpu_stl_data_ra(env, ptr + 16, 0, ra);
    cpu_stl_data_ra(env, ptr + 20, 0, ra);
    cpu_stl_data_ra(env, ptr + 24, 0, ra);
}

static void ft_x87_latu_fstenv32_no_tag(CPUX86State *env, target_ulong ptr)
{
    uintptr_t ra = GETPC();
    unsigned int tag = 0;
    /* Match tr_fpu_store_tag_to_mem: valid/empty, without classifying values. */
    for (unsigned int i = 0; i < 8; ++i) {
        unsigned int byte = env->fptags[i];
        tag |= ((byte | (byte << 1)) & 3) << (2 * i);
    }
    ft_x87_latu_store_env32(env, ptr, tag, ra);
}

/* FNSTENV observes registers; even on a guest-memory fault their raw bits
 * must survive. Convert only a local value for tag classification. */
static void ft_x87_latu_fstenv_hard(CPUX86State *env, target_ulong ptr,
                                    int data32)
{
    uintptr_t ra = GETPC();
    unsigned int tag = 0;
    float_status status = env->fp_status;

    for (unsigned int i = 0; i < 8; ++i) {
        unsigned int entry;
        if (data32 && !option_fputag) {
            unsigned int byte = env->fptags[i];
            entry = (byte | (byte << 1)) & 3;
        } else if (env->fptags[i]) {
            entry = 3;
        } else if (!env->mode_fpu) {
            /* MMX aliases have an all-ones x87 exponent. */
            entry = 2;
        } else {
            floatx80 value = float64_to_floatx80(
                (float64)env->fpregs[i].d.low, &status);
            unsigned int exp = value.high & 0x7fff;
            entry = exp == 0 && value.low == 0 ? 1 :
                    exp == 0 || exp == 0x7fff ||
                    !(value.low & (1ULL << 63)) ? 2 : 0;
        }
        tag |= entry << (2 * i);
    }
    if (data32) {
        ft_x87_latu_store_env32(env, ptr, tag, ra);
    } else {
        unsigned int sw = (env->fpus & ~0x3800) |
                          ((env->fpstt & 7) << 11);
        cpu_stw_data_ra(env, ptr, env->fpuc, ra);
        cpu_stw_data_ra(env, ptr + 2, sw, ra);
        cpu_stw_data_ra(env, ptr + 4, tag, ra);
        for (int i = 6; i < 14; i += 2) {
            cpu_stw_data_ra(env, ptr + i, 0, ra);
        }
    }
}

static void ft_x87_latu_fsave32_no_tag(CPUX86State *env, target_ulong ptr)
{
    uintptr_t ra = GETPC();
    /* Legacy tag-off FNSAVE exports all-valid tags, regardless of env tags. */
    ft_x87_latu_store_env32(env, ptr, 0, ra);
    ptr += 28;
    for (unsigned int i = 0; i < 8; ++i) {
        floatx80 value = env->fpregs[(env->fpstt + i) & 7].d;
        cpu_stq_data_ra(env, ptr, value.low, ra);
        cpu_stw_data_ra(env, ptr + 8, value.high, ra);
        ptr += 10;
    }
    /* As in do_fsave, reset only after every guest write succeeds. */
    helper_fninit(env);
}
#endif

static bool ft_x87_check_stack(CPUX86State *env, unsigned int inputs,
                               unsigned int outputs, int push, int pops);

static void ft_convert_fpregs_64_to_x80(CPUX86State *env)
{
    float_status status = env->fp_status;
    for (int i = 0; i < 8; i++) {
        env->fpregs[i].d = float64_to_floatx80(
            (float64)env->fpregs[i].d.low, &status);
    }
#if defined(QUICKTRANS_LATU) && defined(LATX_QUICKTRANS_X87_SIGNAL_ABI)
    env->qt_x87_env_format = QT_X87_ENV_X80;
#endif
}

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
/* FXSAVE is an observation, not a floating-point state conversion. Keep an
 * exact snapshot so even unused NaN payloads survive the helper unchanged.
 * MMX aliases are integer bits and must never pass through float64_to_x80.
 */
static void ft_latu_fxsave_prepare(CPUX86State *env, FPReg *saved)
{
    memcpy(saved, env->fpregs, sizeof(env->fpregs));
    if (env->mode_fpu) {
        ft_convert_fpregs_64_to_x80(env);
    } else {
        for (int i = 0; i < 8; ++i) {
            env->fpregs[i].d.high = 0xffff;
        }
    }
}

static void ft_latu_fxsave_finish(CPUX86State *env, const FPReg *saved)
{
    memcpy(env->fpregs, saved, sizeof(env->fpregs));
#ifdef LATX_QUICKTRANS_X87_SIGNAL_ABI
    env->qt_x87_env_format = env->mode_fpu ? QT_X87_ENV_HARD64 :
                                                          QT_X87_ENV_MMX64;
#endif
}
#endif

static void ft_convert_fpregs_x80_to_64(CPUX86State *env)
{
    float_status status = env->fp_status;
    for (int i = 0; i < 8; i++) {
        env->fpregs[i].d.low =
            (uint64_t)floatx80_to_float64(env->fpregs[i].d, &status);
        env->fpregs[i].d.high = 0;
    }
#if defined(QUICKTRANS_LATU) && defined(LATX_QUICKTRANS_X87_SIGNAL_ABI)
    env->qt_x87_env_format = QT_X87_ENV_HARD64;
#endif
}

#if defined(QUICKTRANS_LATU) && defined(CONFIG_LATX_FAST_TRANSLATOR) && \
    defined(TARGET_X86_64) && !defined(CONFIG_SOFTMMU) && \
    defined(LATX_QUICKTRANS_BCD_HARD64_ABI)
/* These helpers keep the real env in hard64 format throughout guest-memory
 * accesses. On a fault, restore_state_to_opc preserves the prologue snapshot;
 * the signal boundary handles the explicit env format. Async signals only
 * queue delivery until the helper returns.
 * Capture GETPC here, never inside a nested C helper or a temporary CPU env.
 */
static void ft_x87_hard_fbld(CPUX86State *env, target_ulong ptr)
{
    uintptr_t ra = GETPC();
    uint64_t val = 0;
    floatx80 value;
    float_status status;
    unsigned int top;

    env->qt_bcd_helper_env_hard64 = true;
    signal_barrier();
    /* Match helper_fbld_ST0: load the sign last, push after all loads. */
    for (int i = 8; i >= 0; --i) {
        unsigned int v = cpu_ldub_data_ra(env, ptr + i, ra);
        val = val * 100 + (v >> 4) * 10 + (v & 0xf);
    }
    value = int64_to_floatx80(val, &env->fp_status);
    if (cpu_ldub_data_ra(env, ptr + 9, ra) & 0x80) {
        value = floatx80_chs(value);
    }
    status = env->fp_status;
    top = (env->fpstt - 1) & 7;
    env->fpregs[top].d.low = floatx80_to_float64(value, &status);
    env->fpregs[top].d.high = 0;
    env->fptags[top] = 0;
    env->fpstt = top;
    signal_barrier();
    env->qt_bcd_helper_env_hard64 = false;
}

static void ft_x87_hard_bcd_merge_flags(CPUX86State *env, uint8_t old_flags)
{
    /* Match fpu_helper.c's merge_exception_flags, including deferred SE/B. */
    uint8_t flags = get_float_exception_flags(&env->fp_status);
    float_raise(old_flags, &env->fp_status);
    env->fpus |= (flags & float_flag_invalid ? 1 << 0 : 0) |
                 (flags & float_flag_divbyzero ? 1 << 2 : 0) |
                 (flags & float_flag_overflow ? 1 << 3 : 0) |
                 (flags & float_flag_underflow ? 1 << 4 : 0) |
                 (flags & float_flag_inexact ? 1 << 5 : 0) |
                 (flags & float_flag_input_denormal ? 1 << 1 : 0);
    if (env->fpus & (~env->fpuc & 0x3f)) {
        env->fpus |= (1 << 7) | (1 << 15);
    }
}

static void ft_x87_hard_fbstp(CPUX86State *env, target_ulong ptr)
{
    static const FloatRoundMode rounding_modes[4] = {
        float_round_nearest_even, float_round_down,
        float_round_up, float_round_to_zero
    };
    uintptr_t ra = GETPC();
    float_status status;
    floatx80 value;
    uint8_t old_flags;
    target_ulong mem_ref = ptr;
    int64_t val;

    env->qt_bcd_helper_env_hard64 = true;
    signal_barrier();
    /* Hard-FPU FLDCW updates the hardware rounding state, not necessarily
     * fp_status. The software integer conversion must use the current RC. */
    set_float_rounding_mode(rounding_modes[(env->fpuc >> 10) & 3],
                            &env->fp_status);
    status = env->fp_status;
    value = float64_to_floatx80(
        (float64)env->fpregs[env->fpstt].d.low, &status);
    old_flags = get_float_exception_flags(&env->fp_status);
    set_float_exception_flags(0, &env->fp_status);
    val = floatx80_to_int64(value, &env->fp_status);
    if (val >= 1000000000000000000LL || val <= -1000000000000000000LL) {
        set_float_exception_flags(float_flag_invalid, &env->fp_status);
        while (mem_ref < ptr + 7) {
            cpu_stb_data_ra(env, mem_ref++, 0, ra);
        }
        cpu_stb_data_ra(env, mem_ref++, 0xc0, ra);
        cpu_stb_data_ra(env, mem_ref++, 0xff, ra);
        cpu_stb_data_ra(env, mem_ref++, 0xff, ra);
    } else {
        target_ulong mem_end = ptr + 9;
        /* Match helper_fbst_ST0: sign first, then low BCD bytes in order. */
        if (value.high & 0x8000) {
            cpu_stb_data_ra(env, mem_end, 0x80, ra);
            val = -val;
        } else {
            cpu_stb_data_ra(env, mem_end, 0x00, ra);
        }
        while (mem_ref < mem_end && val != 0) {
            int v = val % 100;
            val /= 100;
            v = ((v / 10) << 4) | (v % 10);
            cpu_stb_data_ra(env, mem_ref++, v, ra);
        }
        while (mem_ref < mem_end) {
            cpu_stb_data_ra(env, mem_ref++, 0, ra);
        }
    }
    /* Faults leave conversion flags unmerged and TOP unchanged, as before. */
    ft_x87_hard_bcd_merge_flags(env, old_flags);
    env->fptags[env->fpstt] = 1;
    env->fpstt = (env->fpstt + 1) & 7;
    signal_barrier();
    env->qt_bcd_helper_env_hard64 = false;
}
#endif

static void ft_x87_helper_f2xm1(CPUX86State *env)
{
    if (!ft_x87_check_stack(env, 1, 1, 0, 0)) {
        return;
    }
    floatx80 st0 = env->fpregs[env->fpstt].d;
    uint16_t exponent = st0.high & 0x7fff;
    if (exponent >= 0x4000 && exponent < 0x7fff) {
        return;
    }
    helper_f2xm1(env);
}

static bool ft_x87_propagate_quiet_nans(CPUX86State *env, unsigned int dst)
{
    floatx80 a = env->fpregs[env->fpstt].d;
    floatx80 b = env->fpregs[(env->fpstt + 1) & 7].d;
    if (floatx80_is_any_nan(a) && floatx80_is_any_nan(b) &&
        !floatx80_invalid_encoding(a) && !floatx80_invalid_encoding(b) &&
        !floatx80_is_signaling_nan(a, &env->fp_status) &&
        !floatx80_is_signaling_nan(b, &env->fp_status)) {
        /* Larger significand wins; equal payloads prefer positive. */
        env->fpregs[dst].d = floatx80_add(a, b, &env->fp_status);
        return true;
    }
    return false;
}

static void ft_x87_helper_fscale(CPUX86State *env)
{
    if (!ft_x87_check_stack(env, 3, 1, 0, 0)) {
        return;
    }
    if (!ft_x87_propagate_quiet_nans(env, env->fpstt)) {
        helper_fscale(env);
    }
}

static void ft_x87_helper_fld1(CPUX86State *env)
{
    if (!ft_x87_check_stack(env, 0, 1, 1, 0)) {
        return;
    }
    helper_fpush(env);
    helper_fld1_ST0(env);
}

static void ft_x87_helper_fldz(CPUX86State *env)
{
    if (!ft_x87_check_stack(env, 0, 1, 1, 0)) {
        return;
    }
    helper_fpush(env);
    helper_fldz_ST0(env);
}

static void ft_x87_helper_fldl2t(CPUX86State *env)
{
    if (!ft_x87_check_stack(env, 0, 1, 1, 0)) {
        return;
    }
    helper_fpush(env);
    helper_fldl2t_ST0(env);
}

static void ft_x87_helper_fldl2e(CPUX86State *env)
{
    if (!ft_x87_check_stack(env, 0, 1, 1, 0)) {
        return;
    }
    helper_fpush(env);
    helper_fldl2e_ST0(env);
}

static void ft_x87_helper_fldpi(CPUX86State *env)
{
    if (!ft_x87_check_stack(env, 0, 1, 1, 0)) {
        return;
    }
    helper_fpush(env);
    helper_fldpi_ST0(env);
}

static void ft_x87_helper_fldlg2(CPUX86State *env)
{
    if (!ft_x87_check_stack(env, 0, 1, 1, 0)) {
        return;
    }
    helper_fpush(env);
    helper_fldlg2_ST0(env);
}

static void ft_x87_helper_fldln2(CPUX86State *env)
{
    if (!ft_x87_check_stack(env, 0, 1, 1, 0)) {
        return;
    }
    helper_fpush(env);
    helper_fldln2_ST0(env);
}

static void ft_x87_helper_fld_reg(CPUX86State *env, int st_index)
{
    if (!ft_x87_check_stack(env, 1u << st_index, 1, 1, 0)) {
        return;
    }
    floatx80 value = env->fpregs[(env->fpstt + st_index) & 7].d;
    helper_fpush(env);
    env->fpregs[env->fpstt].d = value;
}

static void ft_x87_trace(const char *op, CPUX86State *env)
{
#ifdef CONFIG_LATX_DEBUG
    /* Host startup diagnostic setting, as in the FST wrappers. */
    static int trace_state;
    int trace = __atomic_load_n(&trace_state, __ATOMIC_RELAXED);
    if (!trace) {
        trace = getenv("LATX_QT_X87_TRACE") ? 2 : 1;
        __atomic_store_n(&trace_state, trace, __ATOMIC_RELAXED);
    }
    if (trace == 2) {
        unsigned int top = env->fpstt;
        floatx80 st0 = env->fpregs[top].d;
        fprintf(stderr, "[QT-X87] %s top=%u tag0=%u tag1=%u st0=%04x:%016" PRIx64 "\n",
                op, top, env->fptags[top], env->fptags[(top + 1) & 7],
                st0.high, st0.low);
    }
#else
    (void)op;
    (void)env;
#endif
}

static void ft_x87_helper_fsincos(CPUX86State *env)
{
    if (!ft_x87_check_stack(env, 1, 3, 1, 0)) {
        return;
    }
    floatx80 input = env->fpregs[env->fpstt].d;
#ifdef QUICKTRANS_LATU
    /* Finite supported inputs outside |x| < 2^63 set C2 without a push. */
    unsigned exponent = input.high & 0x7fff;
    if (exponent == 0x7fff && input.low == UINT64_C(0x8000000000000000)) {
        /* Infinity is invalid, not a finite argument-reduction failure. */
        float_raise(float_flag_invalid, &env->fp_status);
        env->fpus |= 1;
        if (!(env->fpuc & 1)) {
            env->fpus |= 0x8080;
            return;
        }
        env->fpus &= ~0x600; /* Masked invalid: clear C1 and C2. */
        floatx80 indefinite = floatx80_default_nan(&env->fp_status);
        env->fpregs[env->fpstt].d = indefinite;
        helper_fpush(env);
        env->fpregs[env->fpstt].d = indefinite;
        env->fptags[env->fpstt] = 0;
        return;
    }
    if (exponent >= 0x403e && exponent < 0x7fff && (input.low >> 63)) {
        env->fpus = (env->fpus & ~0x200) | 0x400;
        return;
    }
#endif

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
    /* Existing checks above handle stack faults, infinity and range failure.
     * Keep NaN/unsupported encodings on the established separate helpers. */
    if (option_soft_fpu == 2 && exponent < 0x7fff &&
        (exponent == 0 || (input.low >> 63))) {
        helper_fsincos(env);
        ft_x87_trace("fsincos", env);
        return;
    }
#endif
    helper_fsin(env);
    helper_fpush(env);
    env->fpregs[env->fpstt].d = input;
    env->fptags[env->fpstt] = 0;
    helper_fcos(env);
    ft_x87_trace("fsincos", env);
}

static uint64_t ft_x87_helper_fstl(CPUX86State *env)
{
    uint64_t value = env->fptags[env->fpstt] ? 0xfff8000000000000ULL :
                     helper_fstl_ST0(env);
    /* This is a host startup diagnostic setting, not guest x87 state.
     * Avoid scanning the process environment for every executed store. */
#ifdef CONFIG_LATX_DEBUG
    static int trace_state;
    int trace = __atomic_load_n(&trace_state, __ATOMIC_RELAXED);
    if (!trace) {
        trace = getenv("LATX_QT_X87_TRACE") ? 2 : 1;
        __atomic_store_n(&trace_state, trace, __ATOMIC_RELAXED);
    }
    if (trace == 2) {
        fprintf(stderr, "[QT-X87] fstl value=%016" PRIx64 "\n", value);
    }
#endif
    return value;
}

static uint32_t ft_x87_helper_fsts(CPUX86State *env)
{
    uint32_t value = env->fptags[env->fpstt] ? 0xffc00000u :
                     helper_fsts_ST0(env);

    /* Cache the host startup diagnostic setting, as for FST m64. */
#ifdef CONFIG_LATX_DEBUG
    static int trace_state;
    int trace = __atomic_load_n(&trace_state, __ATOMIC_RELAXED);
    if (!trace) {
        trace = getenv("LATX_QT_X87_TRACE") ? 2 : 1;
        __atomic_store_n(&trace_state, trace, __ATOMIC_RELAXED);
    }
    if (trace == 2) {
        fprintf(stderr, "[QT-X87] fsts value=%08" PRIx32 "\n", value);
    }
#endif
    return value;
}

#ifdef CONFIG_SOFTMMU
static void ft_x87_helper_store16(CPUX86State *env, target_ulong addr,
                                  uint64_t value)
{
    cpu_stw_data_ra(env, addr, value, GETPC());
}

static void ft_x87_helper_store32(CPUX86State *env, target_ulong addr,
                                  uint64_t value)
{
    cpu_stl_data_ra(env, addr, value, GETPC());
}

static void ft_x87_helper_store64(CPUX86State *env, target_ulong addr,
                                  uint64_t value)
{
    cpu_stq_data_ra(env, addr, value, GETPC());
}
#endif

static bool ft_x87_fist_empty(CPUX86State *env)
{
    if (!env->fptags[env->fpstt]) {
        return false;
    }

    /* Empty ST(0): invalid operation plus stack underflow, with C1 cleared. */
    env->fpus |= (1 << 0) | (1 << 6);
    env->fpus &= ~(1 << 9);
    return true;
}

static int32_t ft_x87_helper_fist(CPUX86State *env)
{
    return ft_x87_fist_empty(env) ? (int16_t)0x8000 : helper_fist_ST0(env);
}

static int32_t ft_x87_helper_fistl(CPUX86State *env)
{
    return ft_x87_fist_empty(env) ? (int32_t)0x80000000u :
           helper_fistl_ST0(env);
}

static int64_t ft_x87_helper_fistll(CPUX86State *env)
{
    return ft_x87_fist_empty(env) ? (int64_t)0x8000000000000000ULL :
           helper_fistll_ST0(env);
}

static int32_t ft_x87_helper_fistt(CPUX86State *env)
{
    return ft_x87_fist_empty(env) ? (int16_t)0x8000 : helper_fistt_ST0(env);
}

static int32_t ft_x87_helper_fisttl(CPUX86State *env)
{
    return ft_x87_fist_empty(env) ? (int32_t)0x80000000u :
           helper_fisttl_ST0(env);
}

static int64_t ft_x87_helper_fisttll(CPUX86State *env)
{
    return ft_x87_fist_empty(env) ? (int64_t)0x8000000000000000ULL :
           helper_fisttll_ST0(env);
}

static bool ft_x87_st1_empty(CPUX86State *env)
{
    return !ft_x87_latu_legacy_no_tag() &&
           (env->fptags[env->fpstt] || env->fptags[(env->fpstt + 1) & 7]);
}

static void ft_x87_set_st0_qnan(CPUX86State *env)
{
    env->fpregs[env->fpstt].d = floatx80_default_nan(&env->fp_status);
    env->fptags[env->fpstt] = 0;
}

static bool ft_x87_masked_stack_underflow(CPUX86State *env)
{
    /* Stack underflow sets IE and SF, clears C1, and is masked by IM. */
    env->fpus = (env->fpus | (1 << 0) | (1 << 6)) & ~(1 << 9);
    if (!(env->fpuc & 1)) {
        env->fpus |= (1 << 7) | (1 << 15);
        return false;
    }
    return true;
}

/* Result destinations are logical indices, resolved before any stack pop. */
static void ft_x87_write_indefinite(CPUX86State *env, unsigned int index)
{
    unsigned int slot = (env->fpstt + index) & 7;
    env->fpregs[slot].d = floatx80_default_nan(&env->fp_status);
    env->fptags[slot] = 0;
}

static void ft_x87_helper_fstp80(CPUX86State *env, target_ulong ptr)
{
    CPU_LDoubleU value;
    if (env->fptags[env->fpstt]) {
        if (!ft_x87_masked_stack_underflow(env)) {
            return;
        }
        value.d = floatx80_default_nan(&env->fp_status);
    } else {
        env->fpus &= ~(1 << 9);
        value.d = env->fpregs[env->fpstt].d;
    }
    /* Match do_fstt's guest-memory access order; pop only after both stores. */
    uintptr_t retaddr = GETPC();
    cpu_stq_data_ra(env, ptr, value.l.lower, retaddr);
    cpu_stw_data_ra(env, ptr + 8, value.l.upper, retaddr);
    helper_fpop(env);
}

/* Inputs refer to the old TOP, outputs to TOP after an optional push.
 * On a stack fault, complete only masked operations here. The caller must
 * not perform another write or pop when this returns false. */
static bool ft_x87_check_stack(CPUX86State *env, unsigned int inputs,
                               unsigned int outputs, int push, int pops)
{
    if (ft_x87_latu_legacy_no_tag()) {
        return true;
    }
    bool overflow = push && !env->fptags[(env->fpstt - 1) & 7];
    bool underflow = false;
    for (unsigned int i = 0; inputs >> i; ++i) {
        if ((inputs & (1u << i)) && env->fptags[(env->fpstt + i) & 7]) {
            underflow = true;
        }
    }
    if (!overflow && !underflow) {
        return true;
    }
    bool masked = ft_x87_masked_stack_underflow(env);
    /* An empty source takes precedence over an occupied push destination. */
    if (overflow && !underflow) {
        env->fpus |= 1 << 9;
    }
    if (masked) {
        if (push) {
            helper_fpush(env);
        }
        for (unsigned int i = 0; outputs >> i; ++i) {
            if (outputs & (1u << i)) {
                ft_x87_write_indefinite(env, i);
            }
        }
        while (pops--) {
            helper_fpop(env);
        }
    }
    return false;
}

#define FT_X87_CHECKED_UNARY(name) \
static void ft_x87_helper_##name(CPUX86State *env) \
{ \
    if (ft_x87_check_stack(env, 1, 1, 0, 0)) { \
        helper_##name(env); \
    } \
}
/* FRNDINT needs only ST0. Keep the generic fault handling off the common
 * nonempty path without changing the rounding or exception implementation. */
static void ft_x87_helper_frndint(CPUX86State *env)
{
    if (ft_x87_latu_legacy_no_tag() || !env->fptags[env->fpstt] ||
        ft_x87_check_stack(env, 1, 1, 0, 0)) {
        helper_frndint(env);
    }
}
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
/* Only the mode-2 shared region uses this entry. Keep the slow function
 * separate so the nonempty path needs no host call frame. */
static __attribute__((noinline)) void ft_x87_frndint_soft_empty(CPUX86State *env)
{
    if (ft_x87_check_stack(env, 1, 1, 0, 0)) {
        helper_frndint(env);
    }
}

static void ft_x87_frndint_soft(CPUX86State *env)
{
    if (!env->fptags[env->fpstt]) {
        helper_frndint(env);
    } else {
        ft_x87_frndint_soft_empty(env);
    }
}
#endif

FT_X87_CHECKED_UNARY(fsqrt)
FT_X87_CHECKED_UNARY(fsin)
FT_X87_CHECKED_UNARY(fcos)
#undef FT_X87_CHECKED_UNARY

/* Preserve signaling NaNs in arithmetic temporaries after conversion. */
static void ft_x87_memory_flds(CPUX86State *env, uint32_t value)
{
    bool signaling = float32_is_signaling_nan(value, &env->fp_status);
    helper_flds_FT0(env, value);
    if (signaling) {
        env->ft0.low &= ~UINT64_C(0x4000000000000000);
    }
}

static void ft_x87_memory_fldl(CPUX86State *env, uint64_t value)
{
    bool signaling = float64_is_signaling_nan(value, &env->fp_status);
    helper_fldl_FT0(env, value);
    if (signaling) {
        env->ft0.low &= ~UINT64_C(0x4000000000000000);
    }
}

/* FT0 already contains the loaded memory operand. An empty ST0 must
 * become a valid indefinite result when the stack exception is masked. */
#define FT_X87_CHECKED_MEMORY(name) \
static void ft_x87_memory_##name(CPUX86State *env) \
{ \
    if (ft_x87_check_stack(env, 1, 1, 0, 0)) { \
        env->fpus &= ~(1 << 9); \
        helper_##name##_ST0_FT0(env); \
    } \
}
FT_X87_CHECKED_MEMORY(fadd)
FT_X87_CHECKED_MEMORY(fmul)
FT_X87_CHECKED_MEMORY(fsub)
FT_X87_CHECKED_MEMORY(fsubr)
FT_X87_CHECKED_MEMORY(fdiv)
FT_X87_CHECKED_MEMORY(fdivr)
#undef FT_X87_CHECKED_MEMORY

static void ft_x87_helper_fptan(CPUX86State *env)
{
    if (ft_x87_check_stack(env, 1, 3, 1, 0)) {
        helper_fptan(env);
    }
}

static void ft_x87_helper_fst_reg(CPUX86State *env, int st_index, int pop)
{
    if (!ft_x87_check_stack(env, 1, 1u << st_index, 0, pop)) {
        return;
    }
    unsigned int dst = (env->fpstt + st_index) & 7;
    env->fpregs[dst].d = env->fpregs[env->fpstt].d;
    env->fptags[dst] = 0;
    env->fpus &= ~(1 << 9);
    if (pop) {
        helper_fpop(env);
    }
}

enum {
    FT_X87_REG_ADD, FT_X87_REG_MUL, FT_X87_REG_SUB,
    FT_X87_REG_SUBR, FT_X87_REG_DIV, FT_X87_REG_DIVR, FT_X87_REG_SCALE,
    FT_X87_REG_DEST_N = 8, FT_X87_REG_POP = 16,
};

static inline void ft_x87_helper_binary_reg(CPUX86State *env, int st_index, int op)
{
    unsigned int top = env->fpstt;
    unsigned int src = (top + st_index) & 7;
    unsigned int dst = op & FT_X87_REG_DEST_N ? st_index : 0;
    if (env->fptags[top] || env->fptags[src]) {
        if (!ft_x87_masked_stack_underflow(env)) {
            return;
        }
        ft_x87_write_indefinite(env, dst);
    } else {
        env->fpus &= ~(1 << 9);
        if (op & FT_X87_REG_DEST_N) {
            switch (op & 7) {
            case FT_X87_REG_ADD: helper_fadd_STN_ST0(env, st_index); break;
            case FT_X87_REG_MUL: helper_fmul_STN_ST0(env, st_index); break;
            case FT_X87_REG_SUB: helper_fsub_STN_ST0(env, st_index); break;
            case FT_X87_REG_SUBR: helper_fsubr_STN_ST0(env, st_index); break;
            case FT_X87_REG_DIV: helper_fdiv_STN_ST0(env, st_index); break;
            case FT_X87_REG_DIVR: helper_fdivr_STN_ST0(env, st_index); break;
            }
        } else {
            helper_fmov_FT0_STN(env, st_index);
            switch (op & 7) {
            case FT_X87_REG_ADD: helper_fadd_ST0_FT0(env); break;
            case FT_X87_REG_MUL: helper_fmul_ST0_FT0(env); break;
            case FT_X87_REG_SUB: helper_fsub_ST0_FT0(env); break;
            case FT_X87_REG_SUBR: helper_fsubr_ST0_FT0(env); break;
            case FT_X87_REG_DIV: helper_fdiv_ST0_FT0(env); break;
            case FT_X87_REG_DIVR: helper_fdivr_ST0_FT0(env); break;
            }
        }
    }
    if (op & FT_X87_REG_POP) {
        helper_fpop(env);
    }
}

#define FT_X87_BINARY_WRAPPERS(name, op) \
static void ft_x87_binary_##name##_st0(CPUX86State *env, int index) \
{ ft_x87_helper_binary_reg(env, index, op); } \
static void ft_x87_binary_##name##_stn(CPUX86State *env, int index) \
{ ft_x87_helper_binary_reg(env, index, op | FT_X87_REG_DEST_N); } \
static void ft_x87_binary_##name##_pop(CPUX86State *env, int index) \
{ ft_x87_helper_binary_reg(env, index, op | FT_X87_REG_DEST_N | FT_X87_REG_POP); }
FT_X87_BINARY_WRAPPERS(add, FT_X87_REG_ADD)
FT_X87_BINARY_WRAPPERS(mul, FT_X87_REG_MUL)
FT_X87_BINARY_WRAPPERS(sub, FT_X87_REG_SUB)
FT_X87_BINARY_WRAPPERS(subr, FT_X87_REG_SUBR)
FT_X87_BINARY_WRAPPERS(div, FT_X87_REG_DIV)
FT_X87_BINARY_WRAPPERS(divr, FT_X87_REG_DIVR)
#undef FT_X87_BINARY_WRAPPERS

#define FT_X87_BINARY_ROW(suffix) { \
    ft_x87_binary_add_##suffix, ft_x87_binary_mul_##suffix, \
    ft_x87_binary_sub_##suffix, ft_x87_binary_subr_##suffix, \
    ft_x87_binary_div_##suffix, ft_x87_binary_divr_##suffix }
/* Select the operation while translating, without a generated mode argument. */
static void (*const ft_x87_binary_helpers[3][6])(CPUX86State *, int) = {
    FT_X87_BINARY_ROW(st0), FT_X87_BINARY_ROW(stn), FT_X87_BINARY_ROW(pop)
};
#undef FT_X87_BINARY_ROW

/* mode: quiet comparison in bit 0; number of pops in bits 1 and 2. */
static void ft_x87_helper_compare_reg(CPUX86State *env, int st_index, int mode)
{
    unsigned int top = env->fpstt;
    if (env->fptags[top] || env->fptags[(top + st_index) & 7]) {
        if (!ft_x87_masked_stack_underflow(env)) {
            return;
        }
        env->fpus |= 0x4500;
    } else {
        env->fpus &= ~(1 << 9);
        helper_fmov_FT0_STN(env, st_index);
        if (mode & 1) {
            helper_fucom_ST0_FT0(env);
        } else {
            helper_fcom_ST0_FT0(env);
        }
        if ((env->fpus & ~env->fpuc) & 0x3f) {
            return;
        }
    }
    for (int pops = mode >> 1; pops; --pops) {
        helper_fpop(env);
    }
}

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
/* Match the legacy classifier's order: an ST0 NaN precedes checking the
 * second operand for an invalid encoding. Quiet comparisons still check
 * both operands for sNaN. Only fast-mode comparison wrappers call this. */
static int ft_x87_legacy_unordered_kind(floatx80 x)
{
    unsigned exponent = x.high & 0x7fff;
    if (exponent && !(x.low >> 63)) return 2;
    return exponent == 0x7fff && (x.low << 1) != 0;
}

static bool ft_x87_legacy_snan(floatx80 x)
{
    return (x.high & 0x7fff) == 0x7fff &&
           !(x.low & (UINT64_C(1) << 62)) && (x.low << 2) != 0;
}

static bool ft_x87_fast_unordered(CPUX86State *env, floatx80 a,
                                   floatx80 b, bool quiet, bool flags)
{
    int kind = ft_x87_legacy_unordered_kind(a);
    if (!kind) kind = ft_x87_legacy_unordered_kind(b);
    if (!kind) return false;
    if (flags) {
        env->cc_src |= CC_C | CC_P | CC_Z;
#ifdef CONFIG_LATX_OPT_EFLAGS
        __lbt_mtflag_all(env->cc_src);
#endif
    } else {
        env->fpus |= 0x4500;
    }
    if (!quiet || kind == 2 || ft_x87_legacy_snan(a) || ft_x87_legacy_snan(b)) {
        env->fp_status.float_exception_flags |= 1;
        env->fpus |= 1;
        if (!(env->fpuc & 1)) env->fpus |= 0x8080;
    }
    return true;
}
#endif

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
/* Keep the same load/compare helpers, but enter host context only once.
 * Pop remains generated code after the comparison returns, like LATS. */
static void ft_x87_helper_compare_m32_fast(CPUX86State *env, uint32_t bits)
{
    helper_flds_FT0(env, bits);
    if (!ft_x87_fast_unordered(env, env->fpregs[env->fpstt].d, env->ft0, false, false))
        helper_fcom_ST0_FT0(env);
}

static void ft_x87_helper_compare_m64_fast(CPUX86State *env, uint64_t bits)
{
    helper_fldl_FT0(env, bits);
    if (!ft_x87_fast_unordered(env, env->fpregs[env->fpstt].d, env->ft0, false, false))
        helper_fcom_ST0_FT0(env);
}

static void ft_x87_helper_compare_int_fast(CPUX86State *env, int32_t value)
{
    helper_fildl_FT0(env, value);
    if (!ft_x87_fast_unordered(env, env->fpregs[env->fpstt].d, env->ft0, false, false))
        helper_fcom_ST0_FT0(env);
}

static void ft_x87_helper_compare_reg_fast(CPUX86State *env, int st_index, int mode)
{
    unsigned top = env->fpstt;
    if (ft_x87_fast_unordered(env, env->fpregs[top].d,
                             env->fpregs[(top + st_index) & 7].d,
                             mode & 1, false)) {
        for (int pops = mode >> 1; pops; --pops) helper_fpop(env);
        return;
    }
    unsigned c1 = env->fpus & (1u << 9);
    ft_x87_helper_compare_reg(env, st_index, mode);
    /* The legacy fast comparison preserves C1, including its invalid path. */
    env->fpus = (env->fpus & ~(1u << 9)) | c1;
}
#endif

static void ft_x87_helper_unary(CPUX86State *env, int negate)
{
    if (env->fptags[env->fpstt]) {
        if (ft_x87_masked_stack_underflow(env)) {
            ft_x87_set_st0_qnan(env);
        }
        return;
    }

    if (negate) {
        helper_fchs_ST0(env);
    } else {
        helper_fabs_ST0(env);
    }
}

static void ft_x87_helper_ftst(CPUX86State *env)
{
    if (env->fptags[env->fpstt]) {
        ft_x87_masked_stack_underflow(env);
        env->fpus |= (1 << 14) | (1 << 10) | (1 << 8);
        return;
    }

    helper_fldz_FT0(env);
    helper_fcom_ST0_FT0(env);
}

static void ft_x87_helper_fcmov(CPUX86State *env, int st_index, int mode)
{
    /* Stack faults occur even when the integer condition is false. */
    if (!ft_x87_check_stack(env, 1u | (1u << st_index), 1, 0, 0)) {
        return;
    }
    /* LATU legacy and native retain C1 when both operands are valid.
     * The stack-fault helper above still clears C1 on underflow. */
#ifndef QUICKTRANS_LATU
    env->fpus &= ~(1 << 9);
#endif
#ifdef QUICKTRANS_LATU
    unsigned int flags = env->eflags;
#else
    unsigned int flags = env->cc_src;
#endif
    /* Low byte: CF/PF/ZF mask; bit 8: invert the condition. */
    if (!!(flags & (mode & 0xff)) != !!(mode & 0x100)) {
        helper_fmov_ST0_STN(env, st_index);
    }
}

static void ft_x87_helper_fxch(CPUX86State *env, int st_index)
{
    unsigned int top = env->fpstt;
    unsigned int src = (top + st_index) & 7;

    if (env->fptags[top] || env->fptags[src]) {
        if (!ft_x87_masked_stack_underflow(env)) {
            return;
        }
        /* Substitute only empty operands, then exchange both valid values. */
        if (env->fptags[top]) {
            env->fpregs[top].d = floatx80_default_nan(&env->fp_status);
        }
        if (env->fptags[src]) {
            env->fpregs[src].d = floatx80_default_nan(&env->fp_status);
        }
        env->fptags[top] = 0;
        env->fptags[src] = 0;
    }
    env->fpus &= ~(1 << 9);
    helper_fxchg_ST0_STN(env, st_index);
}

static void ft_x87_helper_fxtract(CPUX86State *env)
{
    if (ft_x87_check_stack(env, 1, 3, 1, 0)) {
        helper_fxtract(env);
    }
}

#define FT_X87_CHECKED_BINARY(name, outputs, pops) \
static void ft_x87_helper_##name(CPUX86State *env) \
{ \
    if (ft_x87_check_stack(env, 3, outputs, 0, pops)) { \
        helper_##name(env); \
    } \
}
FT_X87_CHECKED_BINARY(fprem, 1, 0)
FT_X87_CHECKED_BINARY(fprem1, 1, 0)
#undef FT_X87_CHECKED_BINARY

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
/* Mode-2 shared regions have already selected the checked soft-FPU policy.
 * Separate fault entries keep ordinary calls free of generic-check frames. */
#define FT_SOFT_UNARY_ENTRY(name) \
static __attribute__((noinline)) void ft_soft_##name##_slow(CPUX86State *env) \
{ ft_x87_helper_##name(env); } \
static void ft_soft_##name(CPUX86State *env) \
{ \
    if (!env->fptags[env->fpstt]) helper_##name(env); \
    else ft_soft_##name##_slow(env); \
}
FT_SOFT_UNARY_ENTRY(fsqrt)
FT_SOFT_UNARY_ENTRY(fsin)
#undef FT_SOFT_UNARY_ENTRY

#define FT_SOFT_BINARY_ENTRY(name) \
static __attribute__((noinline)) void ft_soft_##name##_slow(CPUX86State *env) \
{ ft_x87_helper_##name(env); } \
static void ft_soft_##name(CPUX86State *env) \
{ \
    unsigned top = env->fpstt; \
    if (!(env->fptags[top] | env->fptags[(top + 1) & 7])) helper_##name(env); \
    else ft_soft_##name##_slow(env); \
}
FT_SOFT_BINARY_ENTRY(fprem)
FT_SOFT_BINARY_ENTRY(fprem1)
#undef FT_SOFT_BINARY_ENTRY

static __attribute__((noinline)) void ft_soft_f2xm1_slow(CPUX86State *env)
{ ft_x87_helper_f2xm1(env); }
static void ft_soft_f2xm1(CPUX86State *env)
{
    if (env->fptags[env->fpstt]) { ft_soft_f2xm1_slow(env); return; }
    unsigned exponent = env->fpregs[env->fpstt].d.high & 0x7fff;
    if (exponent >= 0x4000 && exponent < 0x7fff) return;
    helper_f2xm1(env);
}
static __attribute__((noinline)) void ft_soft_fscale_slow(CPUX86State *env)
{ ft_x87_helper_fscale(env); }
static void ft_soft_fscale(CPUX86State *env)
{
    unsigned top = env->fpstt;
    if (env->fptags[top] | env->fptags[(top + 1) & 7]) {
        ft_soft_fscale_slow(env); return;
    }
    if (!ft_x87_propagate_quiet_nans(env, top)) helper_fscale(env);
}
#define FT_SOFT_MEMORY_ENTRY(name) \
static __attribute__((noinline)) void ft_soft_memory_##name##_slow(CPUX86State *env) \
{ ft_x87_memory_##name(env); } \
static void ft_soft_memory_##name(CPUX86State *env) \
{ \
    if (!env->fptags[env->fpstt]) { \
        env->fpus &= ~(1 << 9); \
        helper_##name##_ST0_FT0(env); \
    } else ft_soft_memory_##name##_slow(env); \
}
FT_SOFT_MEMORY_ENTRY(fadd)
FT_SOFT_MEMORY_ENTRY(fmul)
FT_SOFT_MEMORY_ENTRY(fsub)
FT_SOFT_MEMORY_ENTRY(fsubr)
FT_SOFT_MEMORY_ENTRY(fdiv)
FT_SOFT_MEMORY_ENTRY(fdivr)
#undef FT_SOFT_MEMORY_ENTRY
#endif

#define FT_X87_CHECKED_NAN_POP(name) \
static void ft_x87_helper_##name(CPUX86State *env) \
{ \
    if (!ft_x87_check_stack(env, 3, 2, 0, 1)) { \
        return; \
    } \
    unsigned int dst = (env->fpstt + 1) & 7; \
    if (ft_x87_propagate_quiet_nans(env, dst)) { \
        helper_fpop(env); \
        return; \
    } \
    helper_##name(env); \
}
FT_X87_CHECKED_NAN_POP(fpatan)
FT_X87_CHECKED_NAN_POP(fyl2x)
FT_X87_CHECKED_NAN_POP(fyl2xp1)
#undef FT_X87_CHECKED_NAN_POP

static void ft_x87_helper_fcomi(CPUX86State *env, int st_index, int mode)
{
#ifdef QUICKTRANS_LATU
#define FT_X87_FLAGS env->eflags
#else
#define FT_X87_FLAGS env->cc_src
#endif
    unsigned int top = env->fpstt;
    unsigned int src = (top + st_index) & 7;
    const int result_flags = CC_Z | CC_P | CC_C;
    FT_X87_FLAGS &= ~(CC_O | CC_S | CC_A);

    if (env->fptags[top] || env->fptags[src]) {
        bool masked = ft_x87_masked_stack_underflow(env);
        FT_X87_FLAGS = (FT_X87_FLAGS & ~result_flags) | result_flags;
        if (!masked) {
            return;
        }
    } else {
        helper_fmov_FT0_STN(env, st_index);
        if (mode & 1) {
            helper_fucomi_ST0_FT0(env);
        } else {
            helper_fcomi_ST0_FT0(env);
        }
        if ((env->fpus & ~env->fpuc) & 0x3f) {
            return;
        }
    }
    FT_X87_FLAGS &= ~(CC_O | CC_S | CC_A);
    if (mode & 2) {
        helper_fpop(env);
    }
#undef FT_X87_FLAGS
}

#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
static void ft_x87_helper_ftst_fast(CPUX86State *env)
{
    floatx80 zero = { .low = 0, .high = 0 };
    if (!ft_x87_fast_unordered(env, env->fpregs[env->fpstt].d, zero, false, false))
        ft_x87_helper_ftst(env);
}

static void ft_x87_helper_fcomi_fast(CPUX86State *env, int st_index, int mode)
{
    unsigned top = env->fpstt;
    if (ft_x87_fast_unordered(env, env->fpregs[top].d,
                             env->fpregs[(top + st_index) & 7].d,
                             mode & 1, true)) {
        if (mode & 2) helper_fpop(env);
        return;
    }
    ft_x87_helper_fcomi(env, st_index, mode);
}
#endif

static double ft_x87_hard_get_st(CPUX86State *env, unsigned int st_index)
{
    uint64_t bits = env->fpregs[(env->fpstt + st_index) & 7].d.low;
    double value;

    memcpy(&value, &bits, sizeof(value));
    return value;
}

static void ft_x87_hard_set_st(CPUX86State *env, unsigned int st_index,
                               double value)
{
    uint64_t bits;
    unsigned int index = (env->fpstt + st_index) & 7;

    memcpy(&bits, &value, sizeof(bits));
    env->fpregs[index].d.low = bits;
    env->fpregs[index].d.high = 0;
    if (!ft_x87_latu_legacy_no_tag()) {
        env->fptags[index] = 0;
    }
}

static void ft_x87_hard_set_st0_qnan(CPUX86State *env)
{
    uint64_t bits = UINT64_C(0xfff8000000000000);
    double value;

    memcpy(&value, &bits, sizeof(value));
    ft_x87_hard_set_st(env, 0, value);
}

static void ft_x87_hard_pop(CPUX86State *env)
{
    if (!ft_x87_latu_legacy_no_tag()) {
        env->fptags[env->fpstt] = 1;
    }
    env->fpstt = (env->fpstt + 1) & 7;
}

static void ft_x87_hard_set_quotient_flags(CPUX86State *env, int quotient)
{
    const unsigned int condition_mask = (1u << 14) | (1u << 10) |
                                        (1u << 9) | (1u << 8);

    env->fpus &= ~condition_mask;
    if (quotient & 4) {
        env->fpus |= 1u << 8;
    }
    if (quotient & 2) {
        env->fpus |= 1u << 14;
    }
    if (quotient & 1) {
        env->fpus |= 1u << 9;
    }
}

static void ft_x87_hard_fpatan(CPUX86State *env)
{
    if (ft_x87_st1_empty(env)) {
        /* A masked stack fault still writes ST(1) and pops ST(0).
         * After the pop, the result destination is the new ST(0). */
        if (ft_x87_masked_stack_underflow(env)) {
            ft_x87_hard_pop(env);
            ft_x87_hard_set_st0_qnan(env);
        }
        return;
    }
    ft_x87_hard_set_st(env, 1,
                       atan2(ft_x87_hard_get_st(env, 1),
                             ft_x87_hard_get_st(env, 0)));
    ft_x87_hard_pop(env);
}

static void ft_x87_hard_fprem_common(CPUX86State *env, bool nearest)
{
    if (ft_x87_st1_empty(env)) {
        ft_x87_hard_set_st0_qnan(env);
        return;
    }

#ifdef QUICKTRANS_LATU
    /* Match legacy's remainder/quotient and exception policy. Convert only
     * the two live operands, not all eight x87 slots. */
    int top = env->fpstt;
    int next = (top + 1) & 7;
    floatx80 saved_next = env->fpregs[next].d;
    float_status status = env->fp_status;

    env->fpregs[top].d = float64_to_floatx80(
        (float64)env->fpregs[top].d.low, &status);
    env->fpregs[next].d = float64_to_floatx80(
        (float64)saved_next.low, &status);
    if (nearest) {
        helper_fprem1(env);
    } else {
        helper_fprem(env);
    }
    status = env->fp_status;
    env->fpregs[top].d.low =
        (uint64_t)floatx80_to_float64(env->fpregs[top].d, &status);
    env->fpregs[top].d.high = 0;
    env->fpregs[next].d = saved_next;
#else
    double dividend;
    double divisor;
    double result;
    int quotient = 0;
    int expdiff;

    dividend = ft_x87_hard_get_st(env, 0);
    divisor = ft_x87_hard_get_st(env, 1);
    env->fpus &= ~((1u << 14) | (1u << 10) | (1u << 9) | (1u << 8));

    if (isfinite(dividend) && isfinite(divisor) && dividend != 0.0 &&
        divisor != 0.0 &&
        (expdiff = ilogb(fabs(dividend)) - ilogb(fabs(divisor))) >= 64) {
        int n = 32 + (expdiff % 32);
        double scaled_divisor = scalbn(divisor, expdiff - n);

        result = fmod(dividend, scaled_divisor);
        env->fpus |= 1u << 10;
    } else if (nearest) {
        result = remquo(dividend, divisor, &quotient);
        ft_x87_hard_set_quotient_flags(env, quotient);
    } else {
        double full_quotient = trunc(dividend / divisor);

        result = fmod(dividend, divisor);
        if (isfinite(full_quotient)) {
            quotient = (int)fmod(full_quotient, 8.0);
        }
        ft_x87_hard_set_quotient_flags(env, quotient);
    }
    ft_x87_hard_set_st(env, 0, result);
#endif
}

static void ft_x87_hard_fprem(CPUX86State *env)
{
    ft_x87_hard_fprem_common(env, false);
}

static void ft_x87_hard_fprem1(CPUX86State *env)
{
    ft_x87_hard_fprem_common(env, true);
}

static void ft_x87_hard_fyl2x(CPUX86State *env)
{
    if (ft_x87_st1_empty(env)) {
        /* A masked stack fault still writes ST(1) and pops ST(0).
         * After the pop, the result destination is the new ST(0). */
        if (ft_x87_masked_stack_underflow(env)) {
            ft_x87_hard_pop(env);
            ft_x87_hard_set_st0_qnan(env);
        }
        return;
    }
    ft_x87_hard_set_st(env, 1,
                       ft_x87_hard_get_st(env, 1) *
                       log2(ft_x87_hard_get_st(env, 0)));
    ft_x87_hard_pop(env);
}

#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
/* Keep the existing whole-stack representation and checked arithmetic.
 * Combining the boundary removes generated call/argument sequences only. */
static void ft_x87_hard_fxtract_checked(CPUX86State *env)
{
    ft_convert_fpregs_64_to_x80(env);
    update_fp_status(env);
    ft_x87_helper_fxtract(env);
    ft_convert_fpregs_x80_to_64(env);
}

#include <fenv.h>

/* Preserve the generic conversion for exceptional encodings. Normal doubles
 * and signed zero have an exact x80 representation, without rounding. */
static __attribute__((noinline)) void ft_x87_fyl2xp1_prepare_slots(CPUX86State *env)
{
    float_status status = env->fp_status;
    for (int i = 0; i < 8; ++i) {
        uint64_t bits = env->fpregs[i].d.low;
        unsigned int exponent = (unsigned int)((bits >> 52) & 0x7ff);
        if (exponent > 0 && exponent < 0x7ff) {
            env->fpregs[i].d = make_floatx80(
                ((bits >> 48) & 0x8000) | (exponent + 0x3c00),
                ((bits & UINT64_C(0x000fffffffffffff)) |
                 UINT64_C(0x0010000000000000)) << 11);
        } else if ((bits << 1) == 0) {
            env->fpregs[i].d = make_floatx80((bits >> 48) & 0x8000, 0);
        } else {
            env->fpregs[i].d = float64_to_floatx80((float64)bits, &status);
        }
    }
#ifdef LATX_QUICKTRANS_X87_SIGNAL_ABI
    env->qt_x87_env_format = QT_X87_ENV_X80;
#endif
}

/* Bypass rounding only when the x80 value is exactly a normal double or
 * signed zero. All subnormals, special values and inexact results stay generic. */
static __attribute__((noinline)) void ft_x87_fyl2xp1_finish_slots(CPUX86State *env)
{
    float_status status = env->fp_status;
    for (int i = 0; i < 8; ++i) {
        floatx80 value = env->fpregs[i].d;
        unsigned int exponent = value.high & 0x7fff;
        uint64_t bits;
        if (exponent >= 0x3c01 && exponent <= 0x43fe &&
            (value.low & UINT64_C(0x80000000000007ff)) ==
                UINT64_C(0x8000000000000000)) {
            bits = ((uint64_t)(value.high & 0x8000) << 48) |
                   ((uint64_t)(exponent - 0x3c00) << 52) |
                   ((value.low >> 11) & UINT64_C(0x000fffffffffffff));
        } else if (exponent == 0 && value.low == 0) {
            bits = (uint64_t)(value.high & 0x8000) << 48;
        } else {
            bits = (uint64_t)floatx80_to_float64(value, &status);
        }
        env->fpregs[i].d.low = bits;
        env->fpregs[i].d.high = 0;
    }
#ifdef LATX_QUICKTRANS_X87_SIGNAL_ABI
    env->qt_x87_env_format = QT_X87_ENV_HARD64;
#endif
}

static void ft_x87_hard_fyl2xp1_checked(CPUX86State *env)
{
    double x = ft_x87_hard_get_st(env, 0);
    double y = ft_x87_hard_get_st(env, 1);
    bool fast = (env->fpuc & 0xf3f) == 0x33f &&
        fabs(x) >= 0x1p-500 && fabs(x) <= 0.25 &&
        fabs(y) >= 0x1p-500 && fabs(y) <= 0x1p500 &&
        (ft_x87_latu_legacy_no_tag() ||
         (!env->fptags[env->fpstt] && !env->fptags[(env->fpstt + 1) & 7]));
    if (fast) {
        /* Keep the signal snapshot in hard64 format; only the result slot
         * is committed after the local extended-precision calculation. */
        /* The guard fixes RC=nearest and PC=extended. Keep the host
         * rounding update required by option_set_rounding_opt. */
        set_float_rounding_mode(float_round_nearest_even, &env->fp_status);
        if (option_set_rounding_opt) {
            fesetround(FE_TONEAREST);
        }
        set_floatx80_rounding_precision(floatx80_precision_x, &env->fp_status);
        double logarithm = log1p(x);
        uint64_t bits;
        memcpy(&bits, &logarithm, sizeof(bits));
        unsigned int dst = (env->fpstt + 1) & 7;
        uint64_t ybits;
        memcpy(&ybits, &y, sizeof(ybits));
        /* The guarded nonzero x makes log1p(x) finite and normal.
         * This conversion is exact and does not change exception flags. */
        floatx80 logarithm_x80 = make_floatx80(
            ((bits >> 48) & 0x8000) |
            (((bits >> 52) & 0x7ff) + (0x3fff - 0x3ff)),
            ((bits & UINT64_C(0x000fffffffffffff)) |
             UINT64_C(0x0010000000000000)) << 11);
        floatx80 result = floatx80_mul(
            logarithm_x80,
            make_floatx80(0x3fff, UINT64_C(0xb8aa3b295c17f0bc)),
            &env->fp_status);
        if ((ybits & UINT64_C(0x000fffffffffffff)) == 0) {
            /* The fast bounds guarantee normal operands and result. Scaling
             * by a signed power of two is exact, with no extra rounding. */
            int scale = (int)((ybits >> 52) & 0x7ff) - 1023;
            result.high = ((result.high & 0x7fff) + scale) |
                          ((result.high ^ (ybits >> 48)) & 0x8000);
        } else {
            /* The fast guard guarantees a finite normal double. Its exact
             * x80 representation needs neither rounding nor exception work. */
            floatx80 multiplier = make_floatx80(
                ((ybits >> 48) & 0x8000) |
                (((ybits >> 52) & 0x7ff) + (0x3fff - 0x3ff)),
                ((ybits & UINT64_C(0x000fffffffffffff)) |
                 UINT64_C(0x0010000000000000)) << 11);
            result = floatx80_mul(multiplier, result, &env->fp_status);
        }
        /* All exceptions are masked and bounded normal inputs can only add
         * inexact. Preserve existing internal and guest exception flags. */
        float_raise(float_flag_inexact, &env->fp_status);
        env->fpus |= 1 << 5;
        env->fpregs[dst].d.low = floatx80_to_float64(result, &env->fp_status);
        env->fpregs[dst].d.high = 0;
        helper_fpop(env);
    } else {
        ft_x87_fyl2xp1_prepare_slots(env);
        update_fp_status(env);
        ft_x87_helper_fyl2xp1(env);
        ft_x87_fyl2xp1_finish_slots(env);
    }
}
#endif
