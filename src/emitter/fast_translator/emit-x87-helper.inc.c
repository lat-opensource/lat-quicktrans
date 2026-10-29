/*
 * SPDX-FileCopyrightText: 2026 LATX Project Authors
 *
 * SPDX-License-Identifier: MIT
 */

/* x87 state conversion and soft-fpu helper boundaries. */

#include "fpu/softfloat.h"

static bool ft_x87_check_stack(CPUX86State *env, unsigned int inputs,
                               unsigned int outputs, int push, int pops);

static void ft_convert_fpregs_64_to_x80(CPUX86State *env)
{
    float_status status = env->fp_status;
    for (int i = 0; i < 8; i++) {
        env->fpregs[i].d = float64_to_floatx80(
            (float64)env->fpregs[i].d.low, &status);
    }
}

static void ft_convert_fpregs_x80_to_64(CPUX86State *env)
{
    float_status status = env->fp_status;
    for (int i = 0; i < 8; i++) {
        env->fpregs[i].d.low =
            (uint64_t)floatx80_to_float64(env->fpregs[i].d, &status);
        env->fpregs[i].d.high = 0;
    }
}

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
    if (getenv("LATX_QT_X87_TRACE")) {
        unsigned int top = env->fpstt;
        floatx80 st0 = env->fpregs[top].d;
        fprintf(stderr, "[QT-X87] %s top=%u tag0=%u tag1=%u st0=%04x:%016" PRIx64 "\n",
                op, top, env->fptags[top], env->fptags[(top + 1) & 7],
                st0.high, st0.low);
    }
}

static void ft_x87_helper_fsincos(CPUX86State *env)
{
    if (!ft_x87_check_stack(env, 1, 3, 1, 0)) {
        return;
    }
    floatx80 input = env->fpregs[env->fpstt].d;

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
    if (getenv("LATX_QT_X87_TRACE")) {
        fprintf(stderr, "[QT-X87] fstl value=%016" PRIx64 "\n", value);
    }
    return value;
}

static uint32_t ft_x87_helper_fsts(CPUX86State *env)
{
    uint32_t value = env->fptags[env->fpstt] ? 0xffc00000u :
                     helper_fsts_ST0(env);

    if (getenv("LATX_QT_X87_TRACE")) {
        fprintf(stderr, "[QT-X87] fsts value=%08" PRIx32 "\n", value);
    }
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
    return env->fptags[env->fpstt] || env->fptags[(env->fpstt + 1) & 7];
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
FT_X87_CHECKED_UNARY(frndint)
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
    FT_X87_REG_SUBR, FT_X87_REG_DIV, FT_X87_REG_DIVR,
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
    env->fpus &= ~(1 << 9);
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
    env->fptags[index] = 0;
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
    env->fptags[env->fpstt] = 1;
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
        ft_x87_hard_set_st0_qnan(env);
        return;
    }
    ft_x87_hard_set_st(env, 1,
                       atan2(ft_x87_hard_get_st(env, 1),
                             ft_x87_hard_get_st(env, 0)));
    ft_x87_hard_pop(env);
}

static void ft_x87_hard_fprem_common(CPUX86State *env, bool nearest)
{
    double dividend;
    double divisor;
    double result;
    int quotient = 0;
    int expdiff;

    if (ft_x87_st1_empty(env)) {
        ft_x87_hard_set_st0_qnan(env);
        return;
    }

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
        ft_x87_hard_set_st0_qnan(env);
        return;
    }
    ft_x87_hard_set_st(env, 1,
                       ft_x87_hard_get_st(env, 1) *
                       log2(ft_x87_hard_get_st(env, 0)));
    ft_x87_hard_pop(env);
}
