/* SPDX-License-Identifier: MIT */
#ifndef QUICKTRANS_CODE_SPACE_H
#define QUICKTRANS_CODE_SPACE_H

#include <setjmp.h>
#include <stddef.h>
#include <stdint.h>

/* LATS uses 16-bit byte offsets; 0xffff is also a link sentinel. */
#define FT_CODE_MAX_BYTES (UINT16_MAX & ~(size_t)3)
enum { FT_CODE_REGION_FULL = 1, FT_CODE_TB_TOO_LARGE = 2 };

typedef struct FtCodeSpace {
    jmp_buf unwind;
    uintptr_t end;
    int error;
} FtCodeSpace;

/* Private to the emitter translation unit. Other clients of fast-la-emit.h
 * (including LATU) retain their original unchecked primitive. */
/* LATS statically links this emitter into its main executable, so TLS is
 * allocated at process startup. local-exec avoids __tls_get_addr calls
 * on normal store checks while preserving independent per-thread state.
 * This header is not used by QUICKTRANS_LATU. */
static __thread FtCodeSpace *ft_code_space_active
    __attribute__((tls_model("local-exec")));
static __thread uintptr_t ft_code_space_end
    __attribute__((tls_model("local-exec"))) = UINTPTR_MAX;

static inline void ft_code_space_init(FtCodeSpace *space, uintptr_t start,
                                      size_t available)
{
    size_t bytes = available < FT_CODE_MAX_BYTES ? available : FT_CODE_MAX_BYTES;
    space->end = start + bytes;
    space->error = available < FT_CODE_MAX_BYTES ? FT_CODE_REGION_FULL
                                               : FT_CODE_TB_TOO_LARGE;
}

static inline void ft_code_space_activate(FtCodeSpace *space)
{
    ft_code_space_active = space;
    ft_code_space_end = space->end;
}

static inline void ft_code_space_clear(void)
{
    ft_code_space_end = UINTPTR_MAX;
    ft_code_space_active = NULL;
}

static __attribute__((cold, noinline, noreturn)) void ft_code_space_fail(void)
{
    longjmp(ft_code_space_active->unwind, ft_code_space_active->error);
}

static inline void ft_code_space_check(const void *out, size_t bytes)
{
    /* One predictable branch. No allocation, logging, or remaining-space
     * bookkeeping on a successful store. Cache copies check once per copy. */
    /* Callers pass one word or a <=16-word cache entry. end is a valid
     * code-buffer address (or UINTPTR_MAX), so subtracting bytes is safe. */
    if (__builtin_expect((uintptr_t)out > ft_code_space_end - bytes, 0)) {
        ft_code_space_fail();
    }
}
#endif
