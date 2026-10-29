/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "quicktrans/detail/code-space.h"
#define FT_LA_CHECK_SPACE(out, bytes) ft_code_space_check(out, bytes)
#include "quicktrans/detail/fast-la-emit.h"

static void region_boundary(unsigned char *boundary, size_t remaining)
{
    uint32_t *start = (uint32_t *)(boundary - remaining);
    FtCodeSpace space;
    int result;

    memset(start, 0xa5, remaining);
    ft_code_space_init(&space, (uintptr_t)start, remaining);
    result = setjmp(space.unwind);
    if (!result) {
        uint32_t *out = start;
        ft_code_space_activate(&space);
        /* The last write would reach a PROT_NONE page without the guard. */
        for (size_t i = 0; i <= remaining / 4; ++i) {
            ft_la_emit_u32(&out, 0x03400000);
        }
        abort();
    }
    ft_code_space_clear();
    assert(result == FT_CODE_REGION_FULL);
    for (size_t i = 0; i < remaining / 4; ++i) {
        assert(start[i] == 0x03400000);
    }
}

static void cache_boundary(unsigned char *boundary)
{
    FtCodeSpace space;
    uint32_t src[16] = {0};
    uint32_t *dst = (uint32_t *)(boundary - 32);
    int result;

    memset(dst, 0xa5, 32);
    ft_code_space_init(&space, (uintptr_t)dst, 32);
    result = setjmp(space.unwind);
    if (!result) {
        ft_code_space_activate(&space);
        ft_code_space_check(dst, sizeof(src));
        memcpy(dst, src, sizeof(src));
        abort();
    }
    ft_code_space_clear();
    assert(result == FT_CODE_REGION_FULL);
    for (int i = 0; i < 8; ++i) {
        assert(dst[i] == 0xa5a5a5a5);
    }
}

static void offset_limit(unsigned char *buffer, size_t available)
{
    FtCodeSpace space;
    uint32_t *start = (uint32_t *)buffer;
    int result;

    memset(buffer, 0xa5, available);
    ft_code_space_init(&space, (uintptr_t)start, available);
    result = setjmp(space.unwind);
    if (!result) {
        uint32_t *out = start;
        ft_code_space_activate(&space);
        for (size_t i = 0; i <= FT_CODE_MAX_BYTES / 4; ++i) {
            ft_la_emit_u32(&out, 0x03400000);
        }
        abort();
    }
    ft_code_space_clear();
    assert(result == FT_CODE_TB_TOO_LARGE);
    assert(start[FT_CODE_MAX_BYTES / 4] == 0xa5a5a5a5);
    assert(start[FT_CODE_MAX_BYTES / 4 - 1] == 0x03400000);
}

int main(void)
{
    size_t page = sysconf(_SC_PAGESIZE);
    size_t usable = (131072 + page - 1) / page * page;
    unsigned char *p = mmap(NULL, usable + page, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(p != MAP_FAILED);
    assert(mprotect(p + usable, page, PROT_NONE) == 0);
    const size_t sizes[] = {0, 4, 16, 60, 64, 68, 1024, 4096};
    for (unsigned i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
        region_boundary(p + usable, sizes[i]);
    }
    cache_boundary(p + usable);
    offset_limit(p, usable);
    /* A failed TB must not leave an active limit for independent emitters. */
    uint32_t word, *out = &word;
    ft_la_emit_u32(&out, 0x03400000);
    assert(word == 0x03400000);
    assert(munmap(p, usable + page) == 0);
    puts("code-space: protected-page, cache-copy and 16-bit limits PASS");
    return 0;
}
