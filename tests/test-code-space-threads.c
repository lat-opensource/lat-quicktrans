/* Targeted TLS storage regression: each thread owns its limit and unwind state. */
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include "quicktrans/detail/code-space.h"
#define FT_LA_CHECK_SPACE(out, bytes) ft_code_space_check(out, bytes)
#include "quicktrans/detail/fast-la-emit.h"

static pthread_barrier_t barrier;
typedef struct { size_t words; uint32_t data[4]; } ThreadCase;
static void sync_threads(void)
{
    int result = pthread_barrier_wait(&barrier);
    assert(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
static void *worker(void *opaque)
{
    ThreadCase *c = opaque;
    FtCodeSpace space;
    assert(ft_code_space_active == NULL);
    assert(ft_code_space_end == UINTPTR_MAX);
    ft_code_space_init(&space, (uintptr_t)c->data, c->words * 4);
    int result = setjmp(space.unwind);
    if (!result) {
        uint32_t *out = c->data;
        ft_code_space_activate(&space);
        sync_threads();
        assert(ft_code_space_active == &space);
        for (size_t i = 0; i <= c->words; ++i) {
            ft_la_emit_u32(&out, 0x03400000);
        }
        assert(0 && "capacity guard failed");
    }
    assert(result == FT_CODE_REGION_FULL);
    sync_threads();
    assert(ft_code_space_active == &space);
    ft_code_space_clear();
    for (size_t i = 0; i < c->words; ++i) assert(c->data[i] == 0x03400000);
    assert(c->data[c->words] == 0xa5a5a5a5);
    return NULL;
}
int main(void)
{
    FtCodeSpace parent;
    uint32_t word;
    pthread_t threads[2];
    ThreadCase cases[2] = {{1, {0}}, {2, {0}}};
    ft_code_space_init(&parent, (uintptr_t)&word, sizeof(word));
    ft_code_space_activate(&parent);
    assert(pthread_barrier_init(&barrier, NULL, 2) == 0);
    for (int n = 0; n < 2; ++n) {
        for (int i = 0; i < 4; ++i) cases[n].data[i] = 0xa5a5a5a5;
        assert(pthread_create(&threads[n], NULL, worker, &cases[n]) == 0);
    }
    for (int n = 0; n < 2; ++n) assert(pthread_join(threads[n], NULL) == 0);
    assert(ft_code_space_active == &parent);
    assert(ft_code_space_end == (uintptr_t)&word + sizeof(word));
    ft_code_space_clear();
    assert(pthread_barrier_destroy(&barrier) == 0);
    puts("code-space: parent and two concurrent thread limits/unwind states PASS");
    return 0;
}
