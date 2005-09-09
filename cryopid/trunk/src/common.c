#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include "cryopid.h"

int syscall_check(int retval, int can_be_fake, char* desc, ...)
{
    va_list va_args;
    /* can_be_fake is true if the syscall might return -1 anyway, and
     * we should simply check errno.
     */
    if (can_be_fake && errno == 0) return retval;
    if (retval == -1) {
	char str[1024];
	snprintf(str, 1024, "Error in %s: %s\n", desc, strerror(errno));
	va_start(va_args, desc);
	vfprintf(stderr, str, va_args);
	va_end(va_args);
	exit(1);
    }
    return retval;
}

#ifdef COMPILING_STUB
/* If we're a stub, lets use a custom malloc implementation so that we don't
 * collide with pages potentially in use by the application. Here's a really
 * really stupid malloc, that simply mmaps a new VMA for each request, and rounds
 * up to the next multiple of PAGE_SIZE.
 *
 * FIXME: do something smarter. Can we persuade malloc to stick to brk'ing and
 * not mmap()?
 */
static void cp_malloc_init_hook();

static void* (*old_malloc_hook)(size_t, const void *);
void (*__malloc_initialize_hook) (void) = cp_malloc_init_hook;

#include <sys/mman.h>
static void *cp_malloc_hook(size_t size, const void *caller)
{
    static long next_free_addr = MALLOC_START;
    int full_len = size + 0x1000 - (size & 0x0fff)?:0x1000;
    if (next_free_addr + full_len > MALLOC_END)
	return NULL; /* out of memory here */
    void *p = mmap((void*)next_free_addr, full_len, PROT_READ|PROT_WRITE,
	    MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
    assert(p == (void*)next_free_addr);
    next_free_addr += full_len;
    return p;
}

static void cp_free_hook(void *ptr, const void *caller)
{
    /* Don't worry about freeing it, because our memory segment will be munmap'd
     * before the real binary executes. However this does waste memory if we
     * do lots of mallocing and freeing. FIXME. fix this.
     */
}

static void cp_malloc_init_hook()
{
    old_malloc_hook = __malloc_hook;
    __malloc_hook = cp_malloc_hook;
    __free_hook = cp_free_hook;
}

#endif

void *xmalloc(int len)
{
    void *p;
    p = malloc(len);
    if (!p)
	    bail("Out of memory!");
    return p;
}

unsigned int checksum(char *ptr, int len, unsigned int start)
{
    int sum = start, i;
    for (i = 0; i < len; i++)
	sum = ((sum << 5) + sum) ^ ptr[i];
    return sum;
}

unsigned long get_task_size()
{
    int stack_var;
    return (unsigned long)((((unsigned long)&stack_var + GB)/GB)*GB);
}

/* vim:set ts=8 sw=4 noet: */
