/* module to manage host libc __getpid stored in the image (ELF) file */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <linux/unistd.h>
#include <asm/ldt.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>

#include "cpimage.h"
#include "cryopid.h"

extern struct user_regs_struct* regs(void);

static void libc_hack_load(char *data)
{
    char *dest = (char*)GETPID_HACK_ADDR;
    struct user_regs_struct *r = regs();

    /* Create region for __getpid refresh hack */
    syscall_check(
	(int)mmap((void*)GETPID_HACK_ADDR, _getpagesize, PROT_READ|PROT_WRITE|PROT_EXEC,
	    MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0, 0), 0, "mmap hack");

    /* set up gs */
    if (!emulate_tls && r->xgs != 0) {
	*dest++=0x66;*dest++=0xb8; *(short*)(dest) = r->xgs; dest+=2; /* mov foo, %eax  */
	*dest++=0x8e;*dest++=0xe8; /* mov %eax, %gs */
	*dest++=0xba;*dest++=0x00;*dest++=0x00;*dest++=0x00;*dest++=0x00; /* mov $0x00, %edx */
	*dest++=0xb9;*dest++=0x00;*dest++=0x00;*dest++=0x00;*dest++=0x00; /* mov $0x00, %ecx */

	/* insert the assembly code of __getpid */
	memcpy(dest, data, SIGNATURE_LENGTH);
    }

    /* restoring VMA previous settings */
    syscall_check(
	(int)mprotect((void*)GETPID_HACK_ADDR, _getpagesize, PROT_READ|PROT_EXEC),
	    0, "mprotect hack");
}

void read_chunk_getpid(void *fptr, int action)
{
    char* signature = (char*) xmalloc(SIGNATURE_LENGTH);
    read_bit(fptr, signature, SIGNATURE_LENGTH);
    if (action & ACTION_PRINT) {
	int i;
	/* printf out signature's bytes */
	info("__getpid hack signature:\n");
	for (i = 0; i < SIGNATURE_LENGTH; i++) {
	    info("[%d] byte value: 0x%02x\t", i, (unsigned char) *(signature + i));
	    if ((!(i % 4) && (i != 0)) || (i == (SIGNATURE_LENGTH-1)))
		info("\n");
	}
    }
    if (action & ACTION_LOAD)
	libc_hack_load(signature);
}
