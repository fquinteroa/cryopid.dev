#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include "process.h"

extern char *_binary_stub_bin_start, *_binary_stub_bin_end;
extern int _binary_stub_bin_size;

void write_stub(int fd) {
    Elf32_Ehdr *e;
    Elf32_Shdr *s;
    char* strtab;
    char* stub_data = (char*)&_binary_stub_bin_start;
    int stub_size = (int)&_binary_stub_bin_size; /* eww */
    int i;

    e = (Elf32_Ehdr*)stub_data;

    assert(e->e_shoff != 0);
    assert(e->e_shentsize == sizeof(Elf32_Shdr));
    assert(e->e_shstrndx != SHN_UNDEF);

    s = (Elf32_Shdr*)(stub_data+(e->e_shoff+(e->e_shstrndx*e->e_shentsize)));
    strtab = stub_data+s->sh_offset;
    
    for (i = 0; i < e->e_shnum; i++) {
	s = (Elf32_Shdr*)(stub_data+e->e_shoff+(i*e->e_shentsize));
	if (s->sh_type != SHT_PROGBITS || s->sh_name == 0)
	    continue;

	if (memcmp(strtab+s->sh_name, "cryopid.image", 13) != 0)
	    continue;

	/* check the signature from the stub's linker script */
	if (memcmp(stub_data+s->sh_offset, "CPIM", 4) != 0) {
	    fprintf(stderr, "Found an invalid stub! Keeping on trying...\n");
	    continue;
	}

	s->sh_info = IMAGE_VERSION;
	*(long*)(stub_data+s->sh_offset) = stub_size;

	write(fd, stub_data, stub_size);
	return;
    }
    fprintf(stderr, "Couldn't find a valid stub linked in! Bugger.\n");
    exit(1);
}

/* vim:set ts=8 sw=4 noet: */
