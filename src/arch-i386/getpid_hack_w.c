/* module to manage host libc __getpid: locate, fetch and store */
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>

#include "cpimage.h"
#include "cryopid.h"

int libc_hack_fetch(const char* name, char** signature)
{
    Elf32_Ehdr libc_ehdr;
    Elf32_Shdr libc_shdr, libc_st;
    Elf32_Off libc_stoff, dynsym_off, dynstr_off;
    Elf32_Word dynsym_size, dynstr_size;
    Elf32_Sym libc_sym;
    int libc_fd, i;
    char    *strtab = NULL, 
	    *dynsym = NULL, 
	    *dynstr = NULL;
    unsigned char asmbyte;

    libc_fd = open(name, O_RDONLY);
    if (libc_fd == -1)
	bail("[E] failed to open %s\n", name);
    
    read(libc_fd, &libc_ehdr, sizeof(Elf32_Ehdr));

    assert(libc_ehdr.e_shoff != 0); /* check section header table’s file offset */
    assert(libc_ehdr.e_shentsize == sizeof(Elf32_Shdr)); /* check section header entry size */
    assert(libc_ehdr.e_shstrndx != SHN_UNDEF); /* must exist a section name string table */

    //info("[i] section header table's offeset is: %d\n", libc_ehdr.e_shoff);
    libc_stoff = libc_ehdr.e_shoff + (libc_ehdr.e_shstrndx * libc_ehdr.e_shentsize);
    if (lseek(libc_fd, libc_stoff, SEEK_SET) == -1) /* seek to section name string table header */
	bail("[E] failed to seek to section name string table header");
    read(libc_fd, &libc_st, sizeof(Elf32_Shdr));
    assert(libc_st.sh_type == SHT_STRTAB);
    //info("[i] string table offset from file start is: %u\n", libc_st.sh_offset);

    /* fetch string table */
    strtab = (char*) xmalloc(libc_st.sh_size);
    if (lseek(libc_fd, libc_st.sh_offset, SEEK_SET) == -1) /* seek to section name string table */
	bail("[E] failed to seek to section name string table"); 
    if (read(libc_fd, strtab, libc_st.sh_size) != libc_st.sh_size)
	info("[W] failed to read the %u bytes of string table\n", libc_st.sh_size);

    /* search .dynsym and .dynstr sections 
	1- it holds the dynamic linking symbol table
	2- it holds strings needed for dynamic linking 
    */
    if (lseek(libc_fd, libc_ehdr.e_shoff, SEEK_SET) == -1) /* seek to section header table */
	bail("[E] failed to seek at %d bytes to section header table", libc_ehdr.e_shoff);
    for (i = 0; i < libc_ehdr.e_shnum; i++) {
	read(libc_fd, &libc_shdr, sizeof(Elf32_Shdr));
	if (libc_shdr.sh_type == SHT_DYNSYM) { /* libc .dynsym section */
	    //info("[i] .dynsym checked as #%d section\n", i);
	    dynsym_off = libc_shdr.sh_offset;
	    dynsym_size = libc_shdr.sh_size;
	    dynsym = (char*) xmalloc(dynsym_size);
	}
	/* libc .dynstr section */
	if ((libc_shdr.sh_type == SHT_STRTAB) && !strcmp(strtab + libc_shdr.sh_name, ".dynstr")) {
	    //info("[i] .dynstr checked as #%d section\n", i);
	    dynstr_off = libc_shdr.sh_offset;
	    dynstr_size = libc_shdr.sh_size;
	    dynstr = (char*) xmalloc(dynstr_size);
	}
    }

    /* fetch .dynsym and .dynstr sections */
    if (lseek(libc_fd, dynsym_off, SEEK_SET) == -1) /* seek to .dynsym section */
	bail("[E] failed to seek to .dynsym section"); 
    if (read(libc_fd, dynsym, dynsym_size) != dynsym_size)
	info("[W] failed to read the %u bytes of .dynsym section\n", dynsym_size);
    if (lseek(libc_fd, dynstr_off, SEEK_SET) == -1) /* seek to .dynstr section */
	bail("[E] failed to seek to .dynstr section"); 
    if (read(libc_fd, dynstr, dynstr_size) != dynstr_size)
	info("[W] failed to read the %u bytes of .dynstr section\n", dynstr_size);
    
    //info("[i] dynamic symbol elements are: %d\n", dynsym_size / sizeof(Elf32_Sym));
    /* looking for __getpid symbol */
    for (i = 0; i < (dynsym_size / sizeof(Elf32_Sym)); i++) {
	memcpy(&libc_sym, dynsym + (i * sizeof(Elf32_Sym)), sizeof(Elf32_Sym));
	if ((ELF32_ST_TYPE(libc_sym.st_info) == STT_FUNC)
		&& strstr(dynstr + libc_sym.st_name, "__getpid")) {
	    info("[+] __getpid symbol found as #%d element at address 0x%x\n", i, libc_sym.st_value);
	    break;
	}
    }
    /* now libc_sym keeps all __getpid symbol information */
    if (lseek(libc_fd, libc_sym.st_value, SEEK_SET) == -1) /* seek to .dynsym section */
	bail("[E] failed to seek to __getpid location at 0x%x", libc_sym.st_value); 
    while (1) {
	if (read(libc_fd, &asmbyte, 1) == -1)
	    bail("[E] failde to read from __getpid");
	//info("[asmbyte] asm byte: 0x%02x\n", (unsigned char) asmbyte);
	if (asmbyte == 0xb8)
	    break;
    }
    if (lseek(libc_fd, -1, SEEK_CUR) == -1) /* seek to 0xb8 */
	bail("[E] failed to seek backward to 0xb8"); 
    *signature = (char*) xmalloc(SIGNATURE_LENGTH);
    /* fetch the signature from libc */
    memset(*signature, 0, SIGNATURE_LENGTH);
    if (read(libc_fd, *signature, SIGNATURE_LENGTH) == -1)
	bail("[E] unable to fetch the signature");
    info("[+] __getpid signature fetched\n");
    /* free all the memory space allacated */
    free(dynsym);
    free(dynstr);
    /* close libc file */
    close(libc_fd);

    return EXIT_SUCCESS;
}

void write_chunk_getpid(void* fptr, struct cp_getpid* data)
{
    write_bit(fptr, data->asmcode, SIGNATURE_LENGTH);
}
