/* module to manage host libc __getpid: locate, fetch and store */
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "cpimage.h"
#include "cryopid.h"

#define	CMP_SIGNATURE_LENGTH	5

static int  libc_fd;
static Elf32_Ehdr   libc_ehdr;
static Elf32_Shdr   libc_sstr_table;
static Elf32_Off    dynsym_off,	dynstr_off;
static Elf32_Word   dynsym_size, dynstr_size;
static char *strtab, *dynsym, *dynstr;

/* fetch ELF section name string table header */
static int fetch_str_hdr(void)
{
    Elf32_Off	str_hdr_off = 0;

    str_hdr_off = libc_ehdr.e_shoff + (libc_ehdr.e_shstrndx * libc_ehdr.e_shentsize);
     /* seek to section name string table header */
    if (lseek(libc_fd, str_hdr_off, SEEK_SET) == -1) {
	info("[E] failed to seek to section name string table header");
	return EXIT_FAILURE;
    }
    /* fetch it */
    if (read(libc_fd, &libc_sstr_table, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr)) {
	info("[W] failed to read the %u bytes of section name string table header\n", sizeof(Elf32_Shdr));
	return EXIT_FAILURE;
    }
    assert(libc_sstr_table.sh_type == SHT_STRTAB);
    //info("[i] string table offset from file start is: %u\n", libc_sstr_table.sh_offset);
    return EXIT_SUCCESS;
}

/* fetch size bytes from ELF (fd) start + offset */
static int fetch_info(char **buffer, Elf32_Off offset, Elf32_Word size, const char *error, const char *warn)
{
    *buffer = (char*) xmalloc(size);
    /* seek to offset from the start of ELF file */
    if (lseek(libc_fd, offset, SEEK_SET) == -1) {
	info("[E] failed to seek to %s", error);
	return EXIT_FAILURE;
    }
    if (read(libc_fd, *buffer, size) != size) {
	info("[W] failed to read the %u bytes of %s\n", size, warn);
	return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/* find a specific function symbol inside the dynamic linking symbol table */
static int find_func_symbol(Elf32_Sym *symbol, unsigned char type, const char *name)
{
    int i;

    for (i = 0; i < (dynsym_size / sizeof(Elf32_Sym)); i++) {
	memcpy(symbol, dynsym + (i * sizeof(Elf32_Sym)), sizeof(Elf32_Sym));
	if ((ELF32_ST_TYPE(symbol->st_info) == STT_FUNC)
		&& strstr(dynstr + symbol->st_name, name)) {
	    info("[+] %s symbol found as #%d element at address 0x%x\n", name, i, symbol->st_value);
	    return EXIT_SUCCESS;
	}
    }
    return EXIT_FAILURE;
}

static int fetch_getpid_signature(char **buffer)
{
    Elf32_Sym	libc_sym;
    unsigned char code[CMP_SIGNATURE_LENGTH];
    /* first bytes of the signature searched: mov $0x14, %eax */
    unsigned char const_signature[CMP_SIGNATURE_LENGTH] = {0xb8, 0x14, 0x00, 0x00, 0x00};

    /* looking for __getpid symbol */
    if (find_func_symbol(&libc_sym, STT_FUNC, "__getpid") == EXIT_FAILURE) {
	info("[E] failed to find __getpid symbol\n");
	return EXIT_FAILURE;
    }
    
    /* now libc_sym keeps all __getpid symbol information */
    if (lseek(libc_fd, libc_sym.st_value, SEEK_SET) == -1) { /* seek to .dynsym section */
	info("[E] failed to seek to __getpid location at 0x%x", libc_sym.st_value);
	return EXIT_FAILURE;
    }

    /*	looking for a good signature. we are looking for machine code 
	of mov $0x14,%eax. it is SYS_GETPID first sign */
    while (1) {
	if (read(libc_fd, &code[0], CMP_SIGNATURE_LENGTH) < CMP_SIGNATURE_LENGTH) {
	    info("[E] failed to read from __getpid");
	    return EXIT_FAILURE;
	}
	/* compare the code fetched against the const signature */
	if (memcmp(code, const_signature, CMP_SIGNATURE_LENGTH) == 0)
	    break;
	/* seek back to get ready for fetching other CMP_SIGNATURE_LENGTH bytes
	   'cause the read() advances the file offset */
	if (lseek(libc_fd, sizeof(unsigned char) - CMP_SIGNATURE_LENGTH, SEEK_CUR) == -1) {
	    info("[E] failed to seek during fetch __getpid signature loop");
	    return EXIT_FAILURE;
    }
    }

    /* seek to 0xb8 ready to fetch the complete __getpid signature */
    if (lseek(libc_fd, -CMP_SIGNATURE_LENGTH, SEEK_CUR) == -1) {
	info("[E] failed to seek backward to the signature's start");
	return EXIT_FAILURE;
    }
    *buffer = (char*) xmalloc(SIGNATURE_LENGTH);
    /* fetch the signature from libc */
    memset(*buffer, 0, SIGNATURE_LENGTH);
    if (read(libc_fd, *buffer, SIGNATURE_LENGTH) == -1) {
	info("[E] unable to fetch the signature");
	return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}

int libc_hack_fetch(const char *name, char **signature)
{
    Elf32_Shdr	libc_shdr;
    int	i;

    libc_fd = open(name, O_RDONLY);
    if (libc_fd == -1) {
	info("[E] failed to open %s\n", name);
	return EXIT_FAILURE;
    }
    
    if (read(libc_fd, &libc_ehdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
	info("[W] failed to read the %u bytes of ELF header\n", sizeof(Elf32_Ehdr));
	return EXIT_FAILURE;
    }

    assert(libc_ehdr.e_shoff != 0); /* check section header table’s file offset */
    assert(libc_ehdr.e_shentsize == sizeof(Elf32_Shdr)); /* check section header entry size */
    assert(libc_ehdr.e_shstrndx != SHN_UNDEF); /* must exist a section name string table */

    //info("[i] section header table's offeset is: %d\n", libc_ehdr.e_shoff);
    /* fetch section name string table header */
    if (fetch_str_hdr() != EXIT_SUCCESS)
	return EXIT_FAILURE;
    
    /* fetch string table */
    if (fetch_info(&strtab, libc_sstr_table.sh_offset, libc_sstr_table.sh_size,
	"section name string table", "string table") != EXIT_SUCCESS)
	return EXIT_FAILURE;
    
    /* search .dynsym and .dynstr sections 
	1- it holds the dynamic linking symbol table
	2- it holds strings needed for dynamic linking 
    */
    if (lseek(libc_fd, libc_ehdr.e_shoff, SEEK_SET) == -1) { /* seek to section header table */
	info("[E] failed to seek at %d bytes to section header table", libc_ehdr.e_shoff);
	return EXIT_FAILURE;
    }

    for (i = 0; i < libc_ehdr.e_shnum; i++) {
	if (read(libc_fd, &libc_shdr, sizeof(Elf32_Shdr)) != sizeof(Elf32_Shdr)) {
	    info("[W] failed to read the %u bytes of a section header\n", sizeof(Elf32_Shdr));
	    return EXIT_FAILURE;
	}
	/* libc .dynsym section */
	if (libc_shdr.sh_type == SHT_DYNSYM) { 
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
    if (fetch_info(&dynsym, dynsym_off, dynsym_size,
	    ".dynsym section", ".dynsym section") != EXIT_SUCCESS)
	return EXIT_FAILURE;

    if (fetch_info(&dynstr, dynstr_off, dynstr_size,
	    ".dynstr section", ".dynstr section") != EXIT_SUCCESS)
	return EXIT_FAILURE;
    
    //info("[i] dynamic symbol elements are: %d\n", dynsym_size / sizeof(Elf32_Sym));

    if (fetch_getpid_signature(signature) != EXIT_SUCCESS)
	return EXIT_FAILURE;
    
    info("[+] __getpid signature fetched\n");
    /* free all the memory space allacated */
    free(strtab);
    free(dynsym);
    free(dynstr);
    /* close libc file */
    close(libc_fd);

    return EXIT_SUCCESS;
}

void write_chunk_getpid(void *fptr, struct cp_getpid *data)
{
    write_bit(fptr, data->code, SIGNATURE_LENGTH);
}
