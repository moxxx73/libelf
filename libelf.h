#ifndef ELFLIB_H
#define ELFLIB_H

#include <elf.h>
#include <sys/types.h>

typedef struct{
    unsigned int sh_name;
    unsigned int sh_type;
    unsigned long sh_flags;
    unsigned long sh_addr;
    unsigned long sh_offset;
    unsigned long sh_size;
    unsigned int sh_link;
    unsigned int sh_info;
    unsigned long sh_addralign;
    unsigned long sh_entsize;
} section_hdr;

typedef struct{
    unsigned int p_type;
    unsigned int p_flags;
    unsigned long p_offset;
    unsigned long p_vaddr;
    unsigned long p_paddr;
    unsigned long p_filesz;
    unsigned long p_memsz;
    unsigned long p_align;
} program_hdr;

typedef struct elfh_struct{
    unsigned char e_ident[EI_NIDENT];
    unsigned short e_type;
    unsigned short e_machine;
    unsigned int e_version;
    unsigned long e_entry;
    unsigned long e_phoff;
    unsigned long e_shoff;
    unsigned int e_flags;
    unsigned short e_ehsize;
    unsigned short e_phentsize;
    unsigned short e_phnum;
    unsigned short e_shentsize;
    unsigned short e_shnum;
    unsigned short e_shstrndx;
} elf_hdr;

typedef struct{
	elf_hdr *hdr;
	program_hdr **phdrs;
	section_hdr **shdrs;
	char *fdata;
	off_t fdata_size;
    uint64_t unused;
} ELF;

char *str_abi(char abi);

char *str_ptype(uint32_t type);

char *str_shtype(uint32_t sh_type);

void free_elf(ELF *elf);

ELF *open_elf(char *filepath);

#endif