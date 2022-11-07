#include "libelf.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

char *str_abi(char abi){
	switch(abi){
		case ELFOSABI_SYSV:
			return "UNIX System V";
		default:
			return "Unknown";
	}
	return NULL;
}

char *str_ptype(uint32_t type){
	switch(type){
		case PT_NULL:
			return "NULL";
		case PT_LOAD:
			return "LOAD";
		case PT_DYNAMIC:
			return "DYNAMIC";
		case PT_INTERP:
			return "INTERP";
		case PT_NOTE:
			return "NOTE";
		case PT_SHLIB:
			return "SHLIB";
		case PT_PHDR:
			return "PHDR";
		case PT_TLS:
			return "TLS";
		case PT_NUM:
			return "NUM";
		case PT_LOOS:
			return "LOOS";
		case PT_GNU_EH_FRAME:
			return "GNU_EH_FRAME";
		case PT_GNU_STACK:
			return "GNU_STACK";
		case PT_GNU_RELRO:
			return "GNU_RELRO";
		case PT_GNU_PROPERTY:
			return "GNU_PROPERTY";
		case PT_LOSUNW:
			return "LOSUNW";
		case PT_SUNWSTACK:
			return "SUNWSTACK";
		case PT_HIOS:
			return "HIOS";
		case PT_LOPROC:
			return "LOPROC";
		case PT_HIPROC:
			return "HIPROC";
		default:
			return "INVALID";
	}
}

void free_phdrs(program_hdr **phdrs, int32_t phnum){
	int index = 0;
	if(!phdrs || (phnum <= 0) ) return;

	for(; index < phnum; index++){
		if(phdrs[index]){
			free(phdrs[index]);
		}
	}
	free(phdrs);
	return;
}

void free_elf(ELF *elf){
	if(elf){
		if(elf->fdata) free(elf->fdata);
		
		if(elf->phdrs) free_phdrs(elf->phdrs, elf->hdr->e_phnum);
		//if(elf->shdrs)

		if(elf->hdr) free(elf->hdr);
		memset(elf, 0, sizeof(ELF));
		free(elf);
	}
	return;
}

program_hdr **parse_phdrs(elf_hdr *hdr, char *fdata, int64_t fdata_size){
	char *dp = NULL;
	int index = 0;
	program_hdr **phdrs=NULL;
	if(!hdr || !fdata || (fdata_size <= 0)){
		fprintf(stderr, "parse_phdrs(): Bad arguments\n");
		return NULL;
	}
	dp = (fdata+hdr->e_phoff);
	phdrs = (program_hdr **)malloc((sizeof(program_hdr *)*(hdr->e_phnum+1)));
	if(!phdrs){
		fprintf(stderr, "parse_phdrs(): %s\n", strerror(errno));
		return NULL;
	}
	memset(phdrs, 0, (sizeof(program_hdr *)*(hdr->e_phnum+1)));
	for(; index < hdr->e_phnum; index++){
		if(!(phdrs[index] = (program_hdr *)malloc(sizeof(program_hdr)))){
			fprintf(stderr, "parse_phdrs(): %s\n", strerror(errno));
			goto PARSE_PHDRS_ERR;
		}
		memset(phdrs[index], 0, sizeof(program_hdr));
		phdrs[index]->p_type = *(uint32_t *)(dp);
		dp += 4;
		if(hdr->e_ident[4] == ELFCLASS64){
			phdrs[index]->p_flags = *(uint32_t *)(dp);
			phdrs[index]->p_offset = *(uint64_t *)(dp+4);
			phdrs[index]->p_vaddr = *(uint64_t *)(dp+12);
			phdrs[index]->p_paddr = *(uint64_t *)(dp+20);
			phdrs[index]->p_filesz = *(uint64_t *)(dp+28);
			phdrs[index]->p_memsz = *(uint64_t *)(dp+36);
			phdrs[index]->p_align = *(uint64_t *)(dp+44);
			dp += 52;
		}else{
			phdrs[index]->p_offset = *(uint32_t *)(dp);
			phdrs[index]->p_vaddr = *(uint32_t *)(dp+4);
			phdrs[index]->p_paddr = *(uint32_t *)(dp+8);
			phdrs[index]->p_filesz = *(uint32_t *)(dp+12);
			phdrs[index]->p_memsz = *(uint32_t *)(dp+16);
			phdrs[index]->p_flags = *(uint32_t *)(dp+20);
			phdrs[index]->p_align = *(uint32_t *)(dp+24);
			dp += 28;
		}
	}
	return phdrs;
PARSE_PHDRS_ERR:
	free_phdrs(phdrs, hdr->e_phnum);
	return NULL;
}

elf_hdr *parse_ehdr(char *data, int size){
	char *dp = NULL;
	elf_hdr *ehdr = NULL;
	
	if(!data || size < sizeof(elf_hdr)) return NULL;
	ehdr = (elf_hdr *)malloc(sizeof(elf_hdr));
	if(!ehdr){
		fprintf(stderr, "parse_ehdr(): %s\n", strerror(errno));
		goto PARSE_EHDR_ERR;
	};
	memset(ehdr, 0, sizeof(elf_hdr));
	memcpy(ehdr->e_ident, data, EI_NIDENT);
	dp = (data+EI_NIDENT);
	ehdr->e_type = *(uint16_t *)(dp);
	ehdr->e_machine = *(uint16_t *)(dp+2);
	ehdr->e_version = *(uint32_t *)(dp+4);
	dp = (dp+8);
	if(ehdr->e_ident[4] == ELFCLASS64){
		ehdr->e_entry = *(uint64_t *)(dp);
		ehdr->e_phoff = *(uint64_t *)(dp+8);
		ehdr->e_shoff = *(uint64_t *)(dp+16);
		dp = (dp+24);
	}else{
		ehdr->e_entry = *(uint32_t *)(dp);
		ehdr->e_phoff = *(uint32_t *)(dp+4);
		ehdr->e_shoff = *(uint32_t *)(dp+8);
		dp = (dp+12);
	}
	ehdr->e_flags = *(uint32_t *)(dp);
	ehdr->e_ehsize = *(uint16_t *)(dp+4);
	
	ehdr->e_phentsize = *(uint16_t *)(dp+6);
	ehdr->e_phnum = *(uint16_t *)(dp+8);
	ehdr->e_shentsize = *(uint16_t *)(dp+10);
	ehdr->e_shnum = *(uint16_t *)(dp+12);
	ehdr->e_shstrndx = *(uint16_t *)(dp+14);

	return ehdr;

PARSE_EHDR_ERR:
	if(ehdr) free(ehdr);
	return NULL;
}

ELF *open_elf(char *filepath){
	FILE *fp = NULL;
	ELF *elf = NULL;
	int64_t total_ph_size = 0;
	int64_t total_sh_size = 0; 
	struct stat fp_stat;

	if(!filepath){
		fprintf(stderr, "open_elf(): File path cannot be NULL\n");
		goto OPEN_ELF_ERR;
	}
	elf = (ELF *)malloc(sizeof(ELF));
	if(!elf){
		fprintf(stderr, "malloc(): %s\n", strerror(errno));
		goto OPEN_ELF_ERR;
	}
	memset(elf, 0, sizeof(ELF));

	memset(&fp_stat, 0, sizeof(struct stat));
	if(stat(filepath, &fp_stat) < 0){
		fprintf(stderr, "stat(): %s\n", strerror(errno));
		goto OPEN_ELF_ERR;		
	}
	if(fp_stat.st_size < sizeof(elf_hdr)){
		fprintf(stderr, "open_elf(): File size too small\n");
		goto OPEN_ELF_ERR;
	}

	elf->fdata_size = fp_stat.st_size;
	elf->fdata = (char *)malloc(elf->fdata_size);
	if(!elf->fdata){
		fprintf(stderr, "malloc(): %s\n", strerror(errno));
		goto OPEN_ELF_ERR;
	}
	memset(elf->fdata, 0, elf->fdata_size);
	fp = fopen(filepath, "r");
	if(!fp){
		fprintf(stderr, "fopen(): %s\n", strerror(errno));
		goto OPEN_ELF_ERR;
	}
	if(fread(elf->fdata, 1, elf->fdata_size, fp) < elf->fdata_size){
		fprintf(stderr, "fread(): %s\n", strerror(errno));
		goto OPEN_ELF_ERR;
	}
	fclose(fp);
	fp = NULL;

	if((*(unsigned int *)elf->fdata) != 0x464c457f){
		fprintf(stderr, "open_elf(): Invalid magic number: 0x%08x\n", *(unsigned int *)elf->fdata);
		goto OPEN_ELF_ERR;
	}
	elf->hdr = parse_ehdr(elf->fdata, elf->fdata_size);
	if(!elf->hdr){
		fprintf(stderr, "open_elf(): Failed to parse ELF header\n");
		goto OPEN_ELF_ERR;
	}
	total_sh_size = elf->hdr->e_shentsize*elf->hdr->e_shnum;
	total_ph_size = elf->hdr->e_phentsize*elf->hdr->e_phnum;
	if((elf->hdr->e_phoff > elf->fdata_size) || (elf->hdr->e_shnum > elf->fdata_size)){
		fprintf(stderr, "open_elf(): Invalid offset in ELF header\n");
		goto OPEN_ELF_ERR;
	}
	if( ((elf->hdr->e_phoff+total_ph_size) > elf->fdata_size) || ((elf->hdr->e_shoff+total_sh_size) > elf->fdata_size) ){
		fprintf(stderr, "open_elf(): Invalid size in ELF header\n");
		goto OPEN_ELF_ERR;
	}
	elf->phdrs = parse_phdrs(elf->hdr, elf->fdata, elf->fdata_size);
	if(!elf->phdrs){
		fprintf(stderr, "open_elf(): Failed to parse program headers\n");
		goto OPEN_ELF_ERR;
	}
	return elf;
OPEN_ELF_ERR:
	if(fp) fclose(fp);
	if(elf) free_elf(elf);
	return NULL;
}