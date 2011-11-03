/*
	pcfxtools -- PC-FX development and reverse engineering tools
	HuOBJ object file converter/extractor

Copyright (C) 2011		Alex Marshall <trap15@raidenii.net>

# This code is licensed to you under the terms of the MIT license;
# see file LICENSE or http://www.opensource.org/licenses/mit-license.php
*/

/* TODO: Change stupid segment extraction into complete working ELF conversion
 *       code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#if 0
#include <libelf.h>
#include <fcntl.h>
#endif

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef struct {
	u8	magic[0xC];
	u32	section_cnt;
	u32	exportdata_cnt;
	u32	exportdata_offset;
	u32	exportdata_datalen;
	u32	exportdata_funclen;
	u32	export_cnt;
	u32	export_offset;
	u32	export_len;
	u32	unk8;
	u32	unk_cnt;
	u32	unk_offset;
	u32	unk_unklen;
	u32	unk_namelen;
} __attribute__((packed)) HuOBJHeader;

typedef struct {
	char	name[0x10];
	u32	dataoffset;
	u32	size;
	u32	relocoffset; // ?
	u32	relocsize; // ?
	u32	unk5;
	u32	unk6;
	u32	unk7;
	u32	unk8;
} __attribute__((packed)) HuOBJSection;

HuOBJHeader read_header(u8* data)
{
	HuOBJHeader hdr;
	memcpy(&hdr, data, sizeof(HuOBJHeader));
	hdr.section_cnt = ntohl(hdr.section_cnt);
	hdr.exportdata_cnt = ntohl(hdr.exportdata_cnt);
	hdr.exportdata_offset = ntohl(hdr.exportdata_offset);
	hdr.exportdata_datalen = ntohl(hdr.exportdata_datalen);
	hdr.exportdata_funclen = ntohl(hdr.exportdata_funclen);
	hdr.export_cnt = ntohl(hdr.export_cnt);
	hdr.export_offset = ntohl(hdr.export_offset);
	hdr.export_len = ntohl(hdr.export_len);
	hdr.unk_cnt = ntohl(hdr.unk_cnt);
	hdr.unk_offset = ntohl(hdr.unk_offset);
	hdr.unk_unklen = ntohl(hdr.unk_unklen);
	hdr.unk_namelen = ntohl(hdr.unk_namelen);
	return hdr;
}

HuOBJSection* read_sections(u8* data, int count)
{
	int i;
	HuOBJSection* sects = malloc(count * sizeof(HuOBJSection));
	if(sects == NULL)
		return NULL;
	for(i = 0; i < count; i++) {
		memcpy(sects + i, data + 0x40 + (i * 0x30), sizeof(HuOBJSection));
		sects[i].dataoffset = ntohl(sects[i].dataoffset);
		sects[i].size = ntohl(sects[i].size);
		sects[i].relocoffset = ntohl(sects[i].relocoffset);
		sects[i].relocsize = ntohl(sects[i].relocsize);
	}
	return sects;
}

#if 0
char top_strtab[0x10] = {
	'\0',
	'.', 's', 'h', 's', 't', 'r', 't', 'a', 'b', '\0',
	'.', 'h', 'a', 's', 'h', '\0'
};

/* TODO: This */
u32 hash_table[] = {
	0xdeadbeef,
	0xdeadbabe,
	0xdeadc0de,
};

void create_elf(u8* data, HuOBJHeader hdr, HuOBJSection* sects, char* fname)
{
	Elf* e;
	Elf_Scn* scn;
	Elf_Data* dat;
	Elf32_Ehdr* ehdr;
	Elf32_Phdr* phdr;
	Elf32_Shdr* shdr;
	char* strtable;
	int strtabsize = 0x10 + (hdr.section_cnt * 0x10);
	strtable = malloc(strtabsize);
	memcpy(strtable, top_strtab, 0x10);
	int i;
	for(i = 0; i < hdr.section_cnt; i++) {
		memcpy(strtable + (i * 0x10), sects[i].name, 0x10);
	}
	int fd;
	if(elf_version(EV_CURRENT) == EV_NONE) {
		perror("Unable to load libelf");
		return;
	}
	fd = open(fname, O_RDWR, 0);
	e = elf_begin(fd, ELF_C_WRITE, NULL);
	ehdr = elf32_newehdr(e);
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_machine = 0x9081;
	ehdr->e_type = ET_REL;
	
	phdr = elf32_newphdr(e, 1);
	
	scn = elf_newscn(e);
	
	dat = elf_newdata(scn);

	dat->d_align = 4;
	dat->d_off = 0;
	dat->d_buf = hash_table;
	dat->d_type = ELF_T_WORD;
	dat->d_size = sizeof(hash_table);
	dat->d_version = EV_CURRENT;

	shdr = elf32_getshdr(scn);
	shdr->sh_name = 11;
	shdr->sh_type = SHT_HASH;
	shdr->sh_flags = SHF_ALLOC;
	shdr->sh_entsize = 0;
	
	scn = elf_newscn(e);
	
	dat = elf_newdata(scn);
	
	dat->d_align = 1;
	dat->d_buf = strtable;
	dat->d_off = 0;
	dat->d_size = strtabsize;
	dat->d_type = ELF_T_BYTE;
	dat->d_version = EV_CURRENT;
	
	shdr = elf32_getshdr(scn);
	shdr->sh_name = 1;
	shdr->sh_type = SHT_STRTAB;
	shdr->sh_flags = SHF_STRINGS | SHF_ALLOC;
	shdr->sh_entsize = 0;
	
	elf_setshstrndx(e, elf_ndxscn(scn));
	
	elf_update(e, ELF_C_NULL);
	phdr->p_type = PT_PHDR;
	phdr->p_offset = ehdr->e_phoff;
	phdr->p_filesz = elf32_fsize(ELF_T_PHDR, 1, EV_CURRENT);
	
	elf_flagphdr(e, ELF_C_SET, ELF_F_DIRTY);
	
	elf_update(e, ELF_C_WRITE);
	
	elf_end(e);
	close(fd);
}
#endif

void dump_binaries(u8* data, HuOBJHeader hdr, HuOBJSection* sects, char* dir)
{
	FILE* fp;
	int i;
	for(i = 0; i < hdr.section_cnt; i++) {
		char fname[256];
		sprintf(fname, "%s/%s.bin", dir, sects[i].name);
		fp = fopen(fname, "wb");
		fwrite(data + sects[i].dataoffset, sects[i].size, 1, fp);
		fclose(fp);
	}
}

void usage(char *app)
{
	fprintf(stderr, "Usage:\n"
			"	%s fooobj.o outfolder\n",
			app);
}

int main(int argc, char *argv[])
{
	HuOBJHeader hdr;
	HuOBJSection* sects;
	printf("HuOBJ object converter/extractor (C)2011 trap15\n");
	if(argc < 3) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	FILE* fp = fopen(argv[1], "rb");
	if(fp == NULL) {
		perror("Can't open object for reading");
		return EXIT_FAILURE;
	}
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	u8* data = malloc(size);
	if(data == NULL) {
		perror("Can't allocate buffer for object data");
		return EXIT_FAILURE;
	}
	fseek(fp, 0, SEEK_SET);
	if(fread(data, size, 1, fp) != 1) {
		perror("Can't read object file");
		return EXIT_FAILURE;
	}
	fclose(fp);
	printf("Converting... ");
	fflush(stdout);
	hdr = read_header(data);
	sects = read_sections(data, hdr.section_cnt);
	if(sects == NULL) {
		perror("Can't decode sections");
		return EXIT_FAILURE;
	}
	/* TODO: Convert to ELF */
	//create_elf(data, hdr, sects, argv[2]);
	dump_binaries(data, hdr, sects, argv[2]);
	free(sects);
	free(data);
	printf("Done!\n");
	return EXIT_SUCCESS;
}

