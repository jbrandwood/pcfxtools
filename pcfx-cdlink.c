/*
	pcfxtools -- a set of tools for NEC PC-FX development and reverse-engineering
	pcfx-cdlink; .cue and .bin generator.

Copyright (C) 2011		Alex Marshall "trap15" <trap15@raidenii.net>
Copyright (C) 2007		Ryphecha / Mednafen

# This code is licensed to you under the terms of the MIT license;
# see file LICENSE or http://www.opensource.org/licenses/mit-license.php
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

uint32_t le32(uint32_t i)
{
	i = ntohl(i);
	i = ((i & 0xFF000000) >> 24) |
	    ((i & 0x00FF0000) >>  8) |
	    ((i & 0x0000FF00) <<  8) |
	    ((i & 0x000000FF) << 24);
	return i;
}

uint16_t le16(uint16_t i)
{
	i = ntohs(i);
	i = ((i & 0xFF00) >> 8) |
	    ((i & 0x00FF) << 8);
	return i;
}

struct {
	char		header[0x10];
	char		unk[0x7F0];
	char		title[0x20];
	uint32_t	sect_off;
	uint32_t	sect_count;
	uint32_t	prog_off;
	uint32_t	prog_point;
	char		maker_id[4];
	char		maker_name[60];
	uint32_t	volume_no;
	uint16_t	version;
	uint16_t	country;
	char		date[8];
	char		pad[0x380];
	char		udata[0x400];
} __attribute__((packed)) BootHeader = {
	.header = "PC-FX:Hu_CD-ROM ",
	.unk = {
#include "boot.h"
	},
	.title = "",
	.sect_off = 0,
	.sect_count = 0,
	.prog_off = 0,
	.prog_point = 0,
	.maker_id = "N/A",
	.maker_name = "pcfx-cdlink",
	.volume_no = 0,
	.version = 0x0100,
	.country = 1,
	.date = "20XX0131",
	.pad = { 0, },
	.udata = { 0, },
};

int main(int argc, char *argv[])
{
	if(argc < 3) {
		printf("Usage: %s input.txt outfiles\n", argv[0]);
		return EXIT_FAILURE;
	}
	FILE* fp = fopen(argv[1], "rb");
	if(fp == NULL) {
		perror("Opening input list");
		return EXIT_FAILURE;
	}
	int keep_going = 1;
	char tmpbuf[256];
	char binname[256] = "\0";
	int i;
	while(keep_going) {
		if(fgets(tmpbuf, 255, fp) == NULL)
			break;
		if(feof(fp))
			keep_going = 0;
		if(memcmp(tmpbuf, "binary", 6) == 0) {
			snprintf(binname, (255 > (strlen(tmpbuf) - 7)) ? strlen(tmpbuf) - 7 : 255, "%s", tmpbuf + 7);
		}else if(memcmp(tmpbuf, "name", 4) == 0) {
			snprintf(BootHeader.title, 0x20, "%s", tmpbuf + 5);
			for(i = 0; i < 0x20; i++) {
				if((BootHeader.title[i] == 0x0A) || (BootHeader.title[i] == 0x0D))
					BootHeader.title[i] = 0;
			}
			BootHeader.title[0x1F] = 0;
		}else if(memcmp(tmpbuf, "makerid", 7) == 0) {
			snprintf(BootHeader.maker_id, 4, "%s", tmpbuf + 8);
			for(i = 0; i < 4; i++) {
				if((BootHeader.maker_id[i] == 0x0A) || (BootHeader.maker_id[i] == 0x0D))
					BootHeader.maker_id[i] = 0;
			}
			BootHeader.maker_id[3] = 0;
		}else if(memcmp(tmpbuf, "maker", 5) == 0) {
			snprintf(BootHeader.maker_name, 60, "%s", tmpbuf + 6);
			for(i = 0; i < 60; i++) {
				if((BootHeader.maker_name[i] == 0x0A) || (BootHeader.maker_name[i] == 0x0D))
					BootHeader.maker_name[i] = 0;
			}
			BootHeader.maker_name[59] = 0;
		}else if(memcmp(tmpbuf, "date", 4) == 0) {
			snprintf(BootHeader.date, 8, "%s", tmpbuf + 5);
		}else if(memcmp(tmpbuf, "country", 7) == 0) {
			BootHeader.country = atoi(tmpbuf + 8);
		}else if(memcmp(tmpbuf, "version", 7) == 0) {
			BootHeader.version = atoi(tmpbuf + 8);
		}
	}
	fclose(fp);

	if(binname[0] == 0) {
		perror("No binary name");
		return EXIT_FAILURE;
	}
	FILE *in_fp, *out_fp;
	struct stat stat_buf;

	if(!(in_fp = fopen(binname, "rb"))) {
		perror("Error opening input file");
		return EXIT_FAILURE;
	}

	char *obinname;
	asprintf(&obinname, "%s.bin", argv[2]);
	if(!(out_fp = fopen(obinname, "wb"))) {
		perror("Error opening output file");
		return EXIT_FAILURE;
	}

	if(fstat(fileno(in_fp), &stat_buf)) {
		perror("fstat error");
		return EXIT_FAILURE;
	}

	uint32_t sector_offset = 2;
	uint32_t sector_count = (stat_buf.st_size + 2047) / 2048;
	uint32_t prog_offset = 0x8000;
	uint32_t prog_point = 0x8000;

	printf("Code+data Size: %ld\n", stat_buf.st_size);
	int32_t sh_size = 1024 * 2048 - stat_buf.st_size - 0x8000 - 2048;
	/* 2KiB minimum for stack or heap(they grow in different directions!) */

	if(sh_size < 0) {
		perror("Program size is too large");
		return EXIT_FAILURE;
	}
	printf("Stack+heap Free Space: %d\n", sh_size);

	BootHeader.sect_off = sector_offset;
	BootHeader.sect_count = sector_count;
	BootHeader.prog_off = prog_offset;
	BootHeader.prog_point = prog_point;

	uint32_t padcnt = 0;

	BootHeader.sect_off = le32(BootHeader.sect_off);
	BootHeader.sect_count = le32(BootHeader.sect_count);
	BootHeader.prog_off = le32(BootHeader.prog_off);
	BootHeader.prog_point = le32(BootHeader.prog_point);
	BootHeader.volume_no = le32(BootHeader.volume_no);
	BootHeader.version = le16(BootHeader.version);
	BootHeader.country = le16(BootHeader.country);
	fwrite(&BootHeader, 1, sizeof(BootHeader), out_fp);
	padcnt += sizeof(BootHeader);

	int t;
	uint8_t* data;
	data = malloc(stat_buf.st_size);
	if(fread(data, stat_buf.st_size, 1, in_fp) != 1) {
		perror("Can't read input data");
		return EXIT_FAILURE;
	}
	fclose(in_fp);
	fwrite(data, stat_buf.st_size, 1, out_fp);
	padcnt += stat_buf.st_size;

	while((padcnt & 2047) || (padcnt < (2048 * 75 * 4))) {
		fputc(0, out_fp);
		padcnt++;
	}
	fclose(out_fp);

	/* Output a simple .cue file. */
	char *cuename;
	asprintf(&cuename, "%s.cue", argv[2]);
	fp = fopen(cuename, "wb");
	fprintf(fp, "FILE \"%s\" BINARY\n", obinname);
	fprintf(fp, "  TRACK 01 MODE1/2048\n");
	fprintf(fp, "    INDEX 01 00:00:00\n");
	fclose(fp);
	free(cuename);
	free(obinname);

	printf("Done.\n");
	return EXIT_SUCCESS;
}


