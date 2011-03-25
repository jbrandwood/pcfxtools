/*
	pcfxtools -- PC-FX development and reverse engineering tools
	HuLIB library extractor

Copyright (C) 2011		Alex Marshall <trap15@raidenii.net>

# This code is licensed to you under the terms of the MIT license;
# see file LICENSE or http://www.opensource.org/licenses/mit-license.php
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;

/* Bare minimum to extract libraries. Maybe figure the rest out too? */
typedef struct {
	char	fname[0x20];
	u32	unk1;
	u32	unk2;
	u32	offset;
	u32	size;
	u32	unk3;
	u32	unk4;
	u32	unk5;
	u32	unk6;
} __attribute__((packed)) HuLIBFile;

HuLIBFile* get_files(u8* data, u32 cnt)
{
	HuLIBFile* fils = malloc(cnt * sizeof(HuLIBFile));
	if(fils == NULL)
		return NULL;
	int i;
	for(i = 0; i < cnt; i++) {
		memcpy(fils + i, data + 0x20 + (0x40 * i), sizeof(HuLIBFile));
		fils[i].offset = ntohl(fils[i].offset);
		fils[i].size = ntohl(fils[i].size);
	}
	return fils;
}

void usage(char *app)
{
	fprintf(stderr, "Usage:\n"
			"	%s libfoo.a outfolder\n",
			app);
}

int main(int argc, char *argv[])
{
	HuLIBFile* fils;
	printf("HuLIB library extractor (C)2011 trap15\n");
	if(argc < 3) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	FILE* fp = fopen(argv[1], "rb");
	if(fp == NULL) {
		perror("Can't open library for reading");
		return EXIT_FAILURE;
	}
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	u8* data = malloc(size);
	if(data == NULL) {
		perror("Can't allocate buffer for library data");
		return EXIT_FAILURE;
	}
	fseek(fp, 0, SEEK_SET);
	if(fread(data, size, 1, fp) != 1) {
		perror("Can't read library file");
		return EXIT_FAILURE;
	}
	fclose(fp);
	u32 count = ntohl(*((u32*)(data + 0xC)));
	fils = get_files(data, count);
	if(fils == NULL) {
		perror("Can't decode library");
		return EXIT_FAILURE;
	}
	int i;
	for(i = 0; i < count; i++) {
		char fname[256];
		snprintf(fname, 255, "%s/%s", argv[2], fils[i].fname);
		printf("Extracting %s... ", fils[i].fname);
		fflush(stdout);
		FILE* nrfp = fopen(fname, "wb");
		fwrite(data + fils[i].offset, fils[i].size, 1, nrfp);
		fclose(nrfp);
		printf("Done!\n");
	}
	free(data);
	free(fils);
	return EXIT_SUCCESS;
}

