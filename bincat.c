/*
	pcfxtools -- PC-FX development and reverse engineering tools
	Binary Concatenator (with LBA header creation)

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

void usage(char *app)
{
	fprintf(stderr, "Usage:\n"
			"	%s out.bin out.h binary1 [binary2 [...]]\n",
			app);
}

void cleanup_name(char *fname)
{
	int i;
	int len = strlen(fname);
	for(i = 0; i < len; i++) {
		if(!isalnum(fname[i]))
		{
			fname[i] = '_';
		}
		fname[i] = toupper(fname[i]);
	}
}

u32 catbin(char *fname, FILE *outfp, u32 *curoff)
{
	u32 lba = *curoff >> 11;
	FILE *fp = fopen(fname, "rb");
	if(fp == NULL) {
		perror("Can't open file for reading");
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	int size = ftell(fp);
	u8* data = malloc(size);
	if(data == NULL) {
		perror("Can't allocate buffer for binary data");
		return -1;
	}
	fseek(fp, 0, SEEK_SET);
	if(fread(data, size, 1, fp) != 1) {
		perror("Can't read binary file");
		return -1;
	}
	fclose(fp);
	if(fwrite(data, size, 1, outfp) != 1) {
		perror("Can't write binary");
		return -1;
	}
	free(data);
	if(size & 0x7FF)
	{
		int i;
		for(i = 0; i < (0x800 - (size & 0x7FF)); i++)
		{
			fputc(0, outfp);
		}
	}
	*curoff += (size + 0x7FF) & ~0x7FF;
	return lba;
}

int main(int argc, char *argv[])
{
	printf("Bincat (C)2011 trap15\n");
	if(argc < 4) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	FILE* fp = fopen(argv[1], "wb");
	if(fp == NULL) {
		perror("Can't open output binary for writing");
		return EXIT_FAILURE;
	}
	FILE* hfp = fopen(argv[2], "wb");
	if(hfp == NULL) {
		perror("Can't open output header for writing");
		return EXIT_FAILURE;
	}
	fprintf(hfp, "#ifndef _BINCAT_OUTPUT_H_\n#define _BINCAT_OUTPUT_H_\n\ntypedef enum {\n");
	int count = argc - 3;
	u32 curoff = 0;
	u32 *lbas = malloc(sizeof(u32) * count);
	int i;
	for(i = 0; i < count; i++) {
		lbas[i] = catbin(argv[i + 3], fp, &curoff) + 2;
		cleanup_name(argv[i + 3]);
		fprintf(hfp, "	BINARY_LBA_%s = %d,\n", argv[i + 3], lbas[i]);
	}
	fprintf(hfp, "} bincat_lbas;\n#endif\n\n");
	fclose(hfp);
	fclose(fp);
	free(lbas);
	return EXIT_SUCCESS;
}

