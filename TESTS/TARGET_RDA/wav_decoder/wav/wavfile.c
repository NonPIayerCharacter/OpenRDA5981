/* $Id: wavfile.c,v 1.2 2011/06/09 00:51:02 ve3wwg Exp $
 * Copyright: wavfile.c (c) Erik de Castro Lopo  erikd@zip.com.au
 *
 * wavfile.c - Functions for reading and writing MS-Windoze .WAV files.
 *
 * This  program is free software; you can redistribute it and/or modify it
 * under the  terms  of  the GNU General Public License as published by the
 * Free Software Foundation.
 *
 * This  program  is  distributed  in  the hope that it will be useful, but
 * WITHOUT   ANY   WARRANTY;   without   even  the   implied   warranty  of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details (licensed by file COPYING or GPLv*).
 *
 * This code was originally written to manipulate Windoze .WAV files
 * under i386 Linux (erikd@zip.com.au).
 *
 * ve3wwg@gmail.com
 */
#include  	<stdio.h>
#include    <stdlib.h>
#include    <stdint.h>

#include "wavfile.h"


/*********************************************************************
 * Find a Chunk
 *********************************************************************/
static int8_t * findchunk(int8_t *pstart, const int8_t *fourcc, uint32_t n)
{
	int8_t	*pend;
	int32_t	k, test;

	pend = pstart + n;

	while ( pstart < pend ) {
		if ( *pstart == *fourcc) { 	/* found match for first char*/
			test = TRUE;
			for ( k = 1; fourcc[k] != 0; k++ )
				test = (test ? ( pstart [k] == fourcc [k] ) : FALSE);
			if ( test )
				return  pstart;
		} /* if*/
		pstart++;
	} /* while lpstart*/

	return  NULL;
} /* findchuck*/


int32_t WaveReadHeader(FILE *readFile, WAVE_HEADER *waveHeader)
{
	int8_t    *buffer;
	int8_t    *ptr;
	int32_t   res = 0;

	buffer = (int8_t *) malloc(BUFFERSIZE * sizeof(char));
	if (!buffer) {
		printf("Error malloc buffer\n");
		return WR_BADMALLOC;
	}

	if (fseek(readFile, 0, SEEK_SET) != 0) {
		printf("BAD_SEEK\n");
		return  WR_BADSEEK;
	}

	res = fread(buffer, sizeof(int8_t), BUFFERSIZE, readFile);

	if (res < BUFFERSIZE) {
		printf("File length too short\n");
		return WR_BADFILELENGTH;
	}

	if (findchunk(buffer, "RIFF", BUFFERSIZE) != buffer) {
		printf("Bad format: Cannot find RIFF file marker\n");
		return  WR_BADRIFF;
	}


	if (!findchunk(buffer, "WAVE", BUFFERSIZE)) {
		printf("Bad format: Cannot find WAVE file marker\n");
		return  WR_BADWAVE;
	}

	ptr = findchunk(buffer, "fmt ", BUFFERSIZE);

	if (!ptr) {
		printf("Bad format: Cannot find 'fmt' file marker\n");
		return  WR_BADFORMAT;
	}

	ptr += 4;	/* Move past "fmt ".*/
	memcpy(waveHeader->waveFormat, ptr, sizeof(WAVEFORMAT));

	if (waveHeader->waveFormat->fmtSize < (sizeof(WAVEFORMAT) - sizeof(uint32_t))) {
		printf("Bad format: Bad fmt size\n");
		return  WR_BADFORMATSIZE;
	}

	if (waveHeader->waveFormat->wFormatTag != PCM_WAVE_FORMAT ) {
		printf("Only supports PCM wave format\n");
		return  WR_NOTPCMFORMAT;
	}


	ptr = findchunk(buffer, "data", BUFFERSIZE);
	if (!ptr) {
		printf("Bad format: unable to find 'data' file marker\n");
		return  WR_NODATACHUNK;
	}


	ptr += 4;	/* Move past "data".*/
	waveHeader->nDataBytes = *((uint32_t *)ptr);
	waveHeader->dataStart  = (uint32_t) ((ptr + 4) - buffer);

	if (waveHeader->waveFormat->nSamplesPerSec != waveHeader->waveFormat->nAvgBytesPerSec / waveHeader->waveFormat->nBlockAlign) {
		printf("Bad file format\n");			/* wwg: report error */
		return  WR_BADFORMATDATA;
	}

	if (waveHeader->waveFormat->nSamplesPerSec != waveHeader->waveFormat->nAvgBytesPerSec / waveHeader->waveFormat->nChannels / ((waveHeader->waveFormat->wBitsPerSample == 16) ? 2 : 1)) {
		printf("Bad file format\n");			/* wwg: report error */
		return  WR_BADFORMATDATA;
	}

	free(buffer);

	return  ERR_NONE;

}


