/* $Id: wavfile.h,v 1.1 2011/06/01 02:38:45 ve3wwg Exp $
 * Copyright:	wavfile.h (c) Erik de Castro Lopo  erikd@zip.com.au
 *
 * This  program is free software; you can redistribute it and/or modify it
 * under the  terms  of  the GNU General Public License as published by the
 * Free Software Foundation.
 *
 * This  program  is  distributed  in  the hope that it will be useful, but
 * WITHOUT   ANY   WARRANTY;   without   even  the   implied   warranty  of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details (licensed by file COPYING or GPLv*).
 */
#ifndef _wavfile_h
#define _wavfile_h

#include <stdint.h>
#include <stdio.h>

#if 0
#define WW_BADOUTPUTFILE	1
#define WW_BADWRITEHEADER	2

#define WR_BADALLOC		3
#define WR_BADSEEK		4
#define WR_BADRIFF		5
#define WR_BADWAVE		6
#define WR_BADFORMAT		7
#define WR_BADFORMATSIZE	8

#define WR_NOTPCMFORMAT		9
#define WR_NODATACHUNK		10
#define WR_BADFORMATDATA	11
#endif

enum {
	ERR_NONE          = 0,
	WW_BADOUTPUTFILE  = 1,
	WW_BADWRITEHEADER = 2,
	WR_BADMALLOC      = 3,
	WR_BADSEEK		  = 4,
	WR_BADRIFF		  = 5,
	WR_BADWAVE		  = 6,
	WR_BADFORMAT	  =	7,
	WR_BADFORMATSIZE  =	8,
	WR_NOTPCMFORMAT	  =	9,
	WR_NODATACHUNK	  =	10,
	WR_BADFORMATDATA  =	11,
	WR_BADFILELENGTH  = 12
};

#define	BUFFERSIZE   		1024
#define	PCM_WAVE_FORMAT   	1

#define	TRUE			1
#define	FALSE			0

typedef  struct	{
	uint32_t    fmtSize;
	uint16_t   	wFormatTag;
	uint16_t   	nChannels;
	uint32_t	nSamplesPerSec;
	uint32_t	nAvgBytesPerSec;
	uint16_t	nBlockAlign;
	uint16_t	wBitsPerSample;
} WAVEFORMAT;


typedef  struct	{
	int8_t    	riffID [4];
	uint32_t    riffSize;
	int8_t    	waveID[4];
	int8_t    	fmtID[4];
	WAVEFORMAT	*waveFormat;
	int8_t		dataID[4];
	uint32_t	nDataBytes;
	uint32_t    dataStart;
} WAVE_HEADER;

extern int32_t WaveReadHeader(FILE *readFile, WAVE_HEADER *waveHeader);

#endif /* _wavfile_h_ */

