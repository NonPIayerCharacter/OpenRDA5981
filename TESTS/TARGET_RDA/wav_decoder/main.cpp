#include "mbed.h"
#include "rtos.h"
#include "rda_i2s_api.h"

#define I2S_CLK_DIV_REG					0x40000048
#define MISC_CFG_REG 					0x4001303C
#define READ_REG32(REG)			 *((volatile unsigned int*)(REG))
#define WRITE_REG32(REG, VAL)    ((*(volatile unsigned int*)(REG)) = (unsigned int)(VAL))

extern "C"
{
#include "wavfile.h"
};

#define OUTBUF_SIZE  	2304
#define WAV_USE_MALLOC	1

#include "SDMMCFileSystem.h"

/* Ping-Pong DMA specific */
volatile uint32_t nFrames;

int32_t bytesLeft;
volatile int16_t outOfData;

#if WAV_USE_MALLOC
uint8_t *outBuf;
#else
uint8_t outBuf[OUTBUF_SIZE * 2];
#endif

volatile bool eofReached = false;

/* File system specific */
FILE *wavFile;

i2s_t obj = {0};

Timer tmr;

DigitalOut led1(LED1);

int32_t FillOutputBuffer(FILE *readFile, uint8_t* outBuf)
{
	int32_t nRead = 0;

	nRead = fread(outBuf, sizeof(uint8_t), OUTBUF_SIZE, readFile);

	if (0 == nRead) {
		eofReached = true;
	}

	return nRead;
}

int main()
{
#if 1
	i2s_cfg_t cfg;
	int32_t res = 0;

	cfg.mode              = I2S_MD_MASTER_TX;
	cfg.tx.fs             = I2S_64FS;
	cfg.tx.ws_polarity    = I2S_WS_NEG;//L
	//cfg.tx.ws_polarity    = I2S_WS_POS;//R
	cfg.tx.std_mode       = I2S_STD_M;
	//cfg.tx.justified_mode = I2S_RIGHT_JM;
	cfg.tx.justified_mode = I2S_LEFT_JM;
	cfg.tx.data_len       = I2S_DL_16b;
	cfg.tx.msb_lsb        = I2S_MSB;
	cfg.tx.wrfifo_cntleft = I2S_WF_CNTLFT_8W;

	led1 = 0;

	rda_i2s_init(&obj, I2S_TX_BCLK, I2S_TX_WS, I2S_TX_SD, NC, NC, NC, NC);
	rda_i2s_format(&obj, &cfg);

	//WRITE_REG32(I2S_CLK_DIV_REG, 0x0E07160E);//32FS 44.1K
	WRITE_REG32(I2S_CLK_DIV_REG, 0x020E2C1E);//64FS 44.1K
#endif


	/* SDMMC Pins: clk, cmd, d0, d1, d2, d3 */
	SDMMCFileSystem sdc(PB_9, PB_0, PB_6, PB_7, PC_0, PC_1, "sdc");

	while (true) {
		wavFile = fopen("/sdc/test_wav.wav", "rb");
		if (!wavFile) {
			printf("Error open wav file\n");
			break;
		}

#if WAV_USE_MALLOC
		outBuf = (uint8_t *) malloc(2 * OUTBUF_SIZE * sizeof(uint8_t));
		if (!outBuf) {
			printf("Error malloc outBuf\n");
			break;
		}
		memset(outBuf, 0, (2 * OUTBUF_SIZE * sizeof(uint8_t)));
#endif

		WAVE_HEADER *waveHeader = (WAVE_HEADER *) malloc(sizeof(WAVE_HEADER));
		if (!waveHeader) {
			printf("Error malloc waveHeader\n");
			break;
		}
		memset(waveHeader, 0, sizeof(WAVE_HEADER));

		waveHeader->waveFormat = (WAVEFORMAT *) malloc(sizeof(WAVEFORMAT));
		if (!waveHeader->waveFormat) {
			printf("Error malloc waveFormat\n");
			break;
		} else
		memset(waveHeader->waveFormat, 0, sizeof(WAVEFORMAT));

		memcpy(waveHeader->riffID, "RIFF", 4);
		memcpy(waveHeader->waveID, "WAVE", 4);
		memcpy(waveHeader->fmtID, "fmt ", 4);
		memcpy(waveHeader->dataID, "data", 4);

		if (WaveReadHeader(wavFile, waveHeader) != ERR_NONE) {
			printf("Error Init\n");
			break;
		}

		printf("WavInfo:\n");
		printf("nChannel:%d\n", waveHeader->waveFormat->nChannels);
		printf("sampleRate:%d\n", waveHeader->waveFormat->nSamplesPerSec);
		printf("bitRate:%d\n", (waveHeader->waveFormat->nAvgBytesPerSec * waveHeader->waveFormat->wBitsPerSample / waveHeader->waveFormat->nChannels));
		printf("bitsPerSample:%d\n", waveHeader->waveFormat->wBitsPerSample);
		printf("\n");

		switch (waveHeader->waveFormat->nSamplesPerSec) {
		case 44100:
			WRITE_REG32(I2S_CLK_DIV_REG, 0x020E2C1E);//64FS 44.1K
			break;
		case 48000:
			WRITE_REG32(I2S_CLK_DIV_REG, 0x020D0555);//64FS 48K
			break;
		case 32000:
			WRITE_REG32(I2S_CLK_DIV_REG, 0x021387FF);//64FS 32K
			break;
		case 22050:
			WRITE_REG32(I2S_CLK_DIV_REG, 0x021C583C);//64FS 22.05K
			break;
		case 24000:
			WRITE_REG32(I2S_CLK_DIV_REG, 0x021A0AAA);//64FS 24K
			break;
		case 16000:
			WRITE_REG32(I2S_CLK_DIV_REG, 0x02271000);//64FS 16K
			break;
		case 11025:
			WRITE_REG32(I2S_CLK_DIV_REG, 0x0238B078);//64FS 11.025K
			break;
		case 12000:
			WRITE_REG32(I2S_CLK_DIV_REG, 0x02341555);//64FS 12K
			break;
		case 8000:
			WRITE_REG32(I2S_CLK_DIV_REG, 0x024E1FFF);//64FS 8K
			break;
		default:
			WRITE_REG32(I2S_CLK_DIV_REG, 0x020E2C1E);//64FS 44.1K
			break;
		}


		fseek(wavFile, waveHeader->dataStart, SEEK_SET);

		/* fill two buffers first */
		fread(outBuf, sizeof(uint8_t), (2 * OUTBUF_SIZE * sizeof(uint8_t)), wavFile);
		nFrames = 2;


		/* Start to transfer the first ping buffer */
		rda_i2s_int_send(&obj, (uint32_t *)outBuf, (OUTBUF_SIZE / sizeof(uint32_t)));

		do {
			/* Wait buffer ready to refill */
			while(I2S_ST_BUSY == obj.sw_tx.state);
			nFrames++;

			if (nFrames & 0x01) {
				/* Send pong buffer, refill ping buffer */
				rda_i2s_int_send(&obj, ((uint32_t *)(outBuf + OUTBUF_SIZE)), (OUTBUF_SIZE / sizeof(uint32_t)));
				//led1 = 1;

				res = FillOutputBuffer(wavFile, outBuf);

				//led1 = 0;
			} else {
				/* Send ping buffer, refill pong buffer */
				rda_i2s_int_send(&obj, (uint32_t *)outBuf, (OUTBUF_SIZE / sizeof(uint32_t)));
				//led1 = 1;

				res = FillOutputBuffer(wavFile, (outBuf + OUTBUF_SIZE));

				//led1 = 0;
			}
		} while (false == eofReached);

		eofReached = false;

		free(waveHeader->waveFormat);
		free(waveHeader);

		if (outBuf) {
			free(outBuf);
		}

		fclose(wavFile);

		printf("Decoder Over\n");
	}
}

