/** file rda58xx.h
 * Headers for interfacing with the codec chip.
 */

#ifndef RDA58XX_H
#define RDA58XX_H

#include "mbed.h"

typedef enum {
    MCI_TYPE_NONE=-1,
    MCI_TYPE_GSM_FR,              /* 0  */
    MCI_TYPE_GSM_HR,              /* 1  */
    MCI_TYPE_GSM_EFR,             /* 2  */
    MCI_TYPE_AMR,                 /* 3  */
    MCI_TYPE_AMR_WB,              /* 4  */
    MCI_TYPE_DAF,                 /* 5  */
    MCI_TYPE_AAC,                 /* 6  */
    MCI_TYPE_PCM_8K,              /* 7  */
    MCI_TYPE_PCM_16K,             /* 8  */
    MCI_TYPE_G711_ALAW,           /* 9  */
    MCI_TYPE_G711_ULAW,           /* 10 */
    MCI_TYPE_DVI_ADPCM,           /* 11 */
    MCI_TYPE_VR,                  /* 12 */
    MCI_TYPE_WAV,                 /* 13 */
    MCI_TYPE_WAV_ALAW,            /* 14 */
    MCI_TYPE_WAV_ULAW,            /* 15 */
    MCI_TYPE_WAV_DVI_ADPCM,       /* 16 */
    MCI_TYPE_SMF,                 /* 17 */
    MCI_TYPE_IMELODY,             /* 18 */
    MCI_TYPE_SMF_SND,             /* 19 */
    MCI_TYPE_MMF,                 /* 20 */
    MCI_TYPE_AU,                  /* 21 */
    MCI_TYPE_AIFF,                /* 22 */
    MCI_TYPE_M4A,                 /* 23 */
    MCI_TYPE_3GP,                 /* 24 */
    MCI_TYPE_MP4,                 /* 25 */
    MCI_TYPE_JPG,                 /* 26 */
    MCI_TYPE_GIF,                 /* 27 */
    MCI_TYPE_MJPG,                /* 28 */
    MCI_TYPE_WMA,                 /* 29 */
    MCI_TYPE_MIDI,                /* 30 */
    MCI_TYPE_RM,                  /* 31 */
    //MCI_TYPE_AVSTRM,              /* 32 */
    MCI_TYPE_SBC,                 /* 32 */
    MCI_TYPE_SCO,                 /* 33 */
    MCI_TYPE_TONE,                /* 34 */
    MCI_TYPE_USB,                 /* 35 */
    MCI_TYPE_LINEIN,              /* 36 */
    MCI_NO_OF_TYPE
} mci_type_enum;

typedef enum {
	UNKNOWN = -1,
	STOP = 0,
	PLAY,
	PAUSE,
	RECORDING,
	STOP_RECORDING
} rda58xx_status;

typedef enum {
	EMPTY = 0,
    FULL
} rda58xx_buffer_status;

typedef enum {
	WITHOUT_ENDING = 0,
    WITH_ENDING
} rda58xx_stop_type;

typedef enum {
	NACK = 0,
	ACK,
	INVALID_COMMAND,
	NO_RESPONSE,
	CME_ERROR
} rda58xx_at_status;

typedef enum {
	FT_DISABLE = 0,
	FT_ENABLE
} rda58xx_ft_test;

typedef struct {
	unsigned char *buffer;
	unsigned char bufferSize;
	rda58xx_status status;
} rda58xx_parameter;

class rda58xx
{
public:
    rda58xx(PinName TX, PinName RX, PinName HRESET);
	~rda58xx(void);
	void hardReset(void);
	void bufferReq(mci_type_enum ftype, unsigned short size, unsigned short threshold1, unsigned short threshold2);
	void bufferReq(mci_type_enum ftype, unsigned short size, unsigned short threshold);
	void startPlay(mci_type_enum ftype);
    void stopPlay(void);
	void stopPlay(rda58xx_stop_type stype);
	void pause(void);
	void resume(void);
	void startRecord(mci_type_enum ftype, unsigned short size);
	void stopRecord(void);
	void setMicGain(unsigned char gain);
	void volAdd(void);
	void volSub(void);	
    void sendRawData(unsigned char *databuf, unsigned short n);
    void setBaudrate(int baud);
	void setStatus(rda58xx_status status);
	rda58xx_status getStatus(void);
	void clearBufferStatus(void);
	rda58xx_buffer_status getBufferStatus(void);
	unsigned char *getBufferAddr(void);
	void setBufferSize(unsigned int size);
	unsigned int getBufferSize(void);
	unsigned int requestData(void);
	void factoryTest(rda58xx_ft_test mode);
	rda58xx_status getCodecStatus(void);
	void getChipVersion(char *version);
    void rx_handler(void);
	void tx_handler(void);
private:
    RawSerial  _serial;
    int        _baud;
    Semaphore  _rxsem;
	DigitalOut _HRESET;
	volatile rda58xx_status _status;
	volatile rda58xx_buffer_status _rx_buffer_status;
	unsigned int _rx_buffer_size;
	unsigned int _tx_buffer_size;
	unsigned int _rx_idx;
	unsigned int _tx_idx;
	unsigned char *_rx_buffer;
	unsigned char *_tx_buffer;	
	rda58xx_parameter _parameter;
	volatile bool _with_parameter;
	DigitalIn _DREQ;

};

#endif

