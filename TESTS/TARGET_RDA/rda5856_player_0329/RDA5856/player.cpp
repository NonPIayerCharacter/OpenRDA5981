#include "player.h"
#include "rda58xx.h"
#include "SDMMCFileSystem.h"

#define RDA5991H_HDK_V1_0
#define BUFFER_2K

#ifdef RDA5991H_HDK_V1_0
SDMMCFileSystem sd(PB_9, PB_0, PB_3, PB_7, PC_0, PC_1, "sd"); //SD Card pins
rda58xx rda5856(PB_2, PB_1, PB_8);//UART pins: tx, rx, xreset //HDK_V1.0
//rda58xx rda5856(PD_3, PD_2, PB_8);//UART pins: tx, rx, xreset //RDA5956
//rda58xx rda5856(PB_2, PB_1, PC_9);//UART pins: tx, rx, xreset //HanFeng
#else
SDMMCFileSystem sd(PB_9, PB_0, PB_6, PB_7, PC_0, PC_1, "sd"); //SD Card pins
rda58xx rda5856(PB_2, PB_1, PC_3);//UART pins: tx, rx, xreset
#endif

playerStatetype  playerState;
ctrlStatetype ctrlState;
#ifdef BUFFER_2K
static unsigned char fileBuf[2048];
#else
static unsigned char fileBuf[1024];
#endif
unsigned char *bufptr;

char list[15][32];            //song list
char index_current = 0;       //song play index
char index_MAX;               //how many song in all
unsigned char vlume = 0x40;   //vlume
unsigned char vlumeflag = 0;  //set vlume flag
volumeStatetype volumeState = VOL_NONE;

void Player::begin(void)
{
    DirHandle *dir;
    struct dirent *ptr;
    FileHandle *fp;

    dir = opendir("/sd");
    printf("\r\n**********playing list**********\r\n");
    unsigned char i = 0, j = 0;
    while(((ptr = dir->readdir()) != NULL)&&(i <15)) {
        if(strstr(ptr->d_name,".mp3")||strstr(ptr->d_name,".MP3")||strstr(ptr->d_name,".AAC")||strstr(ptr->d_name,".aac")
            ||strstr(ptr->d_name,".WAV")||strstr(ptr->d_name,".wav"))
            //||strstr(ptr->d_name,".WMA")||strstr(ptr->d_name,".wma")||strstr(ptr->d_name,".M4A")||strstr(ptr->d_name,".m4a")
            //||strstr(ptr->d_name,".OGG")||strstr(ptr->d_name,".ogg")||strstr(ptr->d_name,".FLAC")||strstr(ptr->d_name,".flac"))
        {
            fp =sd.open(ptr->d_name, O_RDONLY);
            if(fp != NULL) {
                char *byte = ptr->d_name;
                j=0;
                while(*byte) {
                    list[i][j++]  = *byte++;
                }
                printf("%2d . %s\r\n", i,list[i++]);
                fp->close();
            }
        }
    }
    index_MAX = i-1;
    dir->closedir();
    printf("\r\n");
}

/*  This function plays back an audio file.  */
void Player::playFile(char *file)
{
    int bytes;        // How many bytes in buffer left
    int idx, n;
    int ID3TagSize = 0;
    int osDelayMs = 0;
    unsigned int fileSize = 0;
    unsigned short bufferSize = 0;
    unsigned short bufferThreshold = 0;
    unsigned short frameSize = 0;
    unsigned int frame = 0;
    unsigned int byteRate = 0;
    mci_type_enum audioType;

    playerState = PS_PLAY;

    FileHandle *fp =sd.open(file, O_RDONLY);

    if(fp == NULL) {
        printf("Could not open %s\r\n",file);
    } else {
        printf("Playing %s ...\r\n",file);

        fileSize = fp->flen();
        printf("fileSize:%d\r\n", fileSize);

        if (strstr(file, ".mp3") || strstr(file, ".MP3"))
            audioType = MCI_TYPE_DAF;
        else if (strstr(file, ".aac") || strstr(file, ".AAC"))
            audioType = MCI_TYPE_AAC;
        else if (strstr(file, ".wav") || strstr(file, ".WAV"))
            audioType = MCI_TYPE_WAV;
        else {
            printf("Error! Unsupported Format!\r\n");
            fp->close();
            if(index_current != index_MAX)
                index_current++;
            else
                index_current = 0;
            return;
        }

        if (audioType == MCI_TYPE_WAV) {
            bytes = fp->read(fileBuf,44);
            byteRate = (fileBuf[31] << 24) | (fileBuf[30] << 16) | (fileBuf[29] << 8) | fileBuf[28];
            fp->lseek(0, SEEK_SET);

#if 1 
            if (byteRate <= 32000) {
                osDelayMs = 100;
            } else if (byteRate <= 64000) {
                osDelayMs = 45;
            } else if (byteRate <= 88200) {
                osDelayMs = 25;
            } else if (byteRate <= 96000) {
                osDelayMs = 20;
            } else if (byteRate <= 128000) {
                osDelayMs = 15;
            } else if (byteRate <= 176400) {
                osDelayMs = 7;
            } else {
                osDelayMs = 0;
            }
#endif
        } else if (audioType == MCI_TYPE_DAF){
            bytes = fp->read(fileBuf,10);
            if (fileBuf[0] == 0x49 && fileBuf[1] == 0x44 && fileBuf[2] == 0x33) {
                ID3TagSize = (fileBuf[6] << 21) | (fileBuf[7] << 14) | (fileBuf[8] << 7) | (fileBuf[9] << 0);
                printf("ID3TagSize:%d\r\n", ID3TagSize);
                ID3TagSize += 10;
                fp->lseek(ID3TagSize, SEEK_SET);
                printf("ID3 tag skip\r\n");
            } else {
                fp->lseek(0, SEEK_SET);
                printf("No ID3 tag\r\n");
            }
            osDelayMs = 100;
        } else {
            osDelayMs = 90;
        }
        printf("osDelayMs:%d\n", osDelayMs);

        if ((fileSize - ID3TagSize) > (1024 * 5)) {
            bufferSize = 1024 * 8;
            bufferThreshold = 1024 * 5;
        } else {
            bufferSize = 1024 * 8;
            bufferThreshold = (fileSize - ID3TagSize) / 2;
        }
        
        //rda5856.stopPlay(WITHOUT_ENDING);
#ifdef BUFFER_2K        
        rda5856.bufferReq(audioType, bufferSize, bufferThreshold);
#else
        rda5856.bufferReq(audioType, bufferSize, bufferThreshold);
#endif
        /* Main playback loop */
#ifdef BUFFER_2K
        while((bytes = fp->read(fileBuf,2048)) > 0) {
#else
        while((bytes = fp->read(fileBuf,1024)) > 0) {
#endif
            bufptr = fileBuf;
            switch (volumeState) {
            case VOL_NONE:
                break;
            case VOL_ADD:
                rda5856.volAdd();
                volumeState = VOL_NONE;
                break;
            case VOL_SUB:
                rda5856.volSub();
                volumeState = VOL_NONE;
                break;
            default:
                break;
            }
            
            // actual audio data gets sent to RDA58XX.
            if (playerState == PS_PLAY) {
                while(bytes > 0) {
#ifdef BUFFER_2K
                    n = (bytes < 2048) ? bytes : 2048;
#else
                    n = (bytes < 1024) ? bytes : 1024;
#endif
                    rda5856.sendRawData(bufptr, n);
                    bytes -= n;
                    bufptr += n;
                    frame++;
                }
            }

            if (playerState == PS_PAUSE) {
                rda5856.pause();
                printf("PAUSE\r\n");
            }
            while (playerState == PS_PAUSE);         //Pause
            if (playerState == PS_RESUME) {
                rda5856.resume();
                printf("RESUME\r\n");
                playerState = PS_PLAY;
            }

            if(playerState != PS_PLAY) {       //stop
                printf("Stop Playing\r\n");
                rda5856.stopPlay(WITHOUT_ENDING);
                fp->close();
                return;
            }

        }

#if 0
        memset(fileBuf, 0 , 1024);
        //idx = bufferSize / 1024 + 8;
        idx = bufferSize / 1024;
        while (idx > 0) {
            rda5856.sendRawData(bufptr, 1024);
            idx--;
        }
#endif

#if 1
        rda5856.stopPlay(WITH_ENDING);
        while (PLAY == rda5856.getCodecStatus()) {
            Thread::wait(100);
            if(playerState != PS_PLAY) {
                return;
            }
        }
#endif
        fp->close();
        printf("[done!]\r\n");
    }
    if(index_current != index_MAX)
        index_current++;
    else
        index_current = 0;
}

/* PCM file Header */
unsigned char pcmHeader[44] = {
    'R', 'I', 'F', 'F',
    0xFF, 0xFF, 0xFF, 0xFF,
    'W', 'A', 'V', 'E',
    'f', 'm', 't', ' ',
    0x10, 0, 0, 0,          /* 16 */
    0x1, 0,                 /* PCM */
    0x1, 0,                 /* chan */
    0x40, 0x1F, 0x0, 0x0,     /* sampleRate */
    0x80, 0x3E, 0x0, 0x0,     /* byteRate */
    2, 0,                   /* blockAlign */
    0x10, 0,                /* bitsPerSample */
    'd', 'a', 't', 'a',
    0xFF, 0xFF, 0xFF, 0xFF
};

void Set32(unsigned char *d, unsigned int n)
{
    int i;
    for (i=0; i<4; i++) {
        *d++ = (unsigned char)n;
        n >>= 8;
    }
}

/*  This function records an audio file in WAV formats.Use LINK1,left channel  */
void Player::recordFile(char *file)
{
    unsigned int fileSize = 0;
    unsigned int n = 0;

    //rda5856.stopPlay();
    rda5856.stopPlay(WITHOUT_ENDING);
    sd.remove(file);
    FileHandle *fp =sd.open(file, O_WRONLY|O_CREAT);
    if(fp == NULL) {
        printf("Could not open file for write\r\n");
    } else {
        fp->write(pcmHeader, sizeof(pcmHeader));
        //rda5856.setMicGain(7);
        rda5856.startRecord(MCI_TYPE_WAV_DVI_ADPCM, rda5856.getBufferSize() * 2 / 4);
        rda5856.setStatus(RECORDING);
        printf("recording......\r\n");
        
        while (playerState == PS_RECORDING) {
            if (FULL == rda5856.getBufferStatus()) {
                rda5856.clearBufferStatus();
                fp->write(rda5856.getBufferAddr(), rda5856.getBufferSize());
                fileSize += rda5856.getBufferSize();
                n++;
                //printf("REC:%d\n", n);
            }
        }
        rda5856.stopRecord();
        rda5856.clearBufferStatus();

        /* Update file sizes for an RIFF PCM .WAV file */
        fp->lseek(0, SEEK_SET);
        Set32(pcmHeader + 4, fileSize + 36);
        Set32(pcmHeader + 40, fileSize);
        fp->write(pcmHeader, sizeof(pcmHeader));
        fp->close();

        printf("recording end\r\n");
    }
}


