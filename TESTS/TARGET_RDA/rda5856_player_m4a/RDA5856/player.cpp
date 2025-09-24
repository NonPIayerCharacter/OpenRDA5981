#include "player.h"
#include "rda58xx.h"
#include "SDMMCFileSystem.h"

#include <stdio.h>
#include <string.h>
#include "mp4ff.h"
#include "rda_mp4.h"

#define RDA5991H_HDK_V1_0

#ifdef RDA5991H_HDK_V1_0
SDMMCFileSystem sd(PB_9, PB_0, PB_3, PB_7, PC_0, PC_1, "sd"); //SD Card pins
//rda58xx rda5856(PB_2, PB_1, PB_8);//UART pins: tx, rx, xreset
rda58xx rda5856(PB_2, PB_1, PC_6);//UART pins: tx, rx, xreset //HDK_V1.2
//rda58xx rda5856(PD_3, PD_2, PB_8);//UART pins: tx, rx, xreset //RDA5956
#else
SDMMCFileSystem sd(PB_9, PB_0, PB_6, PB_7, PC_0, PC_1, "sd"); //SD Card pins
rda58xx rda5856(PB_2, PB_1, PC_3);//UART pins: tx, rx, xreset
#endif

playerStatetype  playerState;
ctrlStatetype ctrlState;
//static unsigned char fileBuf[1024];
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
        #if 0
        if(strstr(ptr->d_name,".mp3")||strstr(ptr->d_name,".MP3")||strstr(ptr->d_name,".AAC")||strstr(ptr->d_name,".aac")
            ||strstr(ptr->d_name,".M4A")||strstr(ptr->d_name,".m4a")||strstr(ptr->d_name,".WAV")||strstr(ptr->d_name,".wav"))
            //||strstr(ptr->d_name,".WMA")||strstr(ptr->d_name,".wma")
            //||strstr(ptr->d_name,".OGG")||strstr(ptr->d_name,".ogg")||strstr(ptr->d_name,".FLAC")||strstr(ptr->d_name,".flac"))
        #endif
        if (strstr(ptr->d_name,".M4A")||strstr(ptr->d_name,".m4a"))
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
    unsigned short bufferThreshold1 = 0;
    unsigned short bufferThreshold2 = 0;
    unsigned short frameSize = 0;
    unsigned int frame = 0;
    unsigned int byteRate = 0;
    mci_type_enum audioType;

    mp4ff_t *infile;
    mp4ff_callback_t *mp4cb;
    mp4AudioSpecificConfig mp4ASC;
    FILE *mp4File;
#ifdef ADTS_OUT
    FILE *adtsFile;
#endif
    unsigned char *buffer;
    unsigned int buffer_size;
    unsigned long sampleId, numSamples;
    int result;

    playerState = PS_PLAY;

    if (strstr(file, ".m4a") || strstr(file, ".M4A")) {
        //mp4File = fopen(file, "rb");
        char dir[32] = {0};
        int len = sprintf((char *)dir, "%s%s", "/sd/", file);
        dir[len] = '\0';
        printf("%s", dir);
        printf("\n");
        mp4File = fopen(dir, "rb");
#ifdef ADTS_OUT
        memcpy(&dir[len - 3], "aac", 3);
        //adtsFile = fopen("/sd/adts.aac", "wb");
        adtsFile = fopen(dir, "wb");
#endif
        if (mp4File == NULL) {
            printf("Could not open %s\n",file);
        } else {
            printf("Playing %s ...\n",file);

            mp4cb = (mp4ff_callback_t *)malloc(sizeof(mp4ff_callback_t));
            if (mp4cb == NULL) {
                printf("Error malloc mp4cb\n");
                goto ERROR;
            }

            mp4cb->read = read_callback;
            mp4cb->seek = seek_callback;
            mp4cb->user_data = mp4File;

            infile = mp4ff_open_read(mp4cb);

            if (infile == NULL) {
                printf("Error open file: %s\n", file);
                goto ERROR;
            }

            int track = rda_mp4ff_get_aac_track(infile);
            if (track < 0) {
                printf("Unable to find correct AAC sound track in the MP4 file.\n");
                goto ERROR;
            }

            buffer = NULL;
            buffer_size = 0;

            mp4ff_get_decoder_config(infile, track, &buffer, &buffer_size);

            if (buffer) {
                rda_AudioSpecificConfig2(buffer, buffer_size, &mp4ASC, 0);
                free(buffer);
            }
            printf("objectTypeIndex=%d,samplingFrequencyIndex=%d,channelsConfiguration=%d,sbr_present_flag=%d\n",\ 
                mp4ASC.objectTypeIndex, mp4ASC.samplingFrequencyIndex, mp4ASC.channelsConfiguration, mp4ASC.sbr_present_flag);
            numSamples = mp4ff_num_samples(infile, track);
            printf("numSamples:%d\n", numSamples);

            sampleId = 0;

            result = rda_mp4ff_fill_stsz_table(infile, track, sampleId);
            printf("rda_mp4ff_fill_stsz_table:%d\n", result);
            if (result <= 0) {
                printf("Fill stsz table failed\n");
                goto ERROR;
            }

            rda5856.bufferReq(MCI_TYPE_AAC, 1024 * 16, 1024 * 5);
            
            do {
                int rc;
                unsigned long dur;
                int offset;
                int size;
                
                /* get acces unit from MP4 file */
                buffer = NULL;
                buffer_size = 0;

                dur = mp4ff_get_sample_duration(infile, track, sampleId);
                rda_mp4ff_get_sample_position_and_size(infile, track, sampleId, &offset, &size);
                printf("ID:%d,offset:%d,size:%d\n", sampleId, offset, size);
                rc = rda_mp4ff_read_sample_adts(infile, track, sampleId, &buffer,  &buffer_size);
                if (rc == 0) {
                    printf("Reading from MP4 file failed.\n");
                    rda5856.stopPlay(WITHOUT_ENDING);
                    goto ERROR;
                }

                rda_MakeAdtsHeader(buffer, buffer_size, &mp4ASC);
#ifdef ADTS_OUT
                fwrite(buffer, sizeof(unsigned char), buffer_size , adtsFile);
#endif
                bufptr = buffer;
                bytes = buffer_size;
                
                while(bytes > 0) {
                    n = (bytes < 2048) ? bytes : 2048;
                    rda5856.sendRawData(bufptr, n);
                    bytes -= n;
                    bufptr += n;
                    frame++;
                }

                if (playerState == PS_PAUSE)
                    printf("PAUSE\r\n");
                while (playerState == PS_PAUSE);         //Pause

                if(playerState != PS_PLAY) {       //stop
                    printf("Stop Playing\r\n");
                    rda5856.stopPlay(WITHOUT_ENDING);
                    goto END;
                }

                sampleId++;
                result = rda_mp4ff_refill_stsz_table(infile, track, sampleId, numSamples);

                if (result <= 0) {
                    printf("Refill stsz table failed\n");
                    rda5856.stopPlay(WITHOUT_ENDING);
                    goto ERROR;
                }

                if (buffer) {
                    free(buffer);
                }
                
            } while (sampleId < numSamples);

            //rda5856.stopPlay(WITH_ENDING);
            rda5856.stopPlay(WITHOUT_ENDING);
            printf("[done!]\r\n");
            if(index_current < index_MAX)
                index_current++;
            else
                index_current = 0;
            //while(1);
        }
    } else {
        printf("Error! Unsupported Format!\r\n");
        if(index_current < index_MAX)
            index_current++;
        else
            index_current = 0;
        return;
    }

END:
    if (mp4File)
        fclose(mp4File);
#ifdef ADTS_OUT
    if (adtsFile)
        fclose(adtsFile);
#endif
    if (buffer)
        free(buffer);
    if (infile)
        mp4ff_close(infile);    
    if (mp4cb)
        free(mp4cb);
    return;

ERROR:
    if (mp4File)
        fclose(mp4File);
#ifdef ADTS_OUT
    if (adtsFile)
        fclose(adtsFile);
#endif
    if (buffer)
        free(buffer);
    if (infile)
        mp4ff_close(infile);    
    if (mp4cb)
        free(mp4cb);
    if(index_current < index_MAX)
        index_current++;
    else
        index_current = 0;
    return;
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

    rda5856.stopPlay(WITHOUT_ENDING);
    sd.remove(file);
    FileHandle *fp =sd.open(file, O_WRONLY|O_CREAT);
    if(fp == NULL) {
        printf("Could not open file for write\r\n");
    } else {
        fp->write(pcmHeader, sizeof(pcmHeader));
        rda5856.startRecord(MCI_TYPE_WAV_DVI_ADPCM, rda5856.getBufferSize() * 2 / 4);
        rda5856.setStatus(RECORDING);
        printf("recording......\r\n");
        
        while (playerState == PS_RECORDING) {
            if (FULL == rda5856.getBufferStatus()) {
                rda5856.clearBufferStatus();
                fp->write(rda5856.getBufferAddr(), rda5856.getBufferSize());
                fileSize += rda5856.getBufferSize();
                n++;
                printf("REC:%d\r\n", n);
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

