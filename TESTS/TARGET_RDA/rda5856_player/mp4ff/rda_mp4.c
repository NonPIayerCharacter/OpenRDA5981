#include "rda_mp4.h"
#include <stdio.h>

/* defines if an object type can be decoded by this library or not */
static uint8_t ObjectTypesTable[32] = {
    0, /*  0 NULL */
#ifdef MAIN_DEC
    1, /*  1 AAC Main */
#else
    0, /*  1 AAC Main */
#endif
    1, /*  2 AAC LC */
#ifdef SSR_DEC
    1, /*  3 AAC SSR */
#else
    0, /*  3 AAC SSR */
#endif
#ifdef LTP_DEC
    1, /*  4 AAC LTP */
#else
    0, /*  4 AAC LTP */
#endif
#ifdef SBR_DEC
    1, /*  5 SBR */
#else
    0, /*  5 SBR */
#endif
    0, /*  6 AAC Scalable */
    0, /*  7 TwinVQ */
    0, /*  8 CELP */
    0, /*  9 HVXC */
    0, /* 10 Reserved */
    0, /* 11 Reserved */
    0, /* 12 TTSI */
    0, /* 13 Main synthetic */
    0, /* 14 Wavetable synthesis */
    0, /* 15 General MIDI */
    0, /* 16 Algorithmic Synthesis and Audio FX */

    /* MPEG-4 Version 2 */
#ifdef ERROR_RESILIENCE
    1, /* 17 ER AAC LC */
    0, /* 18 (Reserved) */
#ifdef LTP_DEC
    1, /* 19 ER AAC LTP */
#else
    0, /* 19 ER AAC LTP */
#endif
    0, /* 20 ER AAC scalable */
    0, /* 21 ER TwinVQ */
    0, /* 22 ER BSAC */
#ifdef LD_DEC
    1, /* 23 ER AAC LD */
#else
    0, /* 23 ER AAC LD */
#endif
    0, /* 24 ER CELP */
    0, /* 25 ER HVXC */
    0, /* 26 ER HILN */
    0, /* 27 ER Parametric */
#else /* No ER defined */
    0, /* 17 ER AAC LC */
    0, /* 18 (Reserved) */
    0, /* 19 ER AAC LTP */
    0, /* 20 ER AAC scalable */
    0, /* 21 ER TwinVQ */
    0, /* 22 ER BSAC */
    0, /* 23 ER AAC LD */
    0, /* 24 ER CELP */
    0, /* 25 ER HVXC */
    0, /* 26 ER HILN */
    0, /* 27 ER Parametric */
#endif
    0, /* 28 (Reserved) */
    //0, /* 29 (Reserved) */
    1, /* 29 PS */
    0, /* 30 (Reserved) */
    0  /* 31 (Reserved) */
};


/* initialize buffer, call once before first getbits or showbits */
void faad_initbits(bitfile *ld, const void *_buffer, const uint32_t buffer_size)
{
    uint32_t tmp;

    if (ld == NULL)
        return;

    if (buffer_size == 0 || _buffer == NULL) {
        ld->error = 1;
        return;
    }

    ld->buffer = _buffer;

    ld->buffer_size = buffer_size;
    ld->bytes_left  = buffer_size;

    if (ld->bytes_left >= 4) {
        tmp = getdword((uint32_t*)ld->buffer);
        ld->bytes_left -= 4;
    } else {
        tmp = getdword_n((uint32_t*)ld->buffer, ld->bytes_left);
        ld->bytes_left = 0;
    }
    ld->bufa = tmp;

    if (ld->bytes_left >= 4) {
        tmp = getdword((uint32_t*)ld->buffer + 1);
        ld->bytes_left -= 4;
    } else {
        tmp = getdword_n((uint32_t*)ld->buffer + 1, ld->bytes_left);
        ld->bytes_left = 0;
    }
    ld->bufb = tmp;

    ld->start = (uint32_t*)ld->buffer;
    ld->tail = ((uint32_t*)ld->buffer + 2);

    ld->bits_left = 32;

    ld->error = 0;
}

uint8_t faad_byte_align(bitfile *ld)
{
    int remainder = (32 - ld->bits_left) & 0x7;

    if (remainder) {
        faad_flushbits(ld, 8 - remainder);
        return (uint8_t)(8 - remainder);
    }
    return 0;
}

void faad_endbits(bitfile *ld)
{
    // void
}

uint32_t faad_get_processed_bits(bitfile *ld)
{
    return (uint32_t)(8 * (4*(ld->tail - ld->start) - 4) - (ld->bits_left));
}

/* Returns the sample rate based on the sample rate index */
uint32_t get_sample_rate(const uint8_t sr_index)
{
    static const uint32_t sample_rates[] = {
        96000, 88200, 64000, 48000, 44100, 32000,
        24000, 22050, 16000, 12000, 11025, 8000
    };

    if (sr_index < 12)
        return sample_rates[sr_index];

    return 0;
}

int8_t rda_GASpecificConfig(bitfile *ld, mp4AudioSpecificConfig *mp4ASC)
{

    /* 1024 or 960 */
    mp4ASC->frameLengthFlag = faad_get1bit(ld);
#ifndef ALLOW_SMALL_FRAMELENGTH
    if (mp4ASC->frameLengthFlag == 1)
        return -3;
#endif

    mp4ASC->dependsOnCoreCoder = faad_get1bit(ld);
    if (mp4ASC->dependsOnCoreCoder == 1) {
        mp4ASC->coreCoderDelay = (uint16_t)faad_getbits(ld, 14);
    }

    mp4ASC->extensionFlag = faad_get1bit(ld);
    if (mp4ASC->channelsConfiguration == 0) {
        return -3;
    }

#ifdef ERROR_RESILIENCE
    if (mp4ASC->extensionFlag == 1) {
        /* Error resilience not supported yet */
        if (mp4ASC->objectTypeIndex >= ER_OBJECT_START) {
            mp4ASC->aacSectionDataResilienceFlag = faad_get1bit(ld);
            mp4ASC->aacScalefactorDataResilienceFlag = faad_get1bit(ld);
            mp4ASC->aacSpectralDataResilienceFlag = faad_get1bit(ld);
        }
        /* 1 bit: extensionFlag3 */
        faad_getbits(ld, 1);
    }
#endif

    return 0;
}


int8_t rda_AudioSpecificConfigFromBitfile(bitfile *ld,
        mp4AudioSpecificConfig *mp4ASC, uint32_t buffer_size, uint8_t short_form)
{
    int8_t result = 0;
    uint32_t startpos = faad_get_processed_bits(ld);
#ifdef SBR_DEC
    int8_t bits_to_decode = 0;
    int8_t originalObjectTypeIndex;
#endif

    if (mp4ASC == NULL)
        return -8;

    memset(mp4ASC, 0, sizeof(mp4AudioSpecificConfig));

    mp4ASC->objectTypeIndex = (uint8_t)faad_getbits(ld, 5);

    mp4ASC->samplingFrequencyIndex = (uint8_t)faad_getbits(ld, 4);
    if(mp4ASC->samplingFrequencyIndex == 0x0f)
        faad_getbits(ld, 24);

    mp4ASC->channelsConfiguration = (uint8_t)faad_getbits(ld, 4);

    mp4ASC->samplingFrequency = get_sample_rate(mp4ASC->samplingFrequencyIndex);

    M4ALOG("1,objectTypeIndex=%d,samplingFrequencyIndex=%d,channelsConfiguration=%d,sbr_present_flag=%d\n",\
           mp4ASC->objectTypeIndex, mp4ASC->samplingFrequencyIndex, mp4ASC->channelsConfiguration, mp4ASC->sbr_present_flag);

    originalObjectTypeIndex = mp4ASC->objectTypeIndex;

    if (ObjectTypesTable[mp4ASC->objectTypeIndex] != 1) {
        return -1;
    }

    if (mp4ASC->samplingFrequency == 0) {
        return -2;
    }

    if (mp4ASC->channelsConfiguration > 7) {
        return -3;
    }

#if (defined(PS_DEC) || defined(DRM_PS))
    /* check if we have a mono file */
    if (mp4ASC->channelsConfiguration == 1) {
        /* upMatrix to 2 channels for implicit signalling of PS */
        mp4ASC->channelsConfiguration = 2;
    }
#endif

#ifdef SBR_DEC
    mp4ASC->sbr_present_flag = -1;
    mp4ASC->ps_present_flag = -1;
    if (mp4ASC->objectTypeIndex == 5 || mp4ASC->objectTypeIndex == 29) {
        uint8_t tmp;

        mp4ASC->sbr_present_flag = 1;
        if (mp4ASC->objectTypeIndex == 29)
            mp4ASC->ps_present_flag = 1;
        tmp = (uint8_t)faad_getbits(ld, 4);
        /* check for downsampled SBR */
        if (tmp == mp4ASC->samplingFrequencyIndex)
            mp4ASC->downSampledSBR = 1;
        mp4ASC->samplingFrequencyIndex = tmp;
        if (mp4ASC->samplingFrequencyIndex == 15) {
            mp4ASC->samplingFrequency = (uint32_t)faad_getbits(ld, 24);
        } else {
            mp4ASC->samplingFrequency = get_sample_rate(mp4ASC->samplingFrequencyIndex);
        }
        mp4ASC->objectTypeIndex = (uint8_t)faad_getbits(ld, 5);
    }
#endif

    M4ALOG("2,objectTypeIndex=%d,samplingFrequencyIndex=%d,channelsConfiguration=%d,sbr_present_flag=%d\n",\
           mp4ASC->objectTypeIndex, mp4ASC->samplingFrequencyIndex, mp4ASC->channelsConfiguration, mp4ASC->sbr_present_flag);

    if (ObjectTypesTable[mp4ASC->objectTypeIndex] != 1) {
        return -1;
    }

    /* get GASpecificConfig */
    if (mp4ASC->objectTypeIndex == 1 || mp4ASC->objectTypeIndex == 2 ||
            mp4ASC->objectTypeIndex == 3 || mp4ASC->objectTypeIndex == 4 ||
            mp4ASC->objectTypeIndex == 6 || mp4ASC->objectTypeIndex == 7) {
        result = rda_GASpecificConfig(ld, mp4ASC);

#ifdef ERROR_RESILIENCE
    } else if (mp4ASC->objectTypeIndex >= ER_OBJECT_START) { /* ER */
        result = rda_GASpecificConfig(ld, mp4ASC);
        mp4ASC->epConfig = (uint8_t)faad_getbits(ld, 2);
        M4ALOG("mp4ASC->epConfig=%d\n", mp4ASC->epConfig);

        if (mp4ASC->epConfig != 0)
            result = -5;
#endif

    } else {
        result = -4;
    }

#ifdef SSR_DEC
    /* shorter frames not allowed for SSR */
    if ((mp4ASC->objectTypeIndex == 4) && mp4ASC->frameLengthFlag)
        return -6;
#endif


#ifdef SBR_DEC
    if(short_form)
        bits_to_decode = 0;
    else
        bits_to_decode = (int8_t)(buffer_size*8 - (startpos-faad_get_processed_bits(ld)));
    M4ALOG("bits_to_decode=%d\n", bits_to_decode);
    if ((mp4ASC->objectTypeIndex != 5) && (bits_to_decode >= 16)) {
        int16_t syncExtensionType = (int16_t)faad_getbits(ld, 11);
        M4ALOG("syncExtensionType=0x%04x\n", syncExtensionType);

        if (syncExtensionType == 0x2b7) {
            uint8_t tmp_OTi = (uint8_t)faad_getbits(ld, 5);

            if (tmp_OTi == 5) {
                mp4ASC->sbr_present_flag = (uint8_t)faad_get1bit(ld);

                if (mp4ASC->sbr_present_flag) {
                    uint8_t tmp;

                    /* Don't set OT to SBR until checked that it is actually there */
                    mp4ASC->objectTypeIndex = tmp_OTi;

                    tmp = (uint8_t)faad_getbits(ld, 4);

                    /* check for downsampled SBR */
                    if (tmp == mp4ASC->samplingFrequencyIndex)
                        mp4ASC->downSampledSBR = 1;
                    mp4ASC->samplingFrequencyIndex = tmp;

                    if (mp4ASC->samplingFrequencyIndex == 15) {
                        mp4ASC->samplingFrequency = (uint32_t)faad_getbits(ld, 24);
                    } else {
                        mp4ASC->samplingFrequency = get_sample_rate(mp4ASC->samplingFrequencyIndex);
                    }
                    bits_to_decode = (int8_t)(buffer_size*8 - (startpos-faad_get_processed_bits(ld)));
                    M4ALOG("bits_to_decode=%d\n", bits_to_decode);
                    if (bits_to_decode >= 12) {
                        syncExtensionType = (int16_t)faad_getbits(ld, 11);
                        M4ALOG("syncExtensionType=0x%04x\n", syncExtensionType);
                        if (syncExtensionType == 0x548)
                            mp4ASC->ps_present_flag = (uint8_t)faad_get1bit(ld);
                    }
                }
            }
        }
    }

    /* no SBR signalled, this could mean either implicit signalling or no SBR in this file */
    /* MPEG specification states: assume SBR on files with samplerate <= 24000 Hz */
    if (mp4ASC->sbr_present_flag == -1) {
        if (mp4ASC->samplingFrequency <= 24000) {
            mp4ASC->samplingFrequency *= 2;
            mp4ASC->forceUpSampling = 1;
        } else { /* > 24000*/
            mp4ASC->downSampledSBR = 1;
        }
    }
#endif

    M4ALOG("3,objectTypeIndex=%d,samplingFrequencyIndex=%d,channelsConfiguration=%d,sbr_present_flag=%d\n",\
           mp4ASC->objectTypeIndex, mp4ASC->samplingFrequencyIndex, mp4ASC->channelsConfiguration, mp4ASC->sbr_present_flag);

    if (ObjectTypesTable[mp4ASC->objectTypeIndex] != 1) {
        return -1;
    }

#ifdef SBR_DEC
    if (mp4ASC->sbr_present_flag == 1) {
        mp4ASC->samplingFrequency = mp4ASC->samplingFrequency / 2;
        mp4ASC->samplingFrequencyIndex = FindAdtsSRIndex(mp4ASC->samplingFrequency);

        if (mp4ASC->objectTypeIndex == 5)
            mp4ASC->objectTypeIndex = originalObjectTypeIndex;
    }
#endif

    M4ALOG("4,objectTypeIndex=%d,samplingFrequencyIndex=%d,channelsConfiguration=%d,sbr_present_flag=%d\n",\
           mp4ASC->objectTypeIndex, mp4ASC->samplingFrequencyIndex, mp4ASC->channelsConfiguration, mp4ASC->sbr_present_flag);

    if (ObjectTypesTable[mp4ASC->objectTypeIndex] != 1) {
        return -1;
    }

    faad_endbits(ld);

    return 0;
}

int8_t rda_AudioSpecificConfig2(uint8_t *pBuffer,
                                uint32_t buffer_size,
                                mp4AudioSpecificConfig *mp4ASC,
                                uint8_t short_form)
{
    uint8_t ret = 0;
    bitfile ld;
    faad_initbits(&ld, pBuffer, buffer_size);
    faad_byte_align(&ld);
    ret = rda_AudioSpecificConfigFromBitfile(&ld, mp4ASC, buffer_size, short_form);
    faad_endbits(&ld);
    return ret;
}

static int adts_sample_rates[] = {96000,88200,64000,48000,44100,32000,24000,22050,16000,12000,11025,8000,7350,0,0,0};

static int FindAdtsSRIndex(int sr)
{
    int i;

    for (i = 0; i < 16; i++) {
        if (sr == adts_sample_rates[i])
            return i;
    }
    return 16 - 1;
}

int32_t rda_MakeAdtsHeader(unsigned char *data, int size, mp4AudioSpecificConfig *mp4ASC)
{
    int profile = (mp4ASC->objectTypeIndex - 1) & 0x3;

    memset(data, 0, 7 * sizeof(unsigned char));//ADTS header size = 7

    data[0] += 0xFF; /* 8b: syncword */

    data[1] += 0xF0; /* 4b: syncword */
    /* 1b: mpeg id = 0 */
    /* 2b: layer = 0 */
    data[1] += 1; /* 1b: protection absent */

    data[2] += ((profile << 6) & 0xC0); /* 2b: profile */
    data[2] += ((mp4ASC->samplingFrequencyIndex << 2) & 0x3C); /* 4b: sampling_frequency_index */
    /* 1b: private = 0 */
    data[2] += ((mp4ASC->channelsConfiguration >> 2) & 0x1); /* 1b: channel_configuration */

    data[3] += ((mp4ASC->channelsConfiguration << 6) & 0xC0); /* 2b: channel_configuration */
    /* 1b: original */
    /* 1b: home */
    /* 1b: copyright_id */
    /* 1b: copyright_id_start */
    data[3] += ((size >> 11) & 0x3); /* 2b: aac_frame_length */

    data[4] += ((size >> 3) & 0xFF); /* 8b: aac_frame_length */

    data[5] += ((size << 5) & 0xE0); /* 3b: aac_frame_length */
    data[5] += ((0x7FF >> 6) & 0x1F); /* 5b: adts_buffer_fullness */

    data[6] += ((0x7FF << 2) & 0x3F); /* 6b: adts_buffer_fullness */
    /* 2b: num_raw_data_blocks */

    return 0;
}

uint32_t read_callback(void *user_data, void *buffer, uint32_t length)
{
    return fread(buffer, 1, length, (FILE*)user_data);
}

uint32_t seek_callback(void *user_data, uint64_t position)
{
    return fseek((FILE*)user_data, position, SEEK_SET);
}

