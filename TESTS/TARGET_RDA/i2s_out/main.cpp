#include "mbed.h"
#include "rda_i2s_api.h"

uint32_t sin_signal_wdata[48] = {
    0x00000000, 0x800f0960, 0x001dd0e2, 0x802c15cb, 0x0039999a, 0x8046211b, 0x0051756d, 0x805b64f1,
    0x0063c421, 0x806a6e51, 0x006f4650, 0x807236e6, 0x00733333, 0x807236e6, 0x006f4650, 0x806a6e51,
    0x0063c421, 0x805b64f1, 0x0051756d, 0x8046211b, 0x0039999a, 0x802c15cb, 0x001dd0e2, 0x800f0960,
    0x00000000, 0x80f0f6a0, 0x00e22f1e, 0x80d3ea35, 0x00c66666, 0x80b9dee5, 0x00ae8a93, 0x80a49b0f,
    0x009c3bdf, 0x809591af, 0x0090b9b0, 0x808dc91a, 0x008ccccd, 0x808dc91a, 0x0090b9b0, 0x809591af,
    0x009c3bdf, 0x80a49b0f, 0x00ae8a93, 0x80b9dee5, 0x00c66666, 0x80d3ea35, 0x00e22f1e, 0x80f0f6a0
};

int main() {
    i2s_t obj = {0};
    i2s_cfg_t cfg;

    cfg.mode              = I2S_MD_MASTER_TX;
    cfg.tx.fs             = I2S_64FS;
    cfg.tx.ws_polarity    = I2S_WS_POS;
    cfg.tx.std_mode       = I2S_STD_M;
    cfg.tx.justified_mode = I2S_RIGHT_JM;
    cfg.tx.data_len       = I2S_DL_16b;
    cfg.tx.msb_lsb        = I2S_MSB;
    cfg.tx.wrfifo_cntleft = I2S_WF_CNTLFT_8W;

    printf("Init I2S(out)...\r\n");

    rda_i2s_init(&obj, I2S_TX_BCLK, I2S_TX_WS, I2S_TX_SD, NC, NC, NC, NC);
    rda_i2s_format(&obj, &cfg);

    while(true) {
        while(I2S_ST_BUSY == obj.sw_tx.state);
        rda_i2s_int_send(&obj, &sin_signal_wdata[0], 48);
    }
}
