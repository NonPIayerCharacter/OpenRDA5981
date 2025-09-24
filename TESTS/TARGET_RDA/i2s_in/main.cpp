#include "mbed.h"
#include "rda_i2s_api.h"

uint32_t rdata[48] = {0x00000000};

int main() {
    i2s_t obj = {0};
    i2s_cfg_t cfg;

    cfg.mode              = I2S_MD_SLAVE_RX;
    cfg.rx.fs             = I2S_64FS;
    cfg.rx.ws_polarity    = I2S_WS_POS;
    cfg.rx.std_mode       = I2S_STD_M;
    cfg.rx.justified_mode = I2S_RIGHT_JM;
    cfg.rx.data_len       = I2S_DL_16b;
    cfg.rx.msb_lsb        = I2S_MSB;

    printf("Init I2S(in)...\r\n");

    rda_i2s_init(&obj, NC, NC, NC, I2S_RX_BCLK, I2S_RX_WS, I2S_RX_SD, NC);
    rda_i2s_format(&obj, &cfg);

    while(true) {
        while(I2S_ST_BUSY == obj.sw_rx.state);
        rda_i2s_int_recv(&obj, &rdata[0], 48);
    }
}
