#include "mbed_interface.h"
#include "wland_flash_wp.h"
#include "wland_flash.h"

#ifdef FLASH_PROTECT_ENABLE
static unsigned short flash_wrtie_protect_4M(unsigned short status, unsigned int offset)
{
    unsigned int wp = FLASH_WP_NONE;
    if(offset >= flash_size - flash_size/1024)
        wp = FLASH_4M_WP_1023_1024;
    else if(offset >= flash_size - flash_size/256)
        wp = FLASH_4M_WP_255_256;
    else if(offset >= flash_size - flash_size/128)
        wp = FLASH_4M_WP_127_128;
    else if(offset >= flash_size - flash_size/64)
        wp = FLASH_4M_WP_63_64;
    else if(offset >= flash_size - flash_size/32)
        wp = FLASH_4M_WP_31_32;
    else if(offset >= flash_size - flash_size/16)
        wp = FLASH_4M_WP_15_16;
    else if(offset >= flash_size - flash_size/8)
        wp = FLASH_4M_WP_7_8;
    else if(offset >= flash_size - flash_size/4)
        wp = FLASH_4M_WP_3_4;
    else if(offset >= flash_size/2)
        wp = FLASH_4M_WP_1_2;
    else if(offset >= flash_size/4)
        wp = FLASH_4M_WP_1_4;
    else if(offset >= flash_size/8)
        wp = FLASH_4M_WP_1_8;
    else if(offset >= flash_size/16)
        wp = FLASH_4M_WP_1_16;
    else if(offset >= flash_size/32)
        wp = FLASH_4M_WP_1_32;
    else if(offset >= flash_size/64)
        wp = FLASH_4M_WP_1_64;
    else if(offset >= 32 * 1024)
        wp = FLASH_4M_WP_32K;
    else if(offset >= 16 * 1024)
        wp = FLASH_4M_WP_16K;
    else if(offset >= 8 * 1024)
        wp = FLASH_4M_WP_8K;
    else if(offset >= 4 * 1024)
        wp = FLASH_4M_WP_4K;

    return (status & ~FLASH_WP_MASK) | wp;
    
}

static unsigned short flash_wrtie_protect_2M(unsigned short status, unsigned int offset)
{
    unsigned int wp = FLASH_WP_NONE;
    if(offset >= flash_size - flash_size/256)
        wp = FLASH_2M_WP_255_256;
    else if(offset >= flash_size - flash_size/128)
        wp = FLASH_2M_WP_127_128;
    else if(offset >= flash_size - flash_size/64)
        wp = FLASH_2M_WP_63_64;
    else if(offset >= flash_size - flash_size/32)
        wp = FLASH_2M_WP_31_32;
    else if(offset >= flash_size - flash_size/16)
        wp = FLASH_2M_WP_15_16;
    else if(offset >= flash_size - flash_size/8)
        wp = FLASH_2M_WP_7_8;
    else if(offset >= flash_size - flash_size/4)
        wp = FLASH_2M_WP_3_4;
    else if(offset >= flash_size/2)
        wp = FLASH_2M_WP_1_2;
    else if(offset >= flash_size/4)
        wp = FLASH_2M_WP_1_4;
    else if(offset >= flash_size/8)
        wp = FLASH_2M_WP_1_8;
    else if(offset >= flash_size/16)
        wp = FLASH_2M_WP_1_16;
    else if(offset >= flash_size/32)
        wp = FLASH_2M_WP_1_32;
    else if(offset >= 32 * 1024)
        wp = FLASH_2M_WP_32K;
    else if(offset >= 16 * 1024)
        wp = FLASH_2M_WP_16K;
    else if(offset >= 8 * 1024)
        wp = FLASH_2M_WP_8K;
    else if(offset >= 4 * 1024)
        wp = FLASH_2M_WP_4K;

    return (status & ~FLASH_WP_MASK) | wp;
    
}

static unsigned short flash_wrtie_protect_1M(unsigned short status, unsigned int offset)
{
    unsigned int wp = FLASH_WP_NONE;

    if(offset >= flash_size - flash_size/256)
        wp = FLASH_1M_WP_255_256;
    else if(offset >= flash_size - flash_size/128)
        wp = FLASH_1M_WP_127_128;
    else if(offset >= flash_size - flash_size/64)
        wp = FLASH_1M_WP_63_64;
    else if(offset >= flash_size - flash_size/32)
        wp = FLASH_1M_WP_31_32;
    else if(offset >= flash_size - flash_size/16)
        wp = FLASH_1M_WP_15_16;
    else if(offset >= flash_size - flash_size/8)
        wp = FLASH_1M_WP_7_8;
    else if(offset >= flash_size - flash_size/4)
        wp = FLASH_1M_WP_3_4;
    else if(offset >= flash_size/2)
        wp = FLASH_1M_WP_1_2;
    else if(offset >= flash_size/4)
        wp = FLASH_1M_WP_1_4;
    else if(offset >= flash_size/8)
        wp = FLASH_1M_WP_1_8;
    else if(offset >= flash_size/16)
        wp = FLASH_1M_WP_1_16;
    else if(offset >= 32 * 1024)
        wp = FLASH_1M_WP_32K;
    else if(offset >= 16 * 1024)
        wp = FLASH_1M_WP_16K;
    else if(offset >= 8 * 1024)
        wp = FLASH_1M_WP_8K;
    else if(offset >= 4 * 1024)
        wp = FLASH_1M_WP_4K;

    return (status & ~FLASH_WP_MASK) | wp;
    
}

void flash_wrtie_protect_all()
{
    unsigned short status;
    unsigned char r1, r2;
    core_util_critical_section_enter();
    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x05);
    wait_busy_down();
    r1 = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);

    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x35);
    wait_busy_down();
    r2 = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);
    //mbed_error_printf("status %x %x\r\n", r2, r1);
    
    status = (r2 << 8) | r1;
    status = (status & ~FLASH_WP_MASK) | FLASH_WP_ALL;
    //mbed_error_printf("status %04x\r\n", status);
    
    spi_write_reset();
    wait_busy_down();
    WRITE_REG8(FLAHS_CTL_TX_FIFO_DATA_REG, (status&0xff));
    WRITE_REG8(FLAHS_CTL_TX_FIFO_DATA_REG, ((status>>8)&0xff));
    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x01);
    wait_busy_down();
    spi_wip_reset();
    core_util_critical_section_exit();
    return;
}

void flash_wrtie_protect_none()
{
    unsigned short status;
    unsigned char r1, r2;
    core_util_critical_section_enter();
    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x05);
    wait_busy_down();
    r1 = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);

    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x35);
    wait_busy_down();
    r2 = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);
    //mbed_error_printf("status %x %x\r\n", r2, r1);
    
    status = (r2 << 8) | r1;
    status = status & ~FLASH_WP_MASK;
    //mbed_error_printf("status %04x\r\n", status);

    spi_write_reset();
    wait_busy_down();
    WRITE_REG8(FLAHS_CTL_TX_FIFO_DATA_REG, (status&0xff));
    WRITE_REG8(FLAHS_CTL_TX_FIFO_DATA_REG, ((status>>8)&0xff));
    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x01);
    wait_busy_down();
    spi_wip_reset();
    core_util_critical_section_exit();
    return;
}

void flash_wrtie_protect(unsigned int offset)
{
    unsigned short status;
    unsigned char r1, r2;
    core_util_critical_section_enter();
    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x05);
    wait_busy_down();
    r1 = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);

    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x35);
    wait_busy_down();
    r2 = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);
    //mbed_error_printf("status %x %x\r\n", r2, r1);
    
    status = (r2 << 8) | r1;
    if(flash_size == FLASH_4M)
        status = flash_wrtie_protect_4M(status, offset);
    else if(flash_size == FLASH_2M)
        status = flash_wrtie_protect_2M(status, offset);
    else if(flash_size == FLASH_1M)
        status = flash_wrtie_protect_1M(status, offset);
    else
        printf("flash_size is error\r\n");
    //mbed_error_printf("status %04x\r\n", status);
    
    spi_write_reset();
    wait_busy_down();
    WRITE_REG8(FLAHS_CTL_TX_FIFO_DATA_REG, (status&0xff));
    WRITE_REG8(FLAHS_CTL_TX_FIFO_DATA_REG, ((status>>8)&0xff));
    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x01);
    wait_busy_down();
    spi_wip_reset();
    core_util_critical_section_exit();
    return;
}

#else/*FLASH_PROTECT_ENABLE*/
void flash_wrtie_protect_all()
{
    return;
}

void flash_wrtie_protect_none()
{
    return;
}

void flash_wrtie_protect(unsigned int offset)
{
    return;
}

#endif /*FLASH_PROTECT_ENABLE*/

void rda5981_flash_init()
{
    unsigned int status3, status4, status5;
    core_util_critical_section_enter();
    WRITE_REG32(FLASH_CTL_TX_BLOCK_SIZE_REG, 3<<8);
    status3 = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);
    status4 = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);
    status5 = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);

    wait_busy_down();
    spi_wip_reset();
    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x9F);
    wait_busy_down();
    //WRITE_REG32(FLASH_CTL_TX_BLOCK_SIZE_REG, 3<<8);
    //wait_busy_down();
    status3 = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);
    status4 = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);
    status5 = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);
    core_util_critical_section_exit();
   
    if((status5&0xff != 0x14) && (status5&0xff != 0x15) && (status5&0xff != 0x16)){
        mbed_error_printf("flash size error\r\n");
        return;
    }
    flash_size = (1 << (status5&0xff));
    flash_wrtie_protect_all();
    
    return;
}


#if 0
void wait_busy_down(void)
{
    unsigned int tmp = MREAD_WORD(FLASH_CTL_STATUS_REG);
    
    while(tmp&0x1)
    {
        mbed_error_printf("aaaa\r\n");
        tmp = MREAD_WORD(FLASH_CTL_STATUS_REG);
    }
    return;
}

void spi_write_reset(void)
{
    unsigned int tmp;
    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x06);
    wait_busy_down();
    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x05);
    wait_busy_down();
    tmp = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);
    while((tmp & 0x1) == 1)
    {
        WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x05);
        wait_busy_down();
        tmp = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);
    }
}

void spi_wip_reset(void)
{
    unsigned int tmp;
    WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x05);
    wait_busy_down();
    tmp = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);
    while((tmp & 0x1) == 1)
    {
        WRITE_REG32(FLASH_CTL_TX_CMD_ADDR_REG, 0x05);
        wait_busy_down();
        tmp = MREAD_WORD(FLAHS_CTL_RX_FIFO_DATA_REG);
    }
}
#endif


