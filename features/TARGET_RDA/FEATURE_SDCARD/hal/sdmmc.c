#include "global_macros.h"
#include "sdmmc_reg.h"
#include "sdmmc.h"
#include "hal_sdmmc.h"
#include "stdio.h"

#define BOOL  BOOL_T
#define TRUE  BTRUE
#define FALSE BFALSE

//#define CONFIG_SDMMC_DEBUG

#ifdef CONFIG_SDMMC_DEBUG
#define SDMMC_DBG(fmt,args...) \
    rprintf("DBG: %s " fmt "\r",__PRETTY_FUNCTION__,##args)
#define SDMMC_ERR(fmt,args...) \
    rprintf("ERR: %s " fmt "\r",__PRETTY_FUNCTION__,##args)
#else
#define SDMMC_DBG(fmt,args...)
#define SDMMC_ERR(fmt,args...) \
    rprintf("ERR: %s " fmt "\r",__PRETTY_FUNCTION__,##args)
#endif

#define CONFIG_SYS_CLOCK_HZ         (40000000)
//#define CONFIG_SYS_CLOCK_HZ         (80000000)

// Command 8 things: cf spec Vers.2 section 4.3.13
#define MCD_CMD8_CHECK_PATTERN      0xaa
#define MCD_CMD8_VOLTAGE_SEL        (0x1<<8)
//#define MCD_CMD8_VOLTAGE_SEL        (0x2<<8)   // wngl, change to low voltage
#define MCD_OCR_HCS                 (1<<30)
#define MCD_OCR_CCS_MASK            (1<<30)

#define SECOND                    * 1000
// Timeouts for V1
#define MCD_CMD_TIMEOUT_V1        ( 2 SECOND )
#define MCD_RESP_TIMEOUT_V1       ( 2 SECOND )
#define MCD_TRAN_TIMEOUT_V1       ( 2 SECOND )
#define MCD_READ_TIMEOUT_V1       ( 5 SECOND )
#define MCD_WRITE_TIMEOUT_V1      ( 5 SECOND )

// Timeouts for V2
#define MCD_CMD_TIMEOUT_V2        ( 2 SECOND )
#define MCD_RESP_TIMEOUT_V2       ( 2 SECOND )
#define MCD_TRAN_TIMEOUT_V2       ( 2 SECOND )
#define MCD_READ_TIMEOUT_V2       ( 5 SECOND )
#define MCD_WRITE_TIMEOUT_V2      ( 5 SECOND )

#define MCD_SDMMC_OCR_TIMEOUT     ( 1 SECOND )  // the card is supposed to answer within 1s

// Spec Ver2 p96
#define MCD_SDMMC_OCR_VOLT_PROF_MASK  0x00ff8000


#define SDMMC_RESET_CTRL  (*((volatile unsigned int *)0x40000010UL))

PRIVATE UINT32 g_mcdOcrReg = MCD_SDMMC_OCR_VOLT_PROF_MASK;

/*rca address is high 16 bits, low 16 bits are stuff.You can set rca 0 or other digitals*/
PRIVATE UINT32 g_mcdRcaReg = 0x00000000;

PRIVATE UINT32            g_mcdBlockLen   = 512;
PRIVATE BOOL              g_mcdCardIsSdhc = FALSE;

PRIVATE MCD_STATUS_T      g_mcdStatus = MCD_STATUS_NOTOPEN_PRESENT;

/// Current in-progress transfer, if any.
PRIVATE HAL_SDMMC_TRANSFER_T g_mcdSdmmcTransfer =
                        {
                            .sysMemAddr = 0,
                            .sdCardAddr = 0,
                            .blockNum   = 0,
                            .blockSize  = 0,
                            .direction  = HAL_SDMMC_DIRECTION_WRITE,
                        };


PRIVATE MCD_CARD_VER g_mcdVer = MCD_CARD_V2;

PRIVATE UINT8 g_halSdmmcRead = 0;
PRIVATE UINT8 g_halSdmmcDatOvr = 0;

PRIVATE HWP_SDMMC_T *hwp_sdmmc = hwp_sdmmc1;
PRIVATE MCD_CSD_T mcd_csd;

PRIVATE int is_4wire_en = 0;

extern UINT32 rt_time_get(void);
#define get_time_ms rt_time_get

PRIVATE VOID mdelay(UINT32 msecs)
{
    UINT32 ms_start;
    ms_start = get_time_ms();
    //rprintf("%d\r\n", ms_start);
    while(get_time_ms() < (ms_start + msecs));
    //rprintf("%d\r\n", get_time_ms());
}

PRIVATE UINT32 hal_TimGetUpTime(VOID)
{
    return get_time_ms();
}

PRIVATE VOID hal_SdmmcOpen(UINT8 clk_adj)
{
    hwp_sdmmc->SDMMC_INT_MASK = 0x0;
    hwp_sdmmc->SDMMC_MCLK_ADJUST = clk_adj;// + (1 << 6); //Need check with ic
}

PRIVATE VOID hal_SdmmcClose(VOID)
{
    hwp_sdmmc->SDMMC_CONFIG = 0;
}

PRIVATE VOID hal_SdmmcSendCmd(HAL_SDMMC_CMD_T cmd, UINT32 arg, BOOL suspend)
{
    UINT32 configReg = 0;
    SDMMC_DBG("hwp_sdmmc:0x%x\n", hwp_sdmmc);
    hwp_sdmmc->SDMMC_CONFIG = 0x00000000;

    switch (cmd)
    {
        case HAL_SDMMC_CMD_GO_IDLE_STATE:
            configReg = SDMMC_SDMMC_SENDCMD;
            break;

        case HAL_SDMMC_CMD_ALL_SEND_CID:
            configReg = SDMMC_RSP_SEL_R2    | SDMMC_RSP_EN | SDMMC_SDMMC_SENDCMD; // 0x51
            break;

        case HAL_SDMMC_CMD_SEND_RELATIVE_ADDR:
            configReg = SDMMC_RSP_SEL_OTHER | SDMMC_RSP_EN | SDMMC_SDMMC_SENDCMD; // 0x11
            break;

        case HAL_SDMMC_CMD_SEND_IF_COND:
            configReg = SDMMC_RSP_SEL_OTHER | SDMMC_RSP_EN | SDMMC_SDMMC_SENDCMD; // 0x11
            break;

        case HAL_SDMMC_CMD_SET_DSR:
            configReg = SDMMC_SDMMC_SENDCMD;
            break;

        case HAL_SDMMC_CMD_SELECT_CARD:
            configReg = SDMMC_RSP_SEL_OTHER | SDMMC_RSP_EN | SDMMC_SDMMC_SENDCMD;
            break;

        case HAL_SDMMC_CMD_SEND_CSD                :
            configReg = SDMMC_RSP_SEL_R2    | SDMMC_RSP_EN | SDMMC_SDMMC_SENDCMD;
            break;

        case HAL_SDMMC_CMD_STOP_TRANSMISSION        :
            configReg = SDMMC_RSP_SEL_OTHER | SDMMC_RSP_EN | SDMMC_SDMMC_SENDCMD; // 0x11
            break;

        case HAL_SDMMC_CMD_SEND_STATUS            :
            configReg = SDMMC_RSP_SEL_OTHER | SDMMC_RSP_EN | SDMMC_SDMMC_SENDCMD;
            break;

        case HAL_SDMMC_CMD_SET_BLOCKLEN            :
            configReg = SDMMC_RSP_SEL_OTHER | SDMMC_RSP_EN | SDMMC_SDMMC_SENDCMD;
            break;

        case HAL_SDMMC_CMD_READ_SINGLE_BLOCK        :
            configReg =  SDMMC_RD_WT_SEL_READ
                       | SDMMC_RD_WT_EN
                       | SDMMC_RSP_SEL_OTHER
                       | SDMMC_RSP_EN
                       | SDMMC_SDMMC_SENDCMD; // 0x111
            break;

        case HAL_SDMMC_CMD_READ_MULT_BLOCK        :
            configReg =  SDMMC_S_M_SEL_MULTIPLE
                       | SDMMC_RD_WT_SEL_READ
                       | SDMMC_RD_WT_EN
                       | SDMMC_RSP_SEL_OTHER
                       | SDMMC_RSP_EN
                       | SDMMC_SDMMC_SENDCMD
                       | SDMMC_AUTO_CMD_EN; //0x511
            break;

        case HAL_SDMMC_CMD_WRITE_SINGLE_BLOCK    :
            configReg = SDMMC_RD_WT_SEL_WRITE
                       | SDMMC_RD_WT_EN
                       | SDMMC_RSP_SEL_OTHER
                       | SDMMC_RSP_EN
                       | SDMMC_SDMMC_SENDCMD
                       | 0xA000; // TODO: // 0xA311
            break;

        case HAL_SDMMC_CMD_WRITE_MULT_BLOCK        :
            configReg =  SDMMC_S_M_SEL_MULTIPLE
                       | SDMMC_RD_WT_SEL_WRITE
                       | SDMMC_RD_WT_EN
                       | SDMMC_RSP_SEL_OTHER
                       | SDMMC_RSP_EN
                       | SDMMC_SDMMC_SENDCMD
                       | SDMMC_AUTO_CMD_EN; // 0x711
            break;

        case HAL_SDMMC_CMD_APP_CMD                :
            configReg = SDMMC_RSP_SEL_OTHER | SDMMC_RSP_EN | SDMMC_SDMMC_SENDCMD; // 0x11
            break;

        case HAL_SDMMC_CMD_SET_BUS_WIDTH            :
        case HAL_SDMMC_CMD_SWITCH:
            configReg = SDMMC_RSP_SEL_OTHER | SDMMC_RSP_EN | SDMMC_SDMMC_SENDCMD; // 0x11
            break;

        case HAL_SDMMC_CMD_SEND_NUM_WR_BLOCKS    :
            configReg =  SDMMC_RD_WT_SEL_READ
                       | SDMMC_RD_WT_EN
                       | SDMMC_RSP_SEL_OTHER
                       | SDMMC_RSP_EN
                       | SDMMC_SDMMC_SENDCMD; // 0x111
            break;

        case HAL_SDMMC_CMD_SET_WR_BLK_COUNT        :
            configReg =  SDMMC_RSP_SEL_OTHER | SDMMC_RSP_EN | SDMMC_SDMMC_SENDCMD; // 0x11
            break;

        case HAL_SDMMC_CMD_MMC_SEND_OP_COND:
        case HAL_SDMMC_CMD_SEND_OP_COND:
            configReg =  SDMMC_RSP_SEL_R3    | SDMMC_RSP_EN | SDMMC_SDMMC_SENDCMD; // 0x31
            break;

        default:
            break;
    }

    hwp_sdmmc->SDMMC_CMD_INDEX = SDMMC_COMMAND(cmd);
    hwp_sdmmc->SDMMC_CMD_ARG   = SDMMC_ARGUMENT(arg);
    hwp_sdmmc->SDMMC_CONFIG    = configReg ;
    SDMMC_DBG("cmd:%d, arg:0x%x, configReg:0x%x, SDMMC_CONFIG:0x%x\n",
        SDMMC_COMMAND(cmd), SDMMC_ARGUMENT(arg), configReg, hwp_sdmmc->SDMMC_CONFIG);
}

PRIVATE BOOL hal_SdmmcNeedResponse(HAL_SDMMC_CMD_T cmd)
{
    BOOL ret = FALSE;
    switch (cmd)
    {
        case HAL_SDMMC_CMD_GO_IDLE_STATE:
        case HAL_SDMMC_CMD_SET_DSR:
        case HAL_SDMMC_CMD_STOP_TRANSMISSION:
            break;

        case HAL_SDMMC_CMD_ALL_SEND_CID:
        case HAL_SDMMC_CMD_SEND_RELATIVE_ADDR:
        case HAL_SDMMC_CMD_SEND_IF_COND:
        case HAL_SDMMC_CMD_SELECT_CARD:
        case HAL_SDMMC_CMD_SEND_CSD:
        case HAL_SDMMC_CMD_SEND_STATUS:
        case HAL_SDMMC_CMD_SET_BLOCKLEN:
        case HAL_SDMMC_CMD_READ_SINGLE_BLOCK:
        case HAL_SDMMC_CMD_READ_MULT_BLOCK:
        case HAL_SDMMC_CMD_WRITE_SINGLE_BLOCK:
        case HAL_SDMMC_CMD_WRITE_MULT_BLOCK:
        case HAL_SDMMC_CMD_APP_CMD:
        case HAL_SDMMC_CMD_SET_BUS_WIDTH:
        case HAL_SDMMC_CMD_SEND_NUM_WR_BLOCKS:
        case HAL_SDMMC_CMD_SET_WR_BLK_COUNT:
        case HAL_SDMMC_CMD_MMC_SEND_OP_COND:
        case HAL_SDMMC_CMD_SEND_OP_COND:
        case HAL_SDMMC_CMD_SWITCH:
            ret = TRUE;
            break;

        default:
            break;
    }
    return ret;
}

PRIVATE BOOL hal_SdmmcCmdDone(VOID)
{
    return (!(hwp_sdmmc->SDMMC_STATUS & SDMMC_NOT_SDMMC_OVER)) ? TRUE : FALSE;
}


#define MMC_MAX_CLK 20000000 /* 20 MHz */

PRIVATE VOID hal_SdmmcSetClk(UINT32 clock)
{
    UINT32 div;
    UINT32 sys_clk = 40000000U;

    if((*((volatile unsigned int *)0x40000018U)) & (0x01UL << 11)) {
        sys_clk = 80000000U;
    }
    // Update the divider takes care of the registers configuration
    if (clock > MMC_MAX_CLK) clock = MMC_MAX_CLK;

    // For ASIC: p_clk = sys_clk / 2; div = roundup(p_clk / (2*mclk)) - 1;
    div = ((sys_clk / clock) >> 2) - 1U;

    // For FPGA: p_clk = sys_clk; div = roundup(p_clk / (2*mclk)) - 1;
    //div = ((sys_clk / clock) >> 1) - 1U;

    // mclk   div  mclk  @ sys_clk=26MHz
    // 400K : 32   394Khz
    // 6.5M :  1   6.5Mhz
    hwp_sdmmc->SDMMC_TRANS_SPEED = SDMMC_SDMMC_TRANS_SPEED( div );
    SDMMC_DBG("SDMMC_TRANS_SPEED: 0x%x\n", hwp_sdmmc->SDMMC_TRANS_SPEED);
}

PRIVATE HAL_SDMMC_OP_STATUS_T hal_SdmmcGetOpStatus(VOID)
{
    return ((HAL_SDMMC_OP_STATUS_T)(UINT32)hwp_sdmmc->SDMMC_STATUS);
}

PRIVATE VOID hal_SdmmcGetResp(HAL_SDMMC_CMD_T cmd, UINT32* arg, BOOL suspend)
{
    // TODO Check in the spec for all the commands response types
    switch (cmd)
    {
        // If they require a response, it is cargoed
        // with a 32 bit argument.
        case HAL_SDMMC_CMD_GO_IDLE_STATE       :
        case HAL_SDMMC_CMD_SEND_RELATIVE_ADDR  :
        case HAL_SDMMC_CMD_SEND_IF_COND        :
        case HAL_SDMMC_CMD_SET_DSR               :
        case HAL_SDMMC_CMD_SELECT_CARD           :
        case HAL_SDMMC_CMD_STOP_TRANSMISSION   :
        case HAL_SDMMC_CMD_SEND_STATUS           :
        case HAL_SDMMC_CMD_SET_BLOCKLEN           :
        case HAL_SDMMC_CMD_READ_SINGLE_BLOCK   :
        case HAL_SDMMC_CMD_READ_MULT_BLOCK       :
        case HAL_SDMMC_CMD_WRITE_SINGLE_BLOCK  :
        case HAL_SDMMC_CMD_WRITE_MULT_BLOCK       :
        case HAL_SDMMC_CMD_APP_CMD               :
        case HAL_SDMMC_CMD_SET_BUS_WIDTH       :
        case HAL_SDMMC_CMD_SEND_NUM_WR_BLOCKS  :
        case HAL_SDMMC_CMD_SET_WR_BLK_COUNT       :
        case HAL_SDMMC_CMD_MMC_SEND_OP_COND    :
        case HAL_SDMMC_CMD_SEND_OP_COND           :
        case HAL_SDMMC_CMD_SWITCH:
            arg[0] = hwp_sdmmc->SDMMC_RESP_ARG3;
            arg[1] = 0;
            arg[2] = 0;
            arg[3] = 0;
            break;

        // Those response arguments are 128 bits
        case HAL_SDMMC_CMD_ALL_SEND_CID           :
        case HAL_SDMMC_CMD_SEND_CSD               :
            arg[0] = hwp_sdmmc->SDMMC_RESP_ARG0 << 1;
            arg[1] = hwp_sdmmc->SDMMC_RESP_ARG1;
            arg[2] = hwp_sdmmc->SDMMC_RESP_ARG2;
            arg[3] = hwp_sdmmc->SDMMC_RESP_ARG3;
            break;

        default:
            break;
    }
}

PRIVATE VOID hal_SdmmcEnterDataTransferMode(VOID)
{
    hwp_sdmmc->SDMMC_CONFIG |= SDMMC_RD_WT_EN;
}

PRIVATE VOID hal_SdmmcSetDataWidth(HAL_SDMMC_DATA_BUS_WIDTH_T width)
{
    switch (width)
    {
        case HAL_SDMMC_DATA_BUS_WIDTH_1:
            hwp_sdmmc->SDMMC_DATA_WIDTH = 1;
            break;

        case HAL_SDMMC_DATA_BUS_WIDTH_4:
            hwp_sdmmc->SDMMC_DATA_WIDTH = 4;
            break;

        default:
            break;
    }
}

PRIVATE int hal_SdmmcSetTransferInfo(HAL_SDMMC_TRANSFER_T* transfer)
{
    UINT32 length = 0;
    UINT32 lengthExp = 0;

    length =  transfer->blockSize;

    // The block size register,
    while (length != 1)
    {
        length >>= 1;
        lengthExp++;
    }

    SDMMC_DBG("size=%d count num=%d\n", lengthExp, transfer->blockNum);

    /* Configure amount of data */
    hwp_sdmmc->SDMMC_BLOCK_CNT  = SDMMC_SDMMC_BLOCK_CNT(transfer->blockNum);
    hwp_sdmmc->SDMMC_BLOCK_SIZE = SDMMC_SDMMC_BLOCK_SIZE(lengthExp);

    /* Configure Bytes reordering */
    hwp_sdmmc->apbi_ctrl_sdmmc = SDMMC_SOFT_RST_L | SDMMC_L_ENDIAN(1);
    SDMMC_DBG("size=%d bytes\n", transfer->blockNum*transfer->blockSize);

    // Record Channel used.
    if (transfer->direction == HAL_SDMMC_DIRECTION_READ || transfer->direction == HAL_SDMMC_DIRECTION_WRITE)
        g_halSdmmcRead = 1;

    return 0;
}

PRIVATE BOOL hal_SdmmcTransferDone(VOID)
{
    /*
     * The link is not full duplex. We check both the
     * direction, but only one can be in progress at a time.
     */
    if (g_halSdmmcRead > 0)
    {
        /* Operation in progress is a read. The EMMC module itself can know it has finished*/
        if((0 == g_halSdmmcDatOvr) && (hwp_sdmmc->SDMMC_INT_STATUS & SDMMC_DAT_OVER_INT)) {
            g_halSdmmcDatOvr = 1;
        }

        if ((1 == g_halSdmmcDatOvr) && hal_SdmmcCmdDone())
        {
            /* Transfer is over and clear the interrupt source.*/
            hwp_sdmmc->SDMMC_INT_CLEAR = SDMMC_DAT_OVER_CL;

            g_halSdmmcRead = 0;
            g_halSdmmcDatOvr = 0;

            /*Clear the FIFO .*/
            hwp_sdmmc->apbi_ctrl_sdmmc = 0 | SDMMC_L_ENDIAN(1);
            hwp_sdmmc->apbi_ctrl_sdmmc = SDMMC_SOFT_RST_L | SDMMC_L_ENDIAN(1);
            //hwp_sdmmc->SDDMA_CONTROLER = SDMMC_SDDMA_DISALBE | SDMMC_FLUSH;

            return TRUE;
        }
    }

    // there's still data running through a pipe (or no transfer in progress ...)
    return FALSE;
}

PRIVATE void hal_SdmmcStopTransfer(HAL_SDMMC_TRANSFER_T* transfer)
{
    /* Configure amount of data */
    hwp_sdmmc->SDMMC_BLOCK_CNT  = SDMMC_SDMMC_BLOCK_CNT(0);
    hwp_sdmmc->SDMMC_BLOCK_SIZE = SDMMC_SDMMC_BLOCK_SIZE(0);

    g_halSdmmcRead = 0;

    //hwp_sdmmc->SDDMA_CONTROLER = SDMMC_SDDMA_DISALBE | SDMMC_FLUSH;
    /*  Put the FIFO in reset state. */
    //rprintf("2 apbi_ctrl_sdmmc:0 | SDMMC_L_ENDIAN(1);\n");
    hwp_sdmmc->apbi_ctrl_sdmmc = 0 | SDMMC_L_ENDIAN(1);
    hwp_sdmmc->apbi_ctrl_sdmmc = SDMMC_SOFT_RST_L | SDMMC_L_ENDIAN(1);
#if 0
    if (transfer->direction == HAL_SDMMC_DIRECTION_READ)
    {
        hal_IfcChannelFlush(HAL_IFC_SDMMC_RX, g_halSdmmcReadCh);
        while(!hal_IfcChannelIsFifoEmpty(HAL_IFC_SDMMC_RX, g_halSdmmcReadCh));
        hal_IfcChannelRelease(HAL_IFC_SDMMC_RX, g_halSdmmcReadCh);
        g_halSdmmcReadCh = HAL_UNKNOWN_CHANNEL;
    }
#endif
}

PRIVATE BOOL hal_SdmmcIsBusy(VOID)
{
    if ((hwp_sdmmc->SDMMC_STATUS & (SDMMC_NOT_SDMMC_OVER | SDMMC_BUSY | SDMMC_DL_BUSY)) != 0)
    {
        /* SDMMc is busy doing something.*/
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

// Wait for a command to be done or timeouts
PRIVATE MCD_ERR_T mcd_SdmmcWaitCmdOver(VOID)
{
    UINT64 startTime = hal_TimGetUpTime();
    UINT64 time_out;

    time_out =  (MCD_CARD_V1 == g_mcdVer) ? MCD_CMD_TIMEOUT_V1:MCD_CMD_TIMEOUT_V2;

    while(hal_TimGetUpTime() - startTime < time_out && !hal_SdmmcCmdDone());

    if (!hal_SdmmcCmdDone())
    {
        SDMMC_ERR("timeout\n");
        return MCD_ERR_CARD_TIMEOUT;
    }
    else
    {
        return MCD_ERR_NO;
    }
}

PRIVATE MCD_ERR_T mcd_SdmmcWaitResp(VOID)
{
    HAL_SDMMC_OP_STATUS_T status = hal_SdmmcGetOpStatus();
    UINT64 startTime = hal_TimGetUpTime();
    UINT64 rsp_time_out;

    rsp_time_out =  (MCD_CARD_V1 == g_mcdVer) ? MCD_RESP_TIMEOUT_V1:MCD_RESP_TIMEOUT_V2;

    while(hal_TimGetUpTime() - startTime < rsp_time_out &&status.fields.noResponseReceived)
    {
        status = hal_SdmmcGetOpStatus();
        osDelay(100);
    }

    if (status.fields.noResponseReceived)
    {
        SDMMC_ERR("No Response\n");
        return MCD_ERR_CARD_NO_RESPONSE;
    }

    if(status.fields.responseCrcError)
    {
        SDMMC_ERR("Response CRC\n");
        return MCD_ERR_CARD_RESPONSE_BAD_CRC;
    }

    return MCD_ERR_NO;
}

PRIVATE MCD_ERR_T mcd_SdmmcReadCheckCrc(VOID)
{
    HAL_SDMMC_OP_STATUS_T operationStatus;
    operationStatus = hal_SdmmcGetOpStatus();

    // 0 means no CRC error during transmission
    if (operationStatus.fields.dataError != 0)
    {
        SDMMC_ERR("Bad CRC, 0x%08X\n", operationStatus.reg);
        return MCD_ERR_CARD_RESPONSE_BAD_CRC;
    }
    else
    {
        return MCD_ERR_NO;
    }
}

PRIVATE MCD_ERR_T mcd_SdmmcSendCmd(HAL_SDMMC_CMD_T cmd, UINT32 arg,
                                  UINT32* resp, BOOL suspend)
{
    MCD_ERR_T errStatus = MCD_ERR_NO;
    MCD_CARD_STATUS_T cardStatus = {0};
    UINT32  cmd55Response[4] = {0, 0, 0, 0};
    if (cmd & HAL_SDMMC_ACMD_SEL)
    {
        // This is an application specific command,
        // we send the CMD55 first, response r1
        hal_SdmmcSendCmd(HAL_SDMMC_CMD_APP_CMD, g_mcdRcaReg, FALSE);

        // Wait for command over
        if (MCD_ERR_CARD_TIMEOUT == mcd_SdmmcWaitCmdOver())
        {
            SDMMC_ERR("cmd55 timeout\n");
            return MCD_ERR_CARD_TIMEOUT;
        }

        // Wait for response
        if (hal_SdmmcNeedResponse(HAL_SDMMC_CMD_APP_CMD))
        {
            errStatus = mcd_SdmmcWaitResp();
        }
        if (MCD_ERR_NO != errStatus)
        {
            SDMMC_ERR("cmd55 err=%d\n", errStatus);
            return errStatus;
        }

        // Fetch response
        hal_SdmmcGetResp(HAL_SDMMC_CMD_APP_CMD, cmd55Response, FALSE);

        cardStatus.reg = cmd55Response[0];
        if(HAL_SDMMC_CMD_SEND_OP_COND == cmd) // for some special card
        {
           //if (!(cardStatus.fields.readyForData) || !(cardStatus.fields.appCmd))
           if (!(cardStatus.fields.appCmd))
            {
                SDMMC_ERR("cmd55(acmd41) status\n"); // what error is this?
                return MCD_ERR;
            }
        }
        else
        {
            if (!(cardStatus.fields.readyForData) || !(cardStatus.fields.appCmd))
            {
                SDMMC_ERR("cmd55 status\n"); // what error is this?
                return MCD_ERR;
            }
        }
    }

    // Send proper command. If it was an ACMD, the CMD55 have just been sent.
    hal_SdmmcSendCmd(cmd, arg, suspend);

    // Wait for command to be sent
    errStatus = mcd_SdmmcWaitCmdOver();

    if (MCD_ERR_CARD_TIMEOUT == errStatus)
    {
        SDMMC_ERR("%s send timeout\n",
                  (cmd & HAL_SDMMC_ACMD_SEL)? "ACMD": "CMD");
        return MCD_ERR_CARD_TIMEOUT;
    }

    // Wait for response and get its argument
    if (hal_SdmmcNeedResponse(cmd))
    {
        errStatus = mcd_SdmmcWaitResp();
    }

    if (MCD_ERR_NO != errStatus)
    {
        SDMMC_ERR("%s Response err=%d\n",
                  (cmd & HAL_SDMMC_ACMD_SEL)? "ACMD": "CMD", errStatus);
        return errStatus;
    }

    // Fetch response
    hal_SdmmcGetResp(cmd, resp, FALSE);

    return MCD_ERR_NO;
}

#define MCD_CSD_VERSION_1       0
#define MCD_CSD_VERSION_2       1

PRIVATE MCD_ERR_T mcd_SdmmcInitCsd(MCD_CSD_T* csd, UINT32* csdRaw)
{
    // CF SD spec version2, CSD version 1 ?
    csd->csdStructure       = (UINT8)((csdRaw[3]&(0x3U<<30))>>30);

    // Byte 47 to 75 are different depending on the version
    // of the CSD srtucture.
    csd->specVers           = (UINT8)((csdRaw[3]&(0xf<26))>>26);
    csd->taac               = (UINT8)((csdRaw[3]&(0xff<<16))>>16);
    csd->nsac               = (UINT8)((csdRaw[3]&(0xff<<8))>>8);
    csd->tranSpeed          = (UINT8)(csdRaw[3]&0xff);

    csd->ccc                = (csdRaw[2]&(0xfffU<<20))>>20;
    csd->readBlLen          = (UINT8)((csdRaw[2]&(0xf<<16))>>16);
    csd->readBlPartial      = (((csdRaw[2]&(0x1<<15))>>15) != 0U) ? TRUE : FALSE;
    csd->writeBlkMisalign   = (((csdRaw[2]&(0x1<<14))>>14) != 0U) ? TRUE : FALSE;
    csd->readBlkMisalign    = (((csdRaw[2]&(0x1<<13))>>13) != 0U) ? TRUE : FALSE;
    csd->dsrImp             = (((csdRaw[2]&(0x1<<12))>>12) != 0U) ? TRUE : FALSE;

    if (csd->csdStructure == MCD_CSD_VERSION_1)
    {
        csd->cSize              = (csdRaw[2]&0x3ff)<<2;

        csd->cSize              = csd->cSize|((csdRaw[1]&(0x3U<<30))>>30);
        csd->vddRCurrMin        = (UINT8)((csdRaw[1]&(0x7<<27))>>27);
        csd->vddRCurrMax        = (UINT8)((csdRaw[1]&(0x7<<24))>>24);
        csd->vddWCurrMin        = (UINT8)((csdRaw[1]&(0x7<<21))>>21);
        csd->vddWCurrMax        = (UINT8)((csdRaw[1]&(0x7<<18))>>18);
        csd->cSizeMult          = (UINT8)((csdRaw[1]&(0x7<<15))>>15);

        // Block number: cf Spec Version 2 page 103 (116).
        csd->blockNumber        = (csd->cSize + 1)<<(csd->cSizeMult + 2);
    }
    else
    {
        // csd->csdStructure == MCD_CSD_VERSION_2
        csd->cSize = ((csdRaw[2]&0x3f))|((csdRaw[1]&(0xffffU<<16))>>16);

        // Other fields are undefined --> zeroed
        csd->vddRCurrMin = 0;
        csd->vddRCurrMax = 0;
        csd->vddWCurrMin = 0;
        csd->vddWCurrMax = 0;
        csd->cSizeMult   = 0;

        // Block number: cf Spec Version 2 page 109 (122).
        csd->blockNumber        = (csd->cSize + 1) * 1024;
        //should check incompatible size and return MCD_ERR_UNUSABLE_CARD;
    }

    csd->eraseBlkEnable     = (UINT8)((csdRaw[1]&(0x1<<14))>>14);
    csd->sectorSize         = (UINT8)((csdRaw[1]&(0x7f<<7))>>7);
    csd->wpGrpSize          = (UINT8)(csdRaw[1]&0x7f);

    csd->wpGrpEnable        = (((csdRaw[0]&(0x1U<<31))>>31) != 0U) ? TRUE : FALSE;
    csd->r2wFactor          = (UINT8)((csdRaw[0]&(0x7<<26))>>26);
    csd->writeBlLen         = (UINT8)((csdRaw[0]&(0xf<<22))>>22);
    csd->writeBlPartial     = (((csdRaw[0]&(0x1<<21))>>21) != 0U) ? TRUE : FALSE;
    csd->fileFormatGrp      = (((csdRaw[0]&(0x1<<15))>>15) != 0U) ? TRUE : FALSE;
    csd->copy               = (((csdRaw[0]&(0x1<<14))>>14) != 0U) ? TRUE : FALSE;
    csd->permWriteProtect   = (((csdRaw[0]&(0x1<<13))>>13) != 0U) ? TRUE : FALSE;
    csd->tmpWriteProtect    = (((csdRaw[0]&(0x1<<12))>>12) != 0U) ? TRUE : FALSE;
    csd->fileFormat         = (UINT8)((csdRaw[0]&(0x3<<10))>>10);
    csd->crc                = (UINT8)((csdRaw[0]&(0x7f<<1))>>1);

    return MCD_ERR_NO;
}

PRIVATE MCD_ERR_T mcd_ReadCsd(MCD_CSD_T* mcdCsd)
{
    MCD_ERR_T errStatus = MCD_ERR_NO;
    UINT32 response[4];
    //UINT32            g_mcdNbBlock    = 0;
    // Get card CSD
    errStatus = mcd_SdmmcSendCmd(HAL_SDMMC_CMD_SEND_CSD, g_mcdRcaReg, response, FALSE);
    if (errStatus == MCD_ERR_NO)
    {
        errStatus = mcd_SdmmcInitCsd(mcdCsd, response);
    }

    // Store it localy
    // FIXME: Is this real ? cf Physical Spec version 2
    // page 59 (72) about CMD16 : default block length
    // is 512 bytes. Isn't 512 bytes a good block
    // length ? And I quote : "In both cases, if block length is set larger
    // than 512Bytes, the card sets the BLOCK_LEN_ERROR bit."
    g_mcdBlockLen = (1 << mcdCsd->readBlLen);
    if (g_mcdBlockLen > 512)
    {
        g_mcdBlockLen = 512;
    }
    //g_mcdNbBlock  = mcdCsd->blockNumber * ((1 << mcdCsd->readBlLen)/g_mcdBlockLen);

    return errStatus;
}

PRIVATE MCD_ERR_T mcd_SdmmcTranState(UINT32 iter)
{
    UINT32 cardResponse[4] = {0, 0, 0, 0};
    MCD_ERR_T errStatus = MCD_ERR_NO;
    MCD_CARD_STATUS_T cardStatusTranState;
    UINT64 startTime = hal_TimGetUpTime();
    UINT64 time_out;
    // Using reg to clear all bit of the bitfields that are not
    // explicitly set.
    cardStatusTranState.reg = 0;
    cardStatusTranState.fields.readyForData = 1;
    cardStatusTranState.fields.currentState = MCD_CARD_STATE_TRAN;

    while(1)
    {
        //SDMMC_DBG("CMD13, Set Trans State\n");

        errStatus = mcd_SdmmcSendCmd(HAL_SDMMC_CMD_SEND_STATUS, g_mcdRcaReg, cardResponse, FALSE);
        if (errStatus != MCD_ERR_NO)
        {
            SDMMC_ERR("CMD13, Fail(%d)\n", errStatus);
            // error while sending the command
            return MCD_ERR;
        }
        else if (cardResponse[0] == cardStatusTranState.reg)
        {
            SDMMC_DBG("CMD13, Done\n");
            // the status is the expected one - success
            return MCD_ERR_NO;
        }
        else
        {
            // try again
            // check for timeout
            time_out =  (MCD_CARD_V1 == g_mcdVer) ? MCD_CMD_TIMEOUT_V1:MCD_CMD_TIMEOUT_V2;
            if (hal_TimGetUpTime() - startTime >  time_out )
            {
                SDMMC_ERR("CMD13, Timeout\n");
                return MCD_ERR;
            }
        }
    }
}

PUBLIC MCD_ERR_T mcd_Open(MCD_CSD_T* mcdCsd, MCD_CARD_VER mcdVer)
{
    MCD_ERR_T                  errStatus   = MCD_ERR_NO;
    UINT32                     response[4] = {0, 0, 0, 0};
    MCD_CARD_STATUS_T          cardStatus  = {0};
    BOOL                       isMmc       = FALSE;
    HAL_SDMMC_DATA_BUS_WIDTH_T dataBusWidth = HAL_SDMMC_DATA_BUS_WIDTH_1;
    UINT64 startTime = 0;
    //UINT32 tran_time_out;

    SDMMC_DBG("Enter\n");

    // RCA = 0x0000 for card identification phase.
    g_mcdRcaReg = 0;
    // assume it's not an SDHC card
    g_mcdCardIsSdhc = FALSE;
    g_mcdOcrReg = MCD_SDMMC_OCR_VOLT_PROF_MASK;

    SDMMC_RESET_CTRL &= ~(0x01UL << 17);
    mdelay(1);
    SDMMC_RESET_CTRL |= (0x01UL << 17);

    /* Disable all interrupt, and delay mclk output, using 0 pclk */
    hal_SdmmcOpen(0x00);

    /* Set mclk output <= 400KHz */
    hal_SdmmcSetClk(400000);
    /*
      1. wait for sd mclk stable
      2. must be wait for >= 2ms: 1ms + >= 76 clk, refer to sd spec 2.0 page 129.
     */
    mdelay(1);
    SDMMC_DBG("CMD0\n");
    // Send Power On command
    errStatus = mcd_SdmmcSendCmd(HAL_SDMMC_CMD_GO_IDLE_STATE, 0, response, FALSE);
    if (MCD_ERR_NO != errStatus)
    {
        SDMMC_ERR("No card\n");
        g_mcdStatus = MCD_STATUS_NOTPRESENT;
        hal_SdmmcClose();

        return errStatus;
    }

    SDMMC_DBG("CMD8\n");

    mdelay(100);
    // Check if the card is a spec vers.2 one, response is r7
    errStatus = mcd_SdmmcSendCmd(HAL_SDMMC_CMD_SEND_IF_COND, (MCD_CMD8_VOLTAGE_SEL | MCD_CMD8_CHECK_PATTERN), response, FALSE);
    if (MCD_ERR_NO != errStatus)
    {
        SDMMC_ERR("CMD8 err=%d\n", errStatus);
    }
    else
    {
        SDMMC_DBG("CMD8 Done (support spec v2.0) response=0x%8x\n", response[0]);
        SDMMC_DBG(" hwp_sdmmc->SDMMC_MCLK_ADJUST: 0x%x\n",  hwp_sdmmc->SDMMC_MCLK_ADJUST);
        // This card comply to the SD spec version 2. Is it compatible with the
        // proposed voltage, and is it an high capacity one ?
//        if (response[0] != (MCD_CMD8_VOLTAGE_SEL | MCD_CMD8_CHECK_PATTERN))
        if ((response[0] & 0xff) !=  MCD_CMD8_CHECK_PATTERN)

        {
            SDMMC_ERR("CMD8, Not Supported\n");

            // Bad pattern or unsupported voltage.
            hal_SdmmcClose();
            g_mcdStatus = MCD_STATUS_NOTPRESENT;
            //g_mcdVer = MCD_CARD_V1;
            return MCD_ERR_UNUSABLE_CARD;
        }
        else
        {
            SDMMC_DBG("CMD8, Supported\n");
            g_mcdOcrReg |= MCD_OCR_HCS; //ccs = 1
        }
    }

    // TODO HCS mask bit to ACMD 41 if high capacity
    // Send OCR, as long as the card return busy
    startTime = hal_TimGetUpTime();
    while(1)
    {
        if(hal_TimGetUpTime() - startTime > MCD_SDMMC_OCR_TIMEOUT )
        {
            SDMMC_ERR("ACMD41, Retry Timeout\n");
            hal_SdmmcClose();
            g_mcdStatus = MCD_STATUS_NOTPRESENT;
            return MCD_ERR;
        }

        SDMMC_DBG("ACMD41, response r3\n");
        errStatus = mcd_SdmmcSendCmd(HAL_SDMMC_CMD_SEND_OP_COND, g_mcdOcrReg, response, FALSE);
        if (errStatus == MCD_ERR_CARD_NO_RESPONSE)
        {
            SDMMC_ERR("ACMD41, No Response, MMC Card?\n");
            isMmc = TRUE;
            break;
        }
        SDMMC_DBG("ACMD41 Done, response = 0x%8x\n", response[0]);

        // Bit 31 is power up busy status bit(pdf spec p. 109)
        g_mcdOcrReg = (response[0] & 0x7fffffff);
        // Power up busy bit is set to 1,
        if (response[0] & 0x80000000)
        {
            //SDMMC_DBG("ACMD41, PowerUp done\n");
            // Version 2?
            //if((g_mcdOcrReg & MCD_OCR_HCS) == MCD_OCR_HCS) // no need to check, host always supports SDHC/SDXC
            //{
                // Card is V2: check for high capacity
                if (response[0] & MCD_OCR_CCS_MASK)
                {
                    g_mcdCardIsSdhc = TRUE;
                    SDMMC_DBG("Card is SDHC/SDXC\n");
                }
                else
                {
                    g_mcdCardIsSdhc = FALSE;
                    SDMMC_DBG("Card is SDSC\n");
                }
            //}
            //else {
            //    SDMMC_DBG("Host supports SDSC only\n");
            //}
            SDMMC_DBG("Inserted Card is a SD card\n");
            break;
        }
    }

    if (isMmc) //Not support ACMD41
    {
        SDMMC_DBG("MMC Card\n");
        while(1)
        {
            if(hal_TimGetUpTime() - startTime > MCD_SDMMC_OCR_TIMEOUT )
            {
                hal_SdmmcClose();
                g_mcdStatus = MCD_STATUS_NOTPRESENT;
                return MCD_ERR;
            }

            errStatus = mcd_SdmmcSendCmd(HAL_SDMMC_CMD_MMC_SEND_OP_COND, g_mcdOcrReg, response, FALSE);
            if (errStatus == MCD_ERR_CARD_NO_RESPONSE)
            {
                hal_SdmmcClose();
                g_mcdStatus = MCD_STATUS_NOTPRESENT;
                return MCD_ERR;
            }

            // Bit 31 is power up busy status bit(pdf spec p. 109)
            g_mcdOcrReg = (response[0] & 0x7fffffff);

            // Power up busy bit is set to 1,
            // we can continue ...
            if (response[0] & 0x80000000)
            {
                //30bit: 1: sector mode, > 2G 0: BYTE mode <=2G
                g_mcdCardIsSdhc =  (response[0] & 0x40000000)> 0 ? TRUE : FALSE;
                if (g_mcdCardIsSdhc)
                    SDMMC_DBG("Card is MMC > 2GB\n");
                else
                    SDMMC_DBG("Card is MMC <= 2GB\n");
                break;
            }
        }
    }

    SDMMC_DBG("CMD2\n");

    // Get the CID of the card.
    errStatus = mcd_SdmmcSendCmd(HAL_SDMMC_CMD_ALL_SEND_CID, 0, response, FALSE);
    if(MCD_ERR_NO != errStatus)
    {
        SDMMC_ERR("CMD2 Fail\n");
        hal_SdmmcClose();
        g_mcdStatus = MCD_STATUS_NOTPRESENT;
        return errStatus;
    }

    SDMMC_DBG("CMD3\n");

    // Get card RCA
    if(isMmc) //set rca to card and nor get this.
    g_mcdRcaReg = 0x10000;
    errStatus = mcd_SdmmcSendCmd(HAL_SDMMC_CMD_SEND_RELATIVE_ADDR, g_mcdRcaReg, response, FALSE);
    if (MCD_ERR_NO != errStatus)
    {
        SDMMC_ERR("CMD3 Fail\n");
        hal_SdmmcClose();
        g_mcdStatus = MCD_STATUS_NOTPRESENT;
        return errStatus;
    }

    // Spec Ver 2 pdf p. 81 - rca are the 16 upper bit of this
    // R6 answer. (lower bits are stuff bits)
   if(isMmc == FALSE) {
        g_mcdRcaReg = response[0] & 0xffff0000;
        SDMMC_DBG("CMD3 Done, response=0x%8x, rca=0x%6x\n",
                  response[0], g_mcdRcaReg);
    }

    // Get card CSD
    errStatus = mcd_ReadCsd(mcdCsd);
    if (errStatus != MCD_ERR_NO)
    {
        SDMMC_DBG("Because Get CSD, Initialize Failed\n");
        hal_SdmmcClose();
        g_mcdStatus = MCD_STATUS_NOTPRESENT;
        return errStatus;
    }

    // If possible, set the DSR
    if (mcdCsd->dsrImp)
    {
        errStatus = mcd_SdmmcSendCmd(HAL_SDMMC_CMD_SET_DSR, 0, response, FALSE);
        if (errStatus != MCD_ERR_NO)
        {
            SDMMC_DBG("Because Set DSR, Initialize Failed\n");
            hal_SdmmcClose();
            g_mcdStatus = MCD_STATUS_NOTPRESENT;
            return errStatus;
        }
    }

    SDMMC_DBG("CMD7\n");
    // Select the card
    errStatus = mcd_SdmmcSendCmd(HAL_SDMMC_CMD_SELECT_CARD, g_mcdRcaReg, response, FALSE);
    if (errStatus != MCD_ERR_NO)
    {
        SDMMC_ERR("CMD7 Fail\n");
        hal_SdmmcClose();
        g_mcdStatus = MCD_STATUS_NOTPRESENT;
        return errStatus;
    }
    // That command returns the card status, we check we're in data mode.
    cardStatus.reg = response[0];
    SDMMC_DBG("CMD7 Done, cardStatus=0x%8x\n", response[0]);

    if(!(cardStatus.fields.readyForData))
    {
        SDMMC_ERR("Ready for Data check Fail\n");
        hal_SdmmcClose();
        g_mcdStatus = MCD_STATUS_NOTPRESENT;
        return MCD_ERR;
    }

    if (0 != is_4wire_en) {
        dataBusWidth = HAL_SDMMC_DATA_BUS_WIDTH_4;
    }

    errStatus = mcd_SdmmcSendCmd(HAL_SDMMC_CMD_SET_BUS_WIDTH, dataBusWidth,
                                  response, FALSE);
    if (errStatus != MCD_ERR_NO)
    {
        SDMMC_ERR("Because Set Bus, Initialize Failed");
        hal_SdmmcClose();//pmd_EnablePower(PMD_POWER_SDMMC, FALSE);
        g_mcdStatus = MCD_STATUS_NOTPRESENT;
        return errStatus;
    }

    // That command returns the card status, in tran state ?
    cardStatus.reg = response[0];
    if (   !(cardStatus.fields.appCmd)
        || !(cardStatus.fields.readyForData)
        || (cardStatus.fields.currentState != MCD_CARD_STATE_TRAN))
    {
        SDMMC_ERR("ACMD6 status=%0x", cardStatus.reg);
        hal_SdmmcClose();//pmd_EnablePower(PMD_POWER_SDMMC, FALSE);
        g_mcdStatus = MCD_STATUS_NOTPRESENT;
        return MCD_ERR;
    }

    hal_SdmmcSetDataWidth(dataBusWidth);

    SDMMC_DBG("CMD16 - set block len g_mcdBlockLen=%d\n", g_mcdBlockLen);

    // Configure the block lenght
    errStatus = mcd_SdmmcSendCmd(HAL_SDMMC_CMD_SET_BLOCKLEN, g_mcdBlockLen, response, FALSE);
    if (errStatus != MCD_ERR_NO)
    {
        SDMMC_ERR("CMD16, SET_BLOCKLEN fail\n");
        hal_SdmmcClose();
        g_mcdStatus = MCD_STATUS_NOTPRESENT;
        return errStatus;
    }

#if 1
    // That command returns the card status, in tran state ?
    cardStatus.reg = response[0];
    {
        MCD_CARD_STATUS_T expectedCardStatus;
        expectedCardStatus.reg  = 0;
        expectedCardStatus.fields.readyForData = 1;
        expectedCardStatus.fields.currentState = MCD_CARD_STATE_TRAN;

        if (cardStatus.reg != expectedCardStatus.reg)
        {
            SDMMC_ERR("CMD16 status Fail\n");
            hal_SdmmcClose();
            g_mcdStatus = MCD_STATUS_NOTPRESENT;
            return MCD_ERR;
        }
    }
#endif

    // TODO: DELETE!!!
    hal_SdmmcEnterDataTransferMode();

    /* For cards, fpp = 25MHz for sd, fpp = 50MHz, for sdhc */
#define WORKING_CLK_FREQ    10000000  // 5000000, 6600000, 10000000, 20000000
    SDMMC_DBG("Set Clock: %d\n", WORKING_CLK_FREQ);
    hal_SdmmcSetClk(WORKING_CLK_FREQ);
#undef WORKING_CLK_FREQ

    mdelay(1);

    g_mcdStatus = MCD_STATUS_OPEN;
    g_mcdVer = mcdVer;

#if 0
    tran_time_out = (MCD_CARD_V1 == g_mcdVer) ? MCD_TRAN_TIMEOUT_V1:MCD_TRAN_TIMEOUT_V2;
    // Check that the card is in tran (Transmission) state.
    if (MCD_ERR_NO != mcd_SdmmcTranState(tran_time_out))
    // 5200000, 0, initially, that is to say rougly 0.1 sec ?
    {
        SDMMC_ERR("trans state timeout\n");
        return MCD_ERR_CARD_TIMEOUT;
    }
#endif

    SDMMC_DBG("Done\n");

    return MCD_ERR_NO;
}

PUBLIC MCD_ERR_T mcd_Close(VOID)
{
    MCD_ERR_T errStatus = MCD_ERR_NO;

    // Don't close the MCD driver if a transfer is in progress,
    // and be definitive about it:
    if (hal_SdmmcIsBusy() == TRUE)
    {
        SDMMC_DBG("Attempt to close MCD while a transfer is in progress");
    }

    // Brutal force stop current transfer, if any.
    hal_SdmmcStopTransfer(&g_mcdSdmmcTransfer);

    // Close the SDMMC module
    hal_SdmmcClose();

    g_mcdStatus = MCD_STATUS_NOTOPEN_PRESENT; // without GPIO

    return errStatus;
}

PRIVATE MCD_ERR_T mcd_SdmmcMltBlkRead_Polling(UINT8* pRead, UINT32 startBlock, UINT32 blockNum)
{
    UINT32                  cardResponse[4]     = {0, 0, 0, 0};
    MCD_ERR_T               errStatus           = MCD_ERR_NO;
    HAL_SDMMC_CMD_T         readCmd;
    MCD_CARD_STATUS_T cardStatusTranState;
    cardStatusTranState.reg = 0;
    cardStatusTranState.fields.readyForData = 1;
    cardStatusTranState.fields.currentState = MCD_CARD_STATE_TRAN;
    UINT64 startTime;
    UINT64 tran_time_out;
    UINT64 read_time_out;
    UINT32 bufSize;
    UINT32 bufIdx;
    REG32 *regStatus2  = &(hwp_sdmmc->SDMMC_STATUS2);
    REG32 *regTxRxFifo = &(hwp_sdmmc->APBI_FIFO_TxRx);

    SDMMC_DBG("Enter\n");

    g_mcdSdmmcTransfer.sysMemAddr = (UINT8 *)pRead;
    g_mcdSdmmcTransfer.sdCardAddr = (UINT8 *)startBlock;
    g_mcdSdmmcTransfer.blockNum   = blockNum;
    g_mcdSdmmcTransfer.blockSize  = g_mcdBlockLen;
    g_mcdSdmmcTransfer.direction  = HAL_SDMMC_DIRECTION_READ;

    // Command are different for reading one or several blocks of data
    if (blockNum == 1)
        readCmd = HAL_SDMMC_CMD_READ_SINGLE_BLOCK;
    else
        readCmd = HAL_SDMMC_CMD_READ_MULT_BLOCK;

    // Initiate data migration through Ifc.
    if (hal_SdmmcSetTransferInfo(&g_mcdSdmmcTransfer) != 0)
    {
        SDMMC_ERR("write sd no ifc channel\n");
        return MCD_ERR_DMA_BUSY;
    }

    SDMMC_DBG("send command\n");
    // Initiate data migration of multiple blocks through SD bus.
    errStatus = mcd_SdmmcSendCmd(readCmd,
                                  ((g_mcdCardIsSdhc == TRUE) ? startBlock : (startBlock << 9)),
                                  cardResponse,
                                  FALSE);
    if (errStatus != MCD_ERR_NO)
    {
        SDMMC_ERR("send command err=%d\n", errStatus);
        hal_SdmmcStopTransfer(&g_mcdSdmmcTransfer);
        return MCD_ERR_CMD;
    }

    if (cardResponse[0] != cardStatusTranState.reg)
    {
        SDMMC_ERR("command %d response, 0x%x\n", readCmd, cardResponse[0]);
        hal_SdmmcStopTransfer(&g_mcdSdmmcTransfer);
        return MCD_ERR;
    }
    SDMMC_DBG("send command done\n");

    bufSize = blockNum << 9;  // Total buffer size in bytes
    bufIdx = 0;
    /*while(bufIdx < bufSize) {
        UINT32 regVal;
        while((*regStatus2 & 0x0700UL) == 0UL);
        regVal = *regTxRxFifo;
        pRead[bufIdx]     = (regVal >> 24) & 0xFF;
        pRead[bufIdx + 1] = (regVal >> 16) & 0xFF;
        pRead[bufIdx + 2] = (regVal >>  8) & 0xFF;
        pRead[bufIdx + 3] =  regVal        & 0xFF;
        bufIdx += 4;
    }*/
    while(bufIdx < bufSize) {
        startTime = hal_TimGetUpTime();
        while((*regStatus2 & 0x0700UL) == 0UL) {
            if(hal_TimGetUpTime() - startTime > 1000) {
                SDMMC_ERR("timeout, STATUS2\n");
                hal_SdmmcStopTransfer(&g_mcdSdmmcTransfer);
                return MCD_ERR_CARD_TIMEOUT;
            }
        }
        *((UINT32 *)(&(pRead[bufIdx]))) = *regTxRxFifo;
        bufIdx += 4;
    }

    // Wait
    startTime = hal_TimGetUpTime();
    read_time_out =  (MCD_CARD_V1 == g_mcdVer) ? MCD_READ_TIMEOUT_V1:MCD_READ_TIMEOUT_V2;
    while(!hal_SdmmcTransferDone())
    {
        if (hal_TimGetUpTime() - startTime > (read_time_out*blockNum))
        {
            SDMMC_ERR("timeout, INT_STATUS=0x%08X\n", hwp_sdmmc->SDMMC_INT_STATUS);
            // Abort the transfert.
            hal_SdmmcStopTransfer(&g_mcdSdmmcTransfer);
            return MCD_ERR_CARD_TIMEOUT;
        }
    }

    // Note: CMD12 (stop transfer) is automatically
    // sent by the SDMMC controller.

    if (mcd_SdmmcReadCheckCrc() != MCD_ERR_NO)
    {
        SDMMC_ERR("crc error\n");
        return MCD_ERR;
    }

    tran_time_out = (MCD_CARD_V1 == g_mcdVer) ? MCD_TRAN_TIMEOUT_V1:MCD_TRAN_TIMEOUT_V2;
    // Check that the card is in tran (Transmission) state.
    if (MCD_ERR_NO != mcd_SdmmcTranState(tran_time_out))
    {
        SDMMC_ERR("trans state timeout\n");
        return MCD_ERR_CARD_TIMEOUT;
    }

    return MCD_ERR_NO;
}

PRIVATE MCD_ERR_T mcd_SdmmcMltBlkWrite_Polling(CONST UINT8* pWrite, UINT32 startBlock, UINT32 blockNum)
{
    UINT32                  cardResponse[4]     = {0, 0, 0, 0};
    MCD_ERR_T               errStatus           = MCD_ERR_NO;
    HAL_SDMMC_CMD_T         readCmd;
    MCD_CARD_STATUS_T cardStatusTranState;
    cardStatusTranState.reg = 0;
    cardStatusTranState.fields.readyForData = 1;
    cardStatusTranState.fields.currentState = MCD_CARD_STATE_TRAN;
    UINT64 startTime;
    UINT64 tran_time_out;
    UINT64 read_time_out;
    UINT32 *pWdBuf = (UINT32 *)pWrite;
    UINT32 wdBufSize;
    UINT32 wdBufIdx;
    REG32 *regStatus2  = &(hwp_sdmmc->SDMMC_STATUS2);
    REG32 *regTxRxFifo = &(hwp_sdmmc->APBI_FIFO_TxRx);

    SDMMC_DBG("Enter\n");

    g_mcdSdmmcTransfer.sysMemAddr = (UINT8 *)pWrite;
    g_mcdSdmmcTransfer.sdCardAddr = (UINT8 *)startBlock;
    g_mcdSdmmcTransfer.blockNum   = blockNum;
    g_mcdSdmmcTransfer.blockSize  = g_mcdBlockLen;
    g_mcdSdmmcTransfer.direction  = HAL_SDMMC_DIRECTION_WRITE;

    // Command are different for reading one or several blocks of data
    if (blockNum == 1)
        readCmd = HAL_SDMMC_CMD_WRITE_SINGLE_BLOCK;
    else
        readCmd = HAL_SDMMC_CMD_WRITE_MULT_BLOCK;

    SDMMC_DBG("before set hwp_sdmmc->SDMMC_STATUS: 0x%x, hwp_sdmmc->SDMMC_INT_STATUS:0x%x\n", hwp_sdmmc->SDMMC_STATUS, hwp_sdmmc->SDMMC_INT_STATUS);
    SDMMC_DBG("hwp_sdmmc->SDMMC_STATUS2:0x%x\n", hwp_sdmmc->SDMMC_STATUS2);
    // Initiate data migration through Ifc.

    SDMMC_DBG("hwp_sdmmc->SDMMC_CONFIG:0x%x\n", hwp_sdmmc->SDMMC_CONFIG);
    if (hal_SdmmcSetTransferInfo(&g_mcdSdmmcTransfer) != 0)
    {
        SDMMC_ERR("write sd no ifc channel\n");
        return MCD_ERR_DMA_BUSY;
    }
    SDMMC_DBG("hwp_sdmmc->SDMMC_CONFIG:0x%x\n", hwp_sdmmc->SDMMC_CONFIG);

    SDMMC_DBG("send command\n");
#if 1
    //while (1) {
    SDMMC_DBG("(UINT32)hwp_sdmmc->SDMMC_STATUS: 0x%x\n", (UINT32)(UINT32)hwp_sdmmc->SDMMC_STATUS);
    SDMMC_DBG("hwp_sdmmc->SDMMC_STATUS2:0x%x\n", hwp_sdmmc->SDMMC_STATUS2);
    //mdelay(1000);
    //}
#endif

#if 0
    // Initiate data migration of multiple blocks through SD bus.
    errStatus = mcd_SdmmcSendCmd(readCmd,
                                  startBlock,
                                  cardResponse,
                                  FALSE);
    if (errStatus != MCD_ERR_NO)
    {
        SDMMC_ERR("send command err=%d\n", errStatus);
        hal_SdmmcStopTransfer(&g_mcdSdmmcTransfer);
        return MCD_ERR_CMD;
    }
    SDMMC_DBG("cardResponse:[0x%x][0x%x][0x%x][0x%x]\n", cardResponse[0], cardResponse[1], cardResponse[2], cardResponse[3]);
    SDMMC_DBG("hwp_sdmmc->SDMMC_STATUS2:0x%x\n", hwp_sdmmc->SDMMC_STATUS2);
    if (cardResponse[0] != cardStatusTranState.reg)
    {
        SDMMC_ERR("command response\n");
        hal_SdmmcStopTransfer(&g_mcdSdmmcTransfer);
        return MCD_ERR;
    }
    SDMMC_DBG("send command done\n");
#endif

    wdBufSize = blockNum << 7;  // Total buffer count in words
    wdBufIdx = 0;
    while(wdBufIdx < wdBufSize) {
        startTime = hal_TimGetUpTime();
        while((*regStatus2 & 0x070000UL) == 0UL) {
            if(hal_TimGetUpTime() - startTime > 1000) {
                SDMMC_ERR("timeout, STATUS2\n");
                hal_SdmmcStopTransfer(&g_mcdSdmmcTransfer);
                return MCD_ERR_CARD_TIMEOUT;
            }
        }
        *regTxRxFifo = *(pWdBuf + wdBufIdx);
        wdBufIdx++;
        if(wdBufIdx == 4) {
            // Initiate data migration of multiple blocks through SD bus.
            errStatus = mcd_SdmmcSendCmd(readCmd,
                                          ((g_mcdCardIsSdhc == TRUE) ? startBlock : (startBlock << 9)),
                                          cardResponse,
                                          FALSE);
            if (errStatus != MCD_ERR_NO)
            {
                SDMMC_ERR("send command err=%d\n", errStatus);
                hal_SdmmcStopTransfer(&g_mcdSdmmcTransfer);
                return MCD_ERR_CMD;
            }
            SDMMC_DBG("cardResponse:[0x%x][0x%x][0x%x][0x%x]\n", cardResponse[0], cardResponse[1], cardResponse[2], cardResponse[3]);
            SDMMC_DBG("hwp_sdmmc->SDMMC_STATUS2:0x%x\n", hwp_sdmmc->SDMMC_STATUS2);
            if (cardResponse[0] != cardStatusTranState.reg)
            {
                SDMMC_ERR("command response=0x%08X\n", cardResponse[0]);
                hal_SdmmcStopTransfer(&g_mcdSdmmcTransfer);
                return MCD_ERR;
            }
            SDMMC_DBG("send command done\n");
        }
    }

    // Wait
    startTime = hal_TimGetUpTime();
    read_time_out =  (MCD_CARD_V1 == g_mcdVer) ? MCD_READ_TIMEOUT_V1:MCD_READ_TIMEOUT_V2;
    while(!hal_SdmmcTransferDone())
    {
//    SDMMC_DBG("check while\n");
//    SDMMC_DBG("hwp_sdmmc->SDDMA_STATUS:0x%x\n", hwp_sdmmc->SDDMA_STATUS);
//    SDMMC_DBG("hwp_sdmmc->SDMMC_STATUS2:0x%x\n", hwp_sdmmc->SDMMC_STATUS2);
        if (hal_TimGetUpTime() - startTime > (read_time_out*blockNum))
        {
            SDMMC_ERR("timeout\n");
            // Abort the transfert.
            hal_SdmmcStopTransfer(&g_mcdSdmmcTransfer);
            return MCD_ERR_CARD_TIMEOUT;
        }
    }

    // Note: CMD12 (stop transfer) is automatically
    // sent by the SDMMC controller.

    SDMMC_DBG("before set hwp_sdmmc->SDMMC_STATUS: 0x%x, hwp_sdmmc->SDMMC_INT_STATUS:0x%x\n", hwp_sdmmc->SDMMC_STATUS, hwp_sdmmc->SDMMC_INT_STATUS);
    if (mcd_SdmmcReadCheckCrc() != MCD_ERR_NO)
    {
        SDMMC_ERR("crc error\n");
        return MCD_ERR;
    }

    SDMMC_DBG("before set hwp_sdmmc->SDMMC_STATUS: 0x%x, hwp_sdmmc->SDMMC_INT_STATUS:0x%x\n", hwp_sdmmc->SDMMC_STATUS, hwp_sdmmc->SDMMC_INT_STATUS);
    tran_time_out = (MCD_CARD_V1 == g_mcdVer) ? MCD_TRAN_TIMEOUT_V1:MCD_TRAN_TIMEOUT_V2;
    // Check that the card is in tran (Transmission) state.
    if (MCD_ERR_NO != mcd_SdmmcTranState(tran_time_out))
    {
        SDMMC_ERR("trans state timeout\n");
        return MCD_ERR_CARD_TIMEOUT;
    }
    return MCD_ERR_NO;
}

#define SDMMC_CLKGATE_REG       (*((volatile unsigned int *)0x40000008UL))
#define SDMMC_CLKGATE_REG2      (*((volatile unsigned int *)0x4000000CUL))
#define SDMMC_CLKGATE_BP_REG    (*((volatile unsigned int *)0x40000028UL))
#define IOMUX_CTRL_1_REG        (*((volatile unsigned int *)0x40001048UL))
#define IOMUX_CTRL_4_REG        (*((volatile unsigned int *)0x40001054UL))

/*void wr_rf_reg(unsigned char a, unsigned short d)
{
#define RF_SPI_REG              (*((volatile unsigned int *)0x4001301CUL))
    while(RF_SPI_REG & (0x01UL << 31));
    RF_SPI_REG = (unsigned int)d | ((unsigned int)a << 16) | (0x01UL << 25);
#undef RF_SPI_REG
}*/
#include "rda_ccfg_api.h"

void rda_sdmmc_init(PinName clk, PinName cmd, PinName d0, PinName d1, PinName d2, PinName d3)
{
    UINT32 reg_val;

    /* Enable SDMMC power and clock */
    SDMMC_CLKGATE_REG |= (0x01UL << 5);
    //SDMMC_CLKGATE_REG2 |= (0x01UL << 15);

    if ((NC != d1) && (NC != d2) && (NC != d3)) {
        is_4wire_en = 1;
    }

    if (PB_6 == d0) {
        rda_ccfg_gp(6U, 0x01U);
        /* Config SDMMC pins iomux: clk, cmd, d0 (GPIO 9, 0, 6) */
        reg_val = IOMUX_CTRL_1_REG & ~(7UL) & ~(7UL << 18) & ~(7UL << 27);
        IOMUX_CTRL_1_REG = reg_val |  (3UL) |  (7UL << 18) |  (3UL << 27);
    } else if (PB_3 == d0) {
        /* Config SDMMC pins iomux: clk, cmd, d0 (GPIO 9, 0, 3) */
        reg_val = IOMUX_CTRL_1_REG & ~(7UL) & ~(7UL <<  9) & ~(7UL << 27);
        IOMUX_CTRL_1_REG = reg_val |  (3UL) |  (5UL <<  9) |  (3UL << 27);
    }

    if (0 != is_4wire_en) {
        rda_ccfg_gp(7U, 0x01U);
        /* Config SDMMC pin iomux: d1 (GPIO 7) */
        reg_val = IOMUX_CTRL_1_REG & ~(7UL << 21);
        IOMUX_CTRL_1_REG = reg_val |  (5UL << 21);
        /* Config SDMMC pin iomux: d2, d3 (GPIO 12, 13) */
        reg_val = IOMUX_CTRL_4_REG & ~(7UL) & ~(7UL <<  3);
        IOMUX_CTRL_4_REG = reg_val |  (3UL) |  (3UL <<  3);
    }
}

int rda_sdmmc_open(void)
{
    int ret_val;
    /* Initialize SDMMC Card */
    ret_val = (MCD_ERR_NO == mcd_Open(&mcd_csd, MCD_CARD_V2)) ? 1 : 0;
    return ret_val;
}

int rda_sdmmc_read_blocks(UINT8 *buffer, UINT32 block_start, UINT32 block_num)
{
    MCD_ERR_T ret = mcd_SdmmcMltBlkRead_Polling(buffer, block_start, block_num);

    return (int)ret;
}

int rda_sdmmc_write_blocks(CONST UINT8 *buffer, UINT32 block_start, UINT32 block_num)
{
    MCD_ERR_T ret = mcd_SdmmcMltBlkWrite_Polling(buffer, block_start, block_num);

    return (int)ret;
}

int rda_sdmmc_get_csdinfo(UINT32 *block_size)
{
    // csd_structure : csd[127:126]
    // c_size        : csd[73:62]
    // c_size_mult   : csd[49:47]
    // read_bl_len   : csd[83:80]
    int ret_val = (int)mcd_csd.csdStructure;
    UINT32 block_len, mult, blocknr, capacity;

    switch(ret_val) {
        case 0:
            block_len = 1 << mcd_csd.readBlLen;
            mult = 1 << (mcd_csd.cSizeMult + 2);
            blocknr = (mcd_csd.cSize + 1) * mult;
            capacity = blocknr * block_len;
            *block_size = capacity / 512;
            break;

        case 1:
            *block_size = (mcd_csd.cSize + 1)*1024;
            break;

        default:
            *block_size = 0;
    }

    return ret_val;
}

#if SDMMC_TEST_ENABLE
void rda_sdmmc_test(void)
{
    UINT8 buf[512];
    UINT16 idx;
    UINT32 sector = 0;
    UINT32 blocks = 1;

    for(idx=0;idx<512;idx++) {
        buf[idx] = (UINT8)(idx & 0xFFU);
    }

    rprintf("Init SDMMC\r\n");
    //rda_sdmmc_init(PB_9, PB_0, PB_6, PB_7, PC_0, PC_1);  // for old EVB
    rda_sdmmc_init(PB_9, PB_0, PB_3, PB_7, PC_0, PC_1);  // for RDA5991H_HDK_V1.0

    //rprintf("Write sector:%d, blocks:%d\r\n", sector, blocks);
    //rda_sdmmc_write_blocks(buf, sector, blocks);

    rprintf("Read sector:%d, blocks:%d\r\n", sector, blocks);
    rda_sdmmc_read_blocks(buf, sector, blocks);

    for(idx=0;idx<512;idx++) {
        rprintf(" %02X", buf[idx]);
        if((idx % 16) == 15)
            rprintf("\r\n");
    }

    rprintf("Close SDMMC\r\n");
    mcd_Close();
}
#endif

