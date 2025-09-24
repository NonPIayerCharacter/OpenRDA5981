#ifndef _HAL_SDMMC_H_
#define _HAL_SDMMC_H_

// =============================================================================
// MACROS
// =============================================================================
// =============================================================================
// HAL_SDMMC_ACMD_SEL
// -----------------------------------------------------------------------------
/// Macro to mark a command as application specific
// =============================================================================
#define HAL_SDMMC_ACMD_SEL         0x80000000U


// =============================================================================
// HAL_SDMMC_CMD_MASK
// -----------------------------------------------------------------------------
/// Mask to get from a HAL_SDMMC_CMD_T value the corresponding 
/// command index
// =============================================================================
#define HAL_SDMMC_CMD_MASK 0x3F



// =============================================================================
// HAL_SDMMC_CMD_T
// -----------------------------------------------------------------------------
// SD commands
// =============================================================================
typedef enum
{
    HAL_SDMMC_CMD_GO_IDLE_STATE         = 0U,
    HAL_SDMMC_CMD_MMC_SEND_OP_COND      = 1U,
    HAL_SDMMC_CMD_ALL_SEND_CID            = 2U,
    HAL_SDMMC_CMD_SEND_RELATIVE_ADDR    = 3U,
    HAL_SDMMC_CMD_SET_DSR                = 4U,
    HAL_SDMMC_CMD_SWITCH           = 6U,
    HAL_SDMMC_CMD_SELECT_CARD            = 7U,
    HAL_SDMMC_CMD_SEND_IF_COND          = 8U,
    HAL_SDMMC_CMD_SEND_CSD                = 9U,
    HAL_SDMMC_CMD_STOP_TRANSMISSION        = 12U,
    HAL_SDMMC_CMD_SEND_STATUS            = 13U,
    HAL_SDMMC_CMD_SET_BLOCKLEN            = 16U,
    HAL_SDMMC_CMD_READ_SINGLE_BLOCK        = 17U,
    HAL_SDMMC_CMD_READ_MULT_BLOCK        = 18U,
    HAL_SDMMC_CMD_WRITE_SINGLE_BLOCK    = 24U,
    HAL_SDMMC_CMD_WRITE_MULT_BLOCK        = 25U,
    HAL_SDMMC_CMD_APP_CMD                = 55U,
    HAL_SDMMC_CMD_SET_BUS_WIDTH            = (6U | HAL_SDMMC_ACMD_SEL),
    HAL_SDMMC_CMD_SEND_NUM_WR_BLOCKS    = (22U| HAL_SDMMC_ACMD_SEL),
    HAL_SDMMC_CMD_SET_WR_BLK_COUNT        = (23U| HAL_SDMMC_ACMD_SEL),
    HAL_SDMMC_CMD_SEND_OP_COND            = (41U| HAL_SDMMC_ACMD_SEL)
} HAL_SDMMC_CMD_T;

// =============================================================================
// HAL_SDMMC_OP_STATUS_T
// -----------------------------------------------------------------------------
/// This structure is used the module operation status. It is different from the 
/// IRQ status.
// =============================================================================
typedef union
{
    UINT32 reg;
    struct
    {
        UINT32 operationNotOver     :1;
        /// Module is busy ?
        UINT32 busy                 :1;
        UINT32 dataLineBusy         :1;
        /// '1' means the controller will not perform the new command when SDMMC_SENDCMD= '1'.
        UINT32 suspend              :1;
        UINT32                      :4;
        UINT32 responseCrcError     :1;
        /// 1 as long as no reponse to a command has been received.
        UINT32 noResponseReceived   :1;
        UINT32                      :2;
        /// CRC check for SD/MMC write operation
        /// "101" transmission error
        /// "010" transmission right
        /// "111" flash programming error
        UINT32 crcStatus            :3;
        UINT32                      :1;
        /// 8 bits data CRC check, "00000000" means no data error, 
        /// "00000001" means DATA0 CRC check error, "10000000" means 
        /// DATA7 CRC check error, each bit match one data line.
        UINT32 dataError            :8;
    } fields;
} HAL_SDMMC_OP_STATUS_T;


// =============================================================================
// HAL_SDMMC_DIRECTION_T
// -----------------------------------------------------------------------------
/// Describe the direction of a transfer between the SDmmc controller and a 
/// pluggued card.
// =============================================================================
typedef enum
{
    HAL_SDMMC_DIRECTION_READ,
    HAL_SDMMC_DIRECTION_WRITE,

    HAL_SDMMC_DIRECTION_QTY
} HAL_SDMMC_DIRECTION_T;



// =============================================================================
// HAL_SDMMC_TRANSFER_T
// -----------------------------------------------------------------------------
/// Describe a transfer between the SDmmc module and the SD card
// =============================================================================
typedef struct
{
    /// This address in the system memory
    UINT8* sysMemAddr;
    /// Address in the SD card
    UINT8* sdCardAddr;
    /// Quantity of data to transfer, in blocks
    UINT32 blockNum;
    /// Block size
    UINT32 blockSize;
    HAL_SDMMC_DIRECTION_T direction;
} HAL_SDMMC_TRANSFER_T;



// =============================================================================
// HAL_SDMMC_DATA_BUS_WIDTH_T
// -----------------------------------------------------------------------------
/// Cf spec v2 pdf p. 76 for ACMD6 argument
/// That type is used to describe how many data lines are used to transfer data
/// to and from the SD card.
// =============================================================================
typedef enum
{
    HAL_SDMMC_DATA_BUS_WIDTH_1 = 0x0,
    HAL_SDMMC_DATA_BUS_WIDTH_4 = 0x2,
    HAL_SDMMC_DATA_BUS_WIDTH_8 = 0x4
} HAL_SDMMC_DATA_BUS_WIDTH_T;


//=============================================================================
// 


#endif // _HAL_SDMMC_H_

