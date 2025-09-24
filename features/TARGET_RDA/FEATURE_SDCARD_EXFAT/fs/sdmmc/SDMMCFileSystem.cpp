/* mbed Microcontroller Library
 * Copyright (c) 2006-2012 ARM Limited
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "SDMMCFileSystem.h"
#include "mbed_debug.h"
#include "sdmmc.h"

#define SD_COMMAND_TIMEOUT 5000

#define SD_DBG             0

SDMMCFileSystem::SDMMCFileSystem(PinName clk, PinName cmd, PinName d0,
                     PinName d1, PinName d2, PinName d3, const char* name) :
    FATFileSystem(name), _is_initialized(0) {
        debug_if(SD_DBG, "SDMMCFileSystem(%s)\r\n", name);
        rda_sdmmc_init(clk, cmd, d0, d1, d2, d3);
}

#define R1_IDLE_STATE           (1 << 0)
#define R1_ERASE_RESET          (1 << 1)
#define R1_ILLEGAL_COMMAND      (1 << 2)
#define R1_COM_CRC_ERROR        (1 << 3)
#define R1_ERASE_SEQUENCE_ERROR (1 << 4)
#define R1_ADDRESS_ERROR        (1 << 5)
#define R1_PARAMETER_ERROR      (1 << 6)

// Types
//  - v1.x Standard Capacity
//  - v2.x Standard Capacity
//  - v2.x High Capacity
//  - Not recognised as an SD Card
#define SDCARD_FAIL 0
#define SDCARD_V1   1
#define SDCARD_V2   2
#define SDCARD_V2HC 3

int SDMMCFileSystem::disk_initialize() {
    lock();
    _is_initialized = rda_sdmmc_open();
    if (_is_initialized == 0) {
        debug("Fail to initialize card\n");
        unlock();
        return 1;
    }
    debug_if(SD_DBG, "init card = %d\n", _is_initialized);
    _sectors = _sd_sectors();

    unlock();
    return 0;
}

int SDMMCFileSystem::disk_write(const uint8_t* buffer, uint32_t block_number, uint32_t count) {
    int err;
    lock();
    if (!_is_initialized) {
        unlock();
        return -1;
    }

    err = rda_sdmmc_write_blocks((unsigned char *)buffer, block_number, count);
    if(err != 0) {
        _is_initialized = 0;
    }

    unlock();
    return err;
}

int SDMMCFileSystem::disk_read(uint8_t* buffer, uint32_t block_number, uint32_t count) {
    int err;
    lock();
    if (!_is_initialized) {
        unlock();
        return -1;
    }

    err = rda_sdmmc_read_blocks(buffer, block_number, count);
    if(err != 0) {
        _is_initialized = 0;
    }

    unlock();
    return err;
}

int SDMMCFileSystem::disk_status() {
    lock();
    // FATFileSystem::disk_status() returns 0 when initialized
    int ret = _is_initialized ? 0 : 1;
    unlock();
    return ret;
}

int SDMMCFileSystem::disk_check()
{
    int err = 0;
    lock();
    if(0 == _is_initialized) {
        err = disk_initialize();
    } else {
        unsigned char buf[512];
        err = rda_sdmmc_read_blocks(buf, 0, 1);
        if(0 != err) {
            _is_initialized = 0;
        }
    }
    unlock();
    return err;
}

int SDMMCFileSystem::disk_sync()
{
    return 0;
}

uint32_t SDMMCFileSystem::disk_sectors() {
    lock();
    uint32_t sectors = _sectors;
    unlock();
    return sectors;
}

// PRIVATE FUNCTIONS
uint32_t SDMMCFileSystem::_sd_sectors() {
    uint32_t blocks;
    int csd_structure;

    /* Get CSD info */
    csd_structure = rda_sdmmc_get_csdinfo((unsigned long *)(&blocks));

    switch (csd_structure) {
        case 0:
            cdv = 512;
            debug_if(SD_DBG, "\n\rSDCard\n\rsectors: %lld\n\r", blocks);
            break;

        case 1:
            cdv = 1;
            debug_if(SD_DBG, "\n\rSDHC Card \n\rsectors: %lld\n\r", blocks);
            break;

        default:
            debug("CSD struct unsupported\r\n");
            return 0;
    };
    return blocks;
}
