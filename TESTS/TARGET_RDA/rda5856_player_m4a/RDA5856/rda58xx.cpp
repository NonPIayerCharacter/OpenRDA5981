/** \file rda58xx.c
 * Functions for interfacing with the codec chip.
 */
#include "rda58xx.h"
#include "mbed_interface.h"

#define CHAR_CR             (0x0D)  // carriage return
#define CHAR_LF             (0x0A)  // line feed

#define MUPLAY_PROMPT       "AT+MUPLAY="
#define MUSTART_PROMPT      "AT+MUSTART="
#define TX_DATA_PROMPT      "AT+MURAWDATA="
#define RUSTART_PROMPT      "AT+RUSTART="

#define MUSTOP_CMD          "AT+MUSTOP="
#define MUSTOP_CMD2         "AT+MUSTOP\r\n"
#define RUSTOP_CMD          "AT+RUSTOP\r\n"
#define VOLADD_CMD          "AT+CVOLADD\r\n"
#define VOLSUB_CMD          "AT+CVOLSUB\r\n"
#define RX_VALID_RSP        "\r\nOK\r\n"
#define RX_VALID_RSP2       "OK\r\n"

#define RDALOG(fmt, ...)   printf(fmt, ##__VA_ARGS__)

unsigned char tmpBuffer[64] = {0};
unsigned char tmpIdx = 0;
char res_str[32] = {0};

/** Constructor of class RDA58XX. */
rda58xx::rda58xx(PinName TX, PinName RX, PinName HRESET):
    _serial(TX, RX),
    _baud(3200000),
    _rxsem(0),
    _HRESET(HRESET),
    _status(STOP),
    _rx_buffer_status(EMPTY),
    _rx_buffer_size(640),
    _rx_idx(0),
    _rx_buffer(NULL),
    _DREQ(GPIO_PIN14)
{
    _serial.baud(_baud);
    _serial.attach(this, &rda58xx::rx_handler, RawSerial::RxIrq);
    _HRESET = 1;
    _rx_buffer = new unsigned char [_rx_buffer_size * 2];
}

rda58xx::~rda58xx()
{
    if (_rx_buffer != NULL)
        delete [] _rx_buffer;
}

void rda58xx::hardReset(void)
{
    _HRESET = 0;
    wait_ms(10);
    _HRESET = 1;
    wait_ms(1200);
}

void rda58xx::bufferReq(mci_type_enum ftype, unsigned short size, unsigned short threshold1, unsigned short threshold2)
{
    unsigned char cmd_str[32] = {0};
    int len;

    // Send AT CMD: MUPLAY
    len = sprintf((char *)cmd_str, "%s%d,%d,%d,%d\r\n", MUPLAY_PROMPT, ftype, size, threshold1, threshold2);
    cmd_str[len] = '\0';
    RDALOG("%s", cmd_str);
    _serial.puts((const char *)cmd_str);
    _rxsem.wait();
}

void rda58xx::bufferReq(mci_type_enum ftype, unsigned short size, unsigned short threshold)
{
    unsigned char cmd_str[32] = {0};
    int len;

    // Send AT CMD: MUPLAY
    len = sprintf((char *)cmd_str, "%s%d,%d,%d\r\n", MUPLAY_PROMPT, ftype, size, threshold);
    cmd_str[len] = '\0';
    RDALOG("%s", cmd_str);
    _serial.puts((const char *)cmd_str);
    _rxsem.wait();
}

void rda58xx::startPlay(mci_type_enum ftype)
{
    unsigned char cmd_str[32] = {0};
    int len;

    // Send AT CMD: MUSTART
    len = sprintf((char *)cmd_str, "%s%d\r\n", MUSTART_PROMPT, ftype);
    cmd_str[len] = '\0';
    RDALOG("%s", cmd_str);
    _serial.puts((const char *)cmd_str);
    _rxsem.wait();
}

void rda58xx::stopPlay(void)
{
    // Send AT CMD: MUSTOP
    RDALOG("%s", MUSTOP_CMD);
    _serial.puts((const char *)MUSTOP_CMD2);
    _rxsem.wait();
}

void rda58xx::stopPlay(rda58xx_stop_type stype)
{
    unsigned char cmd_str[32] = {0};
    int len;
    
    // Send AT CMD: MUSTOP
    len = sprintf((char *)cmd_str, "%s%d\r\n", MUSTOP_CMD, stype);
    cmd_str[len] = '\0';
    RDALOG("%s", cmd_str);
    _serial.puts((const char *)cmd_str);
    _rxsem.wait();
}

void rda58xx::startRecord(mci_type_enum ftype, unsigned short size)
{
    unsigned char cmd_str[32] = {0};
    int len;

    // Send AT CMD: RUSTART
    len = sprintf((char *)cmd_str, "%s%d,%d\r\n", RUSTART_PROMPT, ftype, size);
    cmd_str[len] = '\0';
    RDALOG("%s", cmd_str);
    _serial.puts((const char *)cmd_str);
    _rxsem.wait();
}

void rda58xx::stopRecord(void)
{
    // Send AT CMD: RUSTOP
    printf("%s", RUSTOP_CMD);
    _serial.puts((const char *)RUSTOP_CMD);
    setStatus(STOP_RECORDING);
    _rxsem.wait();
}

void rda58xx::volAdd(void)
{
    // Send AT CMD: VOLADD
    RDALOG("%s", VOLADD_CMD);
    _serial.puts((const char *)VOLADD_CMD);
    _rxsem.wait();
}

void rda58xx::volSub(void)
{
    // Send AT CMD: VOLSUB
    RDALOG("%s", VOLSUB_CMD);
    _serial.puts((const char *)VOLSUB_CMD);
    _rxsem.wait();
}

/** Send raw data to RDA58XX  */
void rda58xx::sendRawData(unsigned char *databuf,unsigned short n)
{
    unsigned char cmd_str[32] = {0};
    int len;

    // Send AT CMD: MURAWDATA
    len = sprintf((char *)cmd_str, "%s%d\r\n", TX_DATA_PROMPT, n);
    cmd_str[len] = '\0';
    RDALOG("%s", cmd_str);
    _serial.puts((const char *)cmd_str);
    _rxsem.wait();

    // Raw Data bytes
    RDALOG("SendData\r\n");

    while(n--) {
        _serial.putc(*databuf);
        databuf++;
    }
    _rxsem.wait();
}

void rda58xx::setBaudrate(int baud)
{
    _serial.baud(baud);
}

void rda58xx::setStatus(rda58xx_status status)
{
    _status = status;
}

rda58xx_status rda58xx::getStatus(void)
{
    return _status;
}

rda58xx_buffer_status rda58xx::getBufferStatus(void)
{
    return _rx_buffer_status;
}

void rda58xx::clearBufferStatus(void)
{
    _rx_buffer_status = EMPTY;
}

unsigned char *rda58xx::getBufferAddr(void)
{
    return &_rx_buffer[_rx_buffer_size];
}

/* Set the RX Buffer size.
 * You CAN ONLY use it when you are sure there is NO transmission on RX!!! 
 */
void rda58xx::setBufferSize(unsigned int size)
{
    _rx_buffer_size = size;
    delete [] _rx_buffer;
    _rx_buffer = new unsigned char [_rx_buffer_size * 2];
}

unsigned int rda58xx::getBufferSize(void)
{
    return _rx_buffer_size;
}

unsigned int rda58xx::requestData(void)
{
    return _DREQ;
}

void rda58xx::rx_handler(void)
{
    unsigned char count = (RDA_UART1->FSR >> 9) & 0x7F;

    count = (count <= (_rx_buffer_size - _rx_idx)) ? count : (_rx_buffer_size - _rx_idx);
    while (count--) {
        tmpBuffer[tmpIdx] = (unsigned char) (RDA_UART1->RBR & 0xFF);
        tmpIdx++;
    }
    
    memcpy(&_rx_buffer[_rx_idx], tmpBuffer, tmpIdx);
    _rx_idx += tmpIdx;

    if (_status == RECORDING) {
        if (_rx_buffer_size == _rx_idx) {
            memcpy(&_rx_buffer[_rx_buffer_size], &_rx_buffer[0], _rx_buffer_size);
            _rx_buffer_status = FULL;
            _rx_idx = 0;

        }
    } else if (_status == STOP_RECORDING) {
        if ((_rx_idx >= 4) && (_rx_buffer[_rx_idx - 1] == '\n')) {
            memcpy(res_str, &_rx_buffer[_rx_idx - 4], 4);
            res_str[4] = '\0';
            if (strstr(RX_VALID_RSP2, res_str) != NULL) {
                _rxsem.release();
                _rx_idx = 0;
                _status = PLAY;
            }
        } 
        if (_rx_buffer_size == _rx_idx) {
            memcpy(&_rx_buffer[0], &_rx_buffer[_rx_buffer_size - 10], 10);
            _rx_idx = 10;
        }
    } else {
        if ((_rx_idx >= 4) && ('\n' == _rx_buffer[_rx_idx - 1])) {
            memcpy(res_str, &_rx_buffer[_rx_idx - 4], 4);
            res_str[4] = '\0';
            if (strstr(RX_VALID_RSP2, res_str) != NULL) {
                _rxsem.release();
            } else {            
#if 1
                _rx_buffer[_rx_idx] = '\0';
                mbed_error_printf("%s", _rx_buffer);
#else
                for (unsigned int i = 0; i < _rx_idx; i++) {
                    mbed_error_printf("%02X#", _rx_buffer[i]);
                }
#endif
            }
            _rx_idx = 0;
        }
    }
    tmpIdx = 0;
    if (_rx_idx >= _rx_buffer_size)
        _rx_idx = 0;
}

