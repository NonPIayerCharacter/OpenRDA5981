#include "WiFiStackInterface.h"
#include "rda_sys_wrapper.h"
#include "console.h"
#include "rda59xx_daemon.h"
#include "wland_flash.h"

extern WiFiStackInterface wifi;
extern unsigned int baudrate;
extern char conn_flag;
extern void start_at(void);

void init(void)
{
    int ret;
    ret = rda5981_flash_read_uart(&baudrate);
    if(ret == 0)
        console_set_baudrate(baudrate);
}

int main()
{
    init();
    start_at();

    while (true) {
        osDelay(osWaitForever);
    }
}

