#include "mbed.h"
#include "rtos.h"
#include "WiFiStackInterface.h"
#include "rda_sys_wrapper.h"
#include "wland_rf.h"
#include "wland_recv.h"

extern void start_at(void);
extern int hut_log_handler(void *data);

int main()
{
    WiFiStackInterface wifi;

    printf("Start uarthut test...\r\n");

    reg_user_hut_log_handler(hut_log_handler);
    start_at();
    wifi.connect(NULL, NULL, NULL, NSAPI_SECURITY_NONE);
    
    while (true);
}

