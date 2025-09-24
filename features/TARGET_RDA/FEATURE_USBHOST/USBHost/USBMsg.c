#include "rt_TypeDef.h"
#include "rt_Time.h"
#include "cmsis_os.h"

#include <stdio.h>
#include <string.h>
#define NO_ERR  0
#define ERR     -1

void* usb_msgQ_create(unsigned int queuesz)
{
    void* internal_data;
    osMessageQDef_t msgQ;
    osMessageQId msgQId;

    internal_data = (void *)malloc((4 + queuesz) * sizeof(unsigned int));
    memset(internal_data, 0, sizeof((4 + queuesz) * sizeof(unsigned int)));
    msgQ.queue_sz = queuesz;
    msgQ.pool = internal_data;
    msgQId = osMessageCreate(&msgQ, NULL);

    return (void *)msgQId;
}

int usb_msg_put(void *msgQId, unsigned int msg, unsigned int millisec)
{
    osMessageQId osmsgQId = (osMessageQId)msgQId;
    osStatus res;
    res = osMessagePut(osmsgQId, msg, millisec);
    if(res == osOK)
        return NO_ERR;
    else
        return ERR;
}

int usb_msg_get(void *msgQId, unsigned int *value, unsigned int millisec)
{
    osMessageQId osmsgQId = (osMessageQId)msgQId;
    osEvent evt;
    if(msgQId == NULL){
        printf("msgQId is NULL\r\n");
        return ERR;
    }
    evt = osMessageGet(osmsgQId, millisec);

    if(evt.status == osEventMessage){
        *value = evt.value.v;
        return NO_ERR;
    }else{
        printf("message get error, status = %d\r\n", evt.status);
        return ERR;
    }
}
