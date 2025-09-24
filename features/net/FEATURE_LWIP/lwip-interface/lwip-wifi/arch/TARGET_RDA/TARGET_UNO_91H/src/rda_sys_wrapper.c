#include "rda_sys_wrapper.h"
#include "rt_TypeDef.h"
#include "rt_Time.h"
#include "sys_arch.h"

#include <stdio.h>
#include <string.h>

//#define RDA_SYS_DEBUG
#ifdef RDA_SYS_DEBUG
#define RDA_SYS_PRINT(fmt, ...) do {\
            printf(fmt, ##__VA_ARGS__);\
    } while (0)
#else
#define RDA_SYS_PRINT(fmt, ...)
#endif

#if !defined(USING_STDLIB)
unsigned long g_alarm_buf[WORD_ALIGN(MAX_ALARM_MEM_SIZE) >> 2] = {0};
rda_tmr_ctrl_t g_alarm_ctrl = {
    (r_u8 *)g_alarm_buf + MAX_ALARM_STAT_SIZE,
    (r_u8 *)g_alarm_buf,
    MAX_ALARM_NUM,
    WORD_ALIGN(sizeof(rda_tmr_node_t)),
    0U,
    0U
};

__STATIC_INLINE r_u8 get_node_state(r_u8 *buf, r_u8 idx)
{
    r_u8 state, ofst;
    ofst = (idx & 0x07U);
    buf += (idx >> 3);
    state = (*buf >> ofst) & 0x01U;
    return state;
}

__STATIC_INLINE r_void set_node_state(r_u8 *buf, r_u8 idx, r_u8 state)
{
    r_u8 ofst, tmp;
    ofst = (idx & 0x07U);
    buf += (idx >> 3);
    tmp = *buf & (~(0x01U << ofst));
    *buf = tmp | (((state & 0x01U) << ofst));
}

static rda_tmr_node_t *get_tmr_node(r_void)
{
    rda_tmr_node_t *node = NULL;
    r_u8 idx = g_alarm_ctrl.last_freed_node_idx;
    if((idx < g_alarm_ctrl.max_node_num) && (0U == get_node_state(g_alarm_ctrl.state, idx))) {
        set_node_state(g_alarm_ctrl.state, idx, 1U);
        node = (rda_tmr_node_t *)(g_alarm_ctrl.buff + idx * g_alarm_ctrl.node_size);
        g_alarm_ctrl.node_cntr++;
    } else {
        for(idx = 0U; idx < g_alarm_ctrl.max_node_num; idx++) {
            if(0U == get_node_state(g_alarm_ctrl.state, idx)) {
                set_node_state(g_alarm_ctrl.state, idx, 1U);
                node = (rda_tmr_node_t *)(g_alarm_ctrl.buff + idx * g_alarm_ctrl.node_size);
                g_alarm_ctrl.node_cntr++;
                break;
            }
        }
    }
    return node;
}

static r_void put_tmr_node(rda_tmr_node_t *node)
{
    r_u8 *node_buf = (r_u8 *)node;
    r_u8 idx = (node_buf - g_alarm_ctrl.buff) / g_alarm_ctrl.node_size;
    if((node_buf > g_alarm_ctrl.buff) && (idx < g_alarm_ctrl.max_node_num) &&
        (1U == get_node_state(g_alarm_ctrl.state, idx))) {
        set_node_state(g_alarm_ctrl.state, idx, 0U);
        g_alarm_ctrl.node_cntr--;
        g_alarm_ctrl.last_freed_node_idx = idx;
    }
}
#endif /* !USING_STDLIB */

/**
 * @brief     : get current time in units of micro second
 * @param[in] :
 * @param[out]:
 * @return    : return time value with uint32 type
 */
r_u32 rda_get_cur_time_ms(r_void)
{
    return (r_u32)rt_time_get();
}

/**
 * @brief     : create an alarm with given function, return timer handle
 * @param[in] : func(callback)/data(pass to func)/mode(once or periodic)
 * @param[out]:
 * @return    : return timer handle, a pointer to the timer structure, non-zero is valid
 */
r_void * rda_alarm_create_v2(r_void *func, r_u32 data, r_u32 mode)
{
    r_void * timer_handle = NULL;
#if defined(USING_STDLIB)
    rda_ostmr_cb_t *timer_cb  = r_malloc(sizeof(rda_ostmr_cb_t));
    osTimerDef_t   *timer_def = r_malloc(sizeof(osTimerDef_t));
#else  /* USING_STDLIB */
    rda_ostmr_cb_t *timer_cb  = NULL;
    osTimerDef_t   *timer_def = NULL;
    rda_tmr_node_t *timer_node = get_tmr_node();
    if(NULL == timer_node) {
        return NULL;
    }
    timer_cb  = &(timer_node->cb);
    timer_def = &(timer_node->def);
#endif /* USING_STDLIB */

    r_memset(timer_cb, 0, sizeof(rda_ostmr_cb_t));
    r_memset(timer_def, 0, sizeof(osTimerDef_t));

    timer_def->timer  = timer_cb;
    timer_def->ptimer = (os_ptimer)func;
    timer_handle = (r_void *)osTimerCreate(timer_def, (os_timer_type)mode, (r_void *)data);
    if(((rda_ostmr_cb_t *)timer_handle)->timer != timer_def) {
        RDA_SYS_PRINT("Create alarm error\r\n");
#if defined(USING_STDLIB)
        r_free(timer_cb);
        r_free(timer_def);
#else  /* USING_STDLIB */
        put_tmr_node(timer_node);
#endif /* USING_STDLIB */
        timer_handle = NULL;
    }
    return timer_handle;
}

r_void * rda_alarm_create(r_void *func, r_u32 data)
{
    return rda_alarm_create_v2(func, data, osTimerOnce);
}

/**
 * @brief     : delete an alarm with given handle, then reset the handle
 * @param[in] : *handle(pointer to the timer structure)
 * @param[out]: **handle(address of the handle variable)
 * @return    :
 */
r_s32 rda_alarm_delete(r_void **handle)
{
    if(NULL != *handle) {
        osTimerId timer_id = (osTimerId)(*handle);
        osStatus retval = osTimerDelete(timer_id);
        if(osOK == retval) {
            rda_ostmr_cb_t *timer_cb  =(rda_ostmr_cb_t *)timer_id;
#if defined(USING_STDLIB)
            osTimerDef_t   *timer_def = NULL;
            timer_def = (osTimerDef_t *)(timer_cb->timer);
            r_free(timer_def);
            r_free(timer_cb);
#else  /* USING_STDLIB */
            put_tmr_node((rda_tmr_node_t *)timer_cb);
#endif /* USING_STDLIB */
            *handle = NULL;
        } else {
            RDA_SYS_PRINT("Delete alarm error: %d\r\n", retval);
            return ERR;
        }
        return NO_ERR;
    }
    return ERR;
}

/**
 * @brief     : start an alarm, raise a function call after given timeout delay
 * @param[in] : handle(pointer to the timer structure)/timeout(micro second)
 * @param[out]:
 * @return    :
 */
r_s32 rda_alarm_start(r_void *handle, r_u32 timeout_ms)
{
    if(NULL != handle) {
        osTimerId timer_id = (osTimerId)handle;
        osStatus retval = osTimerStart(timer_id, (uint32_t)timeout_ms);
        if(osOK != retval) {
            RDA_SYS_PRINT("Start alarm error: %d\r\n", retval);
            return ERR;
        }
        return NO_ERR;
    }
    return ERR;
}

/**
 * @brief     : stop an alarm, will not raise a function call any more
 * @param[in] : handle(pointer to the timer structure)
 * @param[out]:
 * @return    :
 */
r_s32 rda_alarm_stop(r_void *handle)
{
    if(NULL != handle) {
        osTimerId timer_id = (osTimerId)handle;
        if(((rda_ostmr_cb_t *)handle)->state != osTimerStopped) {
            osStatus retval = osTimerStop(timer_id);
            if(osOK != retval) {
                RDA_SYS_PRINT("Stop alarm error: %d\r\n", retval);
                return ERR;
            }
            return NO_ERR;
        }
        return NO_ERR;
    }
    return ERR;
}



/* Semaphore */
r_void* rda_sem_create(r_u32 count)
{
    r_void *data;
    osSemaphoreId sem;
    data = (r_void*)r_malloc(sizeof(r_u32) * 2);
    r_memset(data, 0, sizeof(r_u32) * 2);
    osSemaphoreDef_t sem_def = {(data)};
    sem = osSemaphoreCreate(&sem_def, count);
    if(sem == NULL) {
        RDA_SYS_PRINT("rda_sem_create error %d\r\n");
    }

    return (r_void*)sem;
}

r_s32 rda_sem_wait(r_void* sem, r_u32 millisec)
{
    r_s32 res;

    res = osSemaphoreWait(sem, millisec);
    if(res > 0){
        return NO_ERR;
    }else{
        RDA_SYS_PRINT("rda_sem_wait error %d\r\n", res);
        return ERR;
    }
}

r_s32 rda_sem_release(r_void *sem)
{
    r_s32 res;

    res = osSemaphoreRelease(sem);
    if(res == 0){
        return NO_ERR;
    }else{
        RDA_SYS_PRINT("rda_sem_release error %d\r\n", res);
        return ERR;
    }
}

r_s32 rda_sem_delete(r_void *sem)
{
    r_s32 res;

    res = osSemaphoreDelete(sem);
    r_free(sem);
    if(res == 0){
        return NO_ERR;
    }else{
        RDA_SYS_PRINT("rda_sem_delete error %d\r\n", res);
        return ERR;
    }
}


/* Queue */
r_void* rda_msgQ_create(r_u32 queuesz)
{
    r_void* internal_data;
    osMessageQDef_t msgQ;
    osMessageQId msgQId;

    internal_data = (r_void *)r_malloc((4 + queuesz) * sizeof(r_u32));
    r_memset(internal_data, 0, sizeof((4 + queuesz) * sizeof(r_u32)));
    msgQ.queue_sz = queuesz;
    msgQ.pool = internal_data;
    msgQId = osMessageCreate(&msgQ, NULL);

    return (r_void *)msgQId;
}

r_s32 rda_msg_put(r_void *msgQId, r_u32 msg, r_u32 millisec)
{
    osMessageQId osmsgQId = (osMessageQId)msgQId;
    osStatus res;
    res = osMessagePut(osmsgQId, msg, millisec);
    if(res == osOK)
        return NO_ERR;
    else
        return ERR;
}
r_s32 rda_msg_get(r_void *msgQId, r_u32 *value, r_u32 millisec)
{
    osMessageQId osmsgQId = (osMessageQId)msgQId;
    osEvent evt;
    if(msgQId == NULL){
        RDA_SYS_PRINT("msgQId is NULL\r\n");
        return ERR;
    }
    evt = osMessageGet(osmsgQId, millisec);

    if(evt.status == osEventMessage){
        *value = evt.value.v;
        return NO_ERR;
    }else{
        RDA_SYS_PRINT("message get error, status = %d\r\n", evt.status);
        return ERR;
    }
}

r_void* rda_mail_create(r_u32 msgcnt, r_u32 msgsize)
{
    rda_mail_handle *handle = (rda_mail_handle *)r_malloc(sizeof(rda_mail_handle));
    handle->msgsize = msgsize;
    handle->msgq = rda_msgQ_create(msgcnt);
    if(handle->msgq == NULL)
        return NULL;
    return (r_void*)handle;
}

r_s32 rda_mail_get(r_void *rdahandle, r_void *evt, r_u32 wait)
{
    r_u32 data;
    r_s32 ret;
    rda_mail_handle *handle = (rda_mail_handle *)rdahandle;

    ret = rda_msg_get(handle->msgq, &data, wait);
    if(ret != 0)
        return ret;
    r_memcpy((char *)evt, (r_void *)data, handle->msgsize);
    r_free((r_void*)data);
    return ret;
}

r_s32 rda_mail_put(r_void *rdahandle, r_void *evt, r_u32 wait)
{
    r_s32 ret;
    rda_mail_handle *handle = (rda_mail_handle *)rdahandle;

    r_void* data = r_malloc(handle->msgsize);
    r_memcpy(data, evt, handle->msgsize);
    ret = rda_msg_put(handle->msgq, (r_u32)data, wait);
    return ret;
}

/* Mutex */
r_void* rda_mutex_create(r_void)
{
    osMutexId rdamutex;

    r_u32 *mutex_internal_data = (r_u32 *)r_malloc(sizeof(r_u32) * 4);
    r_memset(mutex_internal_data, 0, sizeof(r_u32) * 4);
    osMutexDef_t mutex_def = {(mutex_internal_data)};

    rdamutex = osMutexCreate(&mutex_def);

    return (r_void *)rdamutex;
}

r_s32 rda_mutex_wait(r_void *rdamutex, r_u32 millisec)
{
    osMutexId mutex = (osMutexId)rdamutex;
    osStatus res;
    res = osMutexWait(mutex, millisec);
    if(res == osOK)
        return NO_ERR;
    else
        return ERR;
}

r_s32 rda_mutex_realease(r_void *rdamutex)
{
    osMutexId mutex = (osMutexId)rdamutex;
    osStatus res;
    res = osMutexRelease(mutex);
    if(res == osOK)
        return NO_ERR;
    else
        return ERR;
}

r_s32 rda_mutex_delete(r_void *rdamutex)
{
    osMutexId mutex = (osMutexId)rdamutex;
    osStatus res;
    res = osMutexDelete(mutex);
    r_free(mutex);
    if(res == osOK)
        return NO_ERR;
    else
        return ERR;
}

/* Thread */
r_void* rda_thread_new(const r_u8 *pcName,
                            r_void (*thread)(r_void *arg),
                            r_void *arg, r_u32 stacksize, r_s32 priority)
{
    osThreadDef_t def;
    osThreadId     id;

#ifdef CMSIS_OS_RTX
    def.pthread = (os_pthread)thread;
    def.tpriority = (osPriority)priority;
    def.stacksize = stacksize;
    def.stack_pointer = (uint32_t*)r_malloc(stacksize);
    if (def.stack_pointer == NULL) {
      RDA_SYS_PRINT("Error allocating the stack memory");
      return NULL;
    }
#endif
    id = osThreadCreate(&def, arg);
    if (id == NULL){
        r_free(def.stack_pointer);
        RDA_SYS_PRINT("sys_thread_new create error\n");
        return NULL;
    }
    return (void *)id;
}

r_s32 rda_thread_delete(r_void* id)
{
    osStatus ret;
    r_u32 *stk = ((P_TCB)id)->stack;
    ret = osThreadTerminate(id);
    r_free(stk);
    if(ret != osOK)
        return ERR;
    return NO_ERR;
}

r_void* rda_thread_get_id(r_void)
{
    osThreadId id = osThreadGetId();
    return (r_void*)id;
}
r_void rda_critical_sec_start(r_void)
{
    if(__get_IPSR() == 0U) {
        if(0U == g_critical_sec_counter) {
#if defined(CONFIG_DISABLE_ALL_INT)
            g_critical_ctxt_saved = __disable_irq();
#else  /* CONFIG_DISABLE_ALL_INT */
            __set_BASEPRI(CRI_SEC_START_PRI_LEVEL);
#endif /* CONFIG_DISABLE_ALL_INT */
        }
        g_critical_sec_counter++;
    }
}

r_void rda_critical_sec_end(r_void)
{
    if(__get_IPSR() == 0U) {
        g_critical_sec_counter--;
        if(0U == g_critical_sec_counter) {
#if defined(CONFIG_DISABLE_ALL_INT)
            __set_PRIMASK(g_critical_ctxt_saved);
#else  /* CONFIG_DISABLE_ALL_INT */
            __set_BASEPRI(CRI_SEC_END_PRI_LEVEL);
#endif /* CONFIG_DISABLE_ALL_INT */
        }
    }
}

r_void * rda_create_interrupt(r_u32 vec, r_u32 pri, r_void *isr)
{
    NVIC_SetPriority((IRQn_Type)vec, (uint32_t) pri);
    NVIC_SetVector((IRQn_Type)vec, (uint32_t) isr);

    return NULL;
}

r_void rda_delete_interrupt(r_u32 vec)
{
    NVIC_SetVector((IRQn_Type)vec, 0);
}

r_void rda_enable_interrupt(r_u32 vec)
{
    NVIC_EnableIRQ((IRQn_Type)vec);
}

r_void rda_disable_interrupt(r_u32 vec)
{
    NVIC_DisableIRQ((IRQn_Type)vec);
}


