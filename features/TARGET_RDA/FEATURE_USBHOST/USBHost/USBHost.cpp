/* mbed USBHost Library
 * Copyright (c) 2006-2013 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "USBHost.h"
#include "USBHostHub.h"

// #define FULL_SPEED   1
USBHost * USBHost::instHost = NULL;

#define DEVICE_CONNECTED_EVENT      (1 << 0)
#define DEVICE_DISCONNECTED_EVENT   (1 << 1)
#define TD_PROCESSED_EVENT          (1 << 2)
#define TD_DISCONNECT_EVENT         (1 << 3)

#define MAX_TRY_ENUMERATE_HUB       3

#define MIN(a, b) ((a > b) ? b : a)

#if defined(TARGET_UNO_91H)
#include "USBHALHost_UNO_91H.h"
#include "USBMsg.h"
extern uint8_t ep0_state;
void *usb_msgQ = NULL;

//#define CONFIG_USB_DEBUG

#ifdef CONFIG_USB_DEBUG
#define USBH_DBG(fmt,args...) \
    mbed_error_printf("DBG: %s " fmt "\r",__PRETTY_FUNCTION__,##args)
#else
#define USBH_DBG(fmt,args...)
#endif  /*CONFIG_USB_DEBUG */

#define CFG_USB_DMA_SHAREMEMORY

#ifdef CFG_USB_DMA
#ifdef CFG_USB_DMA_SHAREMEMORY
#define USBMEM_SECTION __attribute__((section("AHB1SMEM1"),aligned))
#define USB_SHARED_MEMORY_MAX_SIZE  (32*1024)

static uint8_t   USBSharedMeoryStartAddr USBMEM_SECTION;
static uint8_t   *p_left    = &USBSharedMeoryStartAddr;
static uint32_t  size_left = USB_SHARED_MEMORY_MAX_SIZE;
uint32_t *a0;

void *usb_malloc_s(uint32_t size)
{
    if(size > size_left) {
        return (void *)0;
    }
    void *p = p_left;

    size_left -= size;
    p_left    += size;

    return (void *)p;
}
#endif /* CFG_USB_DMA_SHAREMEMORY*/
#endif /* CFG_USB_DMA */
#endif/* TARGET_UNO_91H */

/**
* How interrupts are processed:
*    - new device connected:
*       - a message is queued in queue_usb_event with the id DEVICE_CONNECTED_EVENT
*       - when the usb_thread receives the event, it:
*           - resets the device
*           - reads the device descriptor
*           - sets the address of the device
*           - if it is a hub, enumerates it
*   - device disconnected:
*       - a message is queued in queue_usb_event with the id DEVICE_DISCONNECTED_EVENT
*       - when the usb_thread receives the event, it:
*           - free the device and all its children (hub)
*   - td processed
*       - a message is queued in queue_usb_event with the id TD_PROCESSED_EVENT
*       - when the usb_thread receives the event, it:
*           - call the callback attached to the endpoint where the td is attached
*/
void USBHost::usb_process() {

    bool controlListState;
    bool bulkListState;
    bool interruptListState;
    USBEndpoint * ep;
    uint8_t i, j, res, timeout_set_addr = 3;//10;
    uint8_t buf[8];
    bool too_many_hub;
    int idx;

#if DEBUG_TRANSFER
    uint8_t * buf_transfer;
#endif

#if MAX_HUB_NB
    uint8_t k;
#endif

    while(1) {
        osEvent evt = mail_usb_event.get();

        if (evt.status == osEventMail) {

            message_t * usb_msg = (message_t*)evt.value.p;

            switch (usb_msg->event_id) {

                // a new device has been connected
                case DEVICE_CONNECTED_EVENT:
                    too_many_hub = false;
                    buf[4] = 0;
                    do
                    {
                      Lock lock(this);

                  for (i = 0; i < MAX_DEVICE_CONNECTED; i++) {
                      if (!deviceInUse[i]) {
                          USB_DBG_EVENT("new device connected: %p\r\n", &devices[i]);
                          devices[i].init(usb_msg->hub, usb_msg->port, usb_msg->lowSpeed);
                          deviceReset[i] = false;
                          deviceInited[i] = true;
                          break;
                      }
                  }

                      if (i == MAX_DEVICE_CONNECTED) {
                          USB_ERR("Too many device connected!!\r\n");
                          continue;
                      }

                      if (!controlEndpointAllocated) {
#if !defined(TARGET_UNO_91H)
                          control = newEndpoint(CONTROL_ENDPOINT, OUT, 0x08, 0x00);
                          addEndpoint(NULL, 0, (USBEndpoint*)control);
#endif
                          controlEndpointAllocated = true;
                      }

  #if MAX_HUB_NB
                      if (usb_msg->hub_parent)
                          devices[i].setHubParent((USBHostHub *)(usb_msg->hub_parent));
  #endif

                      for (j = 0; j < timeout_set_addr; j++) {
                          resetDevice(&devices[i]);

                          // set size of control endpoint
                          devices[i].setSizeControlEndpoint(8);

                          devices[i].activeAddress(false);

                          // get first 8 bit of device descriptor
                          // and check if we deal with a hub
                          USB_DBG("usb_thread read device descriptor on dev: %p\r\n", &devices[i]);
                          res = getDeviceDescriptor(&devices[i], buf, 8);

                          if (res != USB_TYPE_OK) {
                              USB_ERR("usb_thread could not read dev descr");
                              continue;
                          }

                          // set size of control endpoint
                          devices[i].setSizeControlEndpoint(buf[7]);

                          // second step: set an address to the device
                          res = setAddress(&devices[i], devices[i].getAddress());

                          if (res != USB_TYPE_OK) {
                              USB_ERR("SET ADDR FAILED");
                              continue;
                          }
                          devices[i].activeAddress(true);
                          USB_DBG("Address of %p: %d", &devices[i], devices[i].getAddress());

                          // try to read again the device descriptor to check if the device
                          // answers to its new address
                          res = getDeviceDescriptor(&devices[i], buf, 8);

                          if (res == USB_TYPE_OK) {
                              break;
                          }

                          Thread::wait(100);
                      }

                     if (j == timeout_set_addr) {
                         if ( res == USB_TYPE_ERROR) {
                             disableList(CONTROL_ENDPOINT);
                             ep0_state = USB_EP0_IDLE;
                            if (i != -1) {
                                freeDevice((USBDeviceConnected*)&devices[i]);
                            }
                             mbed_error_printf("usb enum error %d \r\n", i);
                             break;
                        }

                     }
                      USB_INFO("New device connected: %p [hub: %d - port: %d]", &devices[i], usb_msg->hub, usb_msg->port);
#if defined(TARGET_UNO_91H)
                      usb_msg_put(usb_msgQ, USB_CONNECT, WaitForever);
#endif

  #if MAX_HUB_NB
                      if (buf[4] == HUB_CLASS) {
                          for (k = 0; k < MAX_HUB_NB; k++) {
                              if (hub_in_use[k] == false) {
                                  for (uint8_t j = 0; j < MAX_TRY_ENUMERATE_HUB; j++) {
                                      if (hubs[k].connect(&devices[i])) {
                                          devices[i].hub = &hubs[k];
                                          hub_in_use[k] = true;
                                          break;
                                      }
                                  }
                                  if (hub_in_use[k] == true)
                                      break;
                              }
                          }

                          if (k == MAX_HUB_NB) {
                              USB_ERR("Too many hubs connected!!\r\n");
                              too_many_hub = true;
                          }
                      }

                      if (usb_msg->hub_parent)
                          ((USBHostHub *)(usb_msg->hub_parent))->deviceConnected(&devices[i]);
  #endif

                      if ((i < MAX_DEVICE_CONNECTED) && !too_many_hub) {
                          deviceInUse[i] = true;
                      }

                    } while(0);
                    RDA_USB->INTREN |= (USB_INTR_DISCONNECT|USB_INTR_CONNECT);
                    break;

                // a device has been disconnected
                case DEVICE_DISCONNECTED_EVENT:
                    do
                    {
                      Lock lock(this);

#if !defined(TARGET_UNO_91H)
                      controlListState = disableList(CONTROL_ENDPOINT);
                      bulkListState = disableList(BULK_ENDPOINT);
                      interruptListState = disableList(INTERRUPT_ENDPOINT);
#endif

                      idx = findDevice(usb_msg->hub, usb_msg->port, (USBHostHub *)(usb_msg->hub_parent));
                      if (idx != -1) {
                          freeDevice((USBDeviceConnected*)&devices[idx]);
                      }
#if defined(TARGET_UNO_91H)
                      //usb_msg_put(usb_msgQ, USB_DISCONNECT, WaitForever);
#endif
#if !defined(TARGET_UNO_91H)
                      if (controlListState) enableList(CONTROL_ENDPOINT);
                      if (bulkListState) enableList(BULK_ENDPOINT);
                      if (interruptListState) enableList(INTERRUPT_ENDPOINT);
#endif
                    } while(0);

                    break;

                // a td has been processed
                // call callback on the ed associated to the td
                // we are not in ISR -> users can use printf in their callback method
                case TD_PROCESSED_EVENT:
                    ep = (USBEndpoint *) ((HCTD *)usb_msg->td_addr)->ep;
                    if (usb_msg->td_state == USB_TYPE_IDLE) {
                        USB_DBG_EVENT("call callback on td %p [ep: %p state: %s - dev: %p - %s]", usb_msg->td_addr, ep, ep->getStateString(), ep->dev, ep->dev->getName(ep->getIntfNb()));

#if DEBUG_TRANSFER
                        if (ep->getDir() == IN) {
                            buf_transfer = ep->getBufStart();
                            printf("READ SUCCESS [%d bytes transferred - td: 0x%08X] on ep: [%p - addr: %02X]: ",  ep->getLengthTransferred(), usb_msg->td_addr, ep, ep->getAddress());
                            for (int i = 0; i < ep->getLengthTransferred(); i++)
                                printf("%02X ", buf_transfer[i]);
                            printf("\r\n\r\n");
                        }
#endif
                        ep->call();
                    } else {
                        idx = findDevice(ep->dev);
                        if (idx != -1) {
                            if (deviceInUse[idx]) {
                                USB_WARN("td %p processed but not in idle state: %s [ep: %p - dev: %p - %s]", usb_msg->td_addr, ep->getStateString(), ep, ep->dev, ep->dev->getName(ep->getIntfNb()));
                                ep->setState(USB_TYPE_IDLE);
                            }
                        }
                    }
                    break;
                case TD_DISCONNECT_EVENT:
                    usb_msg_put(usb_msgQ, USB_DISCONNECT, WaitForever);
                    break;
            }

            mail_usb_event.free(usb_msg);
        }
    }
}

USBHost::USBHost() : usbThread(osPriorityNormal, USB_THREAD_STACK)
{
    printf("usb host begin \r\n");
    headControlEndpoint = NULL;
    headBulkEndpoint = NULL;
    headInterruptEndpoint = NULL;
    tailControlEndpoint = NULL;
    tailBulkEndpoint = NULL;
    tailInterruptEndpoint = NULL;

    lenReportDescr = 0;

    controlEndpointAllocated = false;

    for (uint8_t i = 0; i < MAX_DEVICE_CONNECTED; i++) {
        deviceInUse[i] = false;
        devices[i].setAddress(i + 1);
        deviceReset[i] = false;
        deviceInited[i] = false;
        for (uint8_t j = 0; j < MAX_INTF; j++)
            deviceAttachedDriver[i][j] = false;
    }

#if MAX_HUB_NB
    for (uint8_t i = 0; i < MAX_HUB_NB; i++) {
        hubs[i].setHost(this);
        hub_in_use[i] = false;
    }
#endif

#if defined(TARGET_UNO_91H)
#ifdef CFG_USB_DMA
    int len = 32*1024;
    a0 = (uint32_t *)usb_malloc_s(len);
    memset(a0, 0, len);
#endif /* CFG_USB_DMA */
#endif /* TARGET_UNO_91H */
    usbThread.start(this, &USBHost::usb_process);
}

USBHost::Lock::Lock(USBHost* pHost) : m_pHost(pHost)
{
  m_pHost->usb_mutex.lock();
}

USBHost::Lock::~Lock()
{
  m_pHost->usb_mutex.unlock();
}

void USBHost::transferCompleted(volatile uint32_t addr)
{
    uint8_t state;

    if(addr == 0)
        return;

    volatile HCTD* tdList = NULL;

    //First we must reverse the list order and dequeue each TD
    do {
        volatile HCTD* td = (volatile HCTD*)addr;
        addr = (uint32_t)td->nextTD; //Dequeue from physical list
        td->nextTD = (hcTd*)tdList; //Enqueue into reversed list
        tdList = td;
    } while(addr);

    while(tdList != NULL) {
        volatile HCTD* td = tdList;
        tdList = (volatile HCTD*)td->nextTD; //Dequeue element now as it could be modified below
        if (td->ep != NULL) {
            USBEndpoint * ep = (USBEndpoint *)(td->ep);

            if (((HCTD *)td)->control >> 28) {
                state = ((HCTD *)td)->control >> 28;
            } else {
                if (td->currBufPtr)
                    ep->setLengthTransferred((uint32_t)td->currBufPtr - (uint32_t)ep->getBufStart());
                state = 16 /*USB_TYPE_IDLE*/;
            }

            ep->unqueueTransfer(td);

            if (ep->getType() != CONTROL_ENDPOINT) {
                // callback on the processed td will be called from the usb_thread (not in ISR)
                message_t * usb_msg = mail_usb_event.alloc();
                usb_msg->event_id = TD_PROCESSED_EVENT;
                usb_msg->td_addr = (void *)td;
                usb_msg->td_state = state;
                mail_usb_event.put(usb_msg);
            }
            ep->setState(state);
            ep->ep_queue.put((uint8_t*)1);
        }
    }
}

USBHost * USBHost::getHostInst()
{
    if (instHost == NULL) {
        instHost = new USBHost();
        instHost->init();
    }
    return instHost;
}


/*
 * Called when a device has been connected
 * Called in ISR!!!! (no printf)
 */
/* virtual */ void USBHost::deviceConnected(int hub, int port, bool lowSpeed, USBHostHub * hub_parent)
{
    // be sure that the new device connected is not already connected...
    int idx = findDevice(hub, port, hub_parent);
    mbed_error_printf("device connected idx is %d \r\n", idx);
    if (idx != -1) {
        if (deviceInited[idx])
            return;
    }

    message_t * usb_msg = mail_usb_event.alloc();
    usb_msg->event_id = DEVICE_CONNECTED_EVENT;
    usb_msg->hub = hub;
    usb_msg->port = port;
    usb_msg->lowSpeed = lowSpeed;
    usb_msg->hub_parent = hub_parent;
    mail_usb_event.put(usb_msg);
}

/*
 * Called when a device has been disconnected
 * Called in ISR!!!! (no printf)
 */
/* virtual */ void USBHost::deviceDisconnected(int hub, int port, USBHostHub * hub_parent, volatile uint32_t addr)
{
    // be sure that the device disconnected is connected...
    int idx = findDevice(hub, port, hub_parent);
    if (idx != -1) {
        if (!deviceInUse[idx])
            return;
    } else {
        return;
    }

    message_t * usb_msg = mail_usb_event.alloc();
    usb_msg->event_id = DEVICE_DISCONNECTED_EVENT;
    usb_msg->hub = hub;
    usb_msg->port = port;
    usb_msg->hub_parent = hub_parent;
    mail_usb_event.put(usb_msg);
}


#if defined(TARGET_UNO_91H)
void USBHost::deviceDisconnectSendMsg()
{
    mbed_error_printf("disconnect msg send \r\n");
    message_t * usb_msg = mail_usb_event.alloc();
    usb_msg->event_id = TD_DISCONNECT_EVENT;
    mail_usb_event.put(usb_msg);
}

void USBHost::deviceDisconnect(int hub, int port, USBHostHub * hub_parent, volatile uint32_t addr)
{

    int idx;
    // a device has been disconnected
    do
    {
        Lock lock(this);

#if 0
        controlListState = disableList(CONTROL_ENDPOINT);
        bulkListState = disableList(BULK_ENDPOINT);
        interruptListState = disableList(INTERRUPT_ENDPOINT);
#endif
        idx = findDevice(hub, port, hub_parent);
        if (idx != -1) {
            freeDevice((USBDeviceConnected*)&devices[idx]);
        }
    } while(0);
}

#endif

void USBHost::freeDevice(USBDeviceConnected * dev)
{
    USBEndpoint * ep = NULL;
    HCED * ed = NULL;

#if MAX_HUB_NB
    if (dev->getClass() == HUB_CLASS) {
        if (dev->hub == NULL) {
            USB_ERR("HUB NULL!!!!!\r\n");
        } else {
            dev->hub->hubDisconnected();
            for (uint8_t i = 0; i < MAX_HUB_NB; i++) {
                if (dev->hub == &hubs[i]) {
                    hub_in_use[i] = false;
                    break;
                }
            }
        }
    }

    // notify hub parent that this device has been disconnected
    if (dev->getHubParent())
        dev->getHubParent()->deviceDisconnected(dev);

#endif

    int idx = findDevice(dev);
    if (idx != -1) {
        deviceInUse[idx] = false;
        deviceReset[idx] = false;

        for (uint8_t j = 0; j < MAX_INTF; j++) {
            deviceAttachedDriver[idx][j] = false;
            if (dev->getInterface(j) != NULL) {
                USB_DBG("FREE INTF %d on dev: %p, %p, nb_endpot: %d, %s", j, (void *)dev->getInterface(j), dev, dev->getInterface(j)->nb_endpoint, dev->getName(j));
                for (int i = 0; i < dev->getInterface(j)->nb_endpoint; i++) {
#if !defined(TARGET_UNO_91H)
                    if ((ep = dev->getEndpoint(j, i)) != NULL) {
                        ed = (HCED *)ep->getHCED();
                        ed->control |= (1 << 14); //sKip bit
                        unqueueEndpoint(ep);

                        freeTD((volatile uint8_t*)ep->getTDList()[0]);
                        freeTD((volatile uint8_t*)ep->getTDList()[1]);

                        freeED((uint8_t *)ep->getHCED());
                    }
                    printList(BULK_ENDPOINT);
                    printList(INTERRUPT_ENDPOINT);
#endif
                }
                USB_INFO("Device disconnected [%p - %s - hub: %d - port: %d]", dev, dev->getName(j), dev->getHub(), dev->getPort());
            }
        }
        dev->disconnect();
    }
}


void USBHost::unqueueEndpoint(USBEndpoint * ep)
{
    USBEndpoint * prec = NULL;
    USBEndpoint * current = NULL;

    for (int i = 0; i < 2; i++) {
        current = (i == 0) ? (USBEndpoint*)headBulkEndpoint : (USBEndpoint*)headInterruptEndpoint;
        prec = current;
        while (current != NULL) {
            if (current == ep) {
                if (current->nextEndpoint() != NULL) {
                    prec->queueEndpoint(current->nextEndpoint());
                    if (current == headBulkEndpoint) {
                        updateBulkHeadED((uint32_t)current->nextEndpoint()->getHCED());
                        headBulkEndpoint = current->nextEndpoint();
                    } else if (current == headInterruptEndpoint) {
                        updateInterruptHeadED((uint32_t)current->nextEndpoint()->getHCED());
                        headInterruptEndpoint = current->nextEndpoint();
                    }
                }
                // here we are dequeuing the queue of ed
                // we need to update the tail pointer
                else {
                    prec->queueEndpoint(NULL);
                    if (current == headBulkEndpoint) {
                        updateBulkHeadED(0);
                        headBulkEndpoint = current->nextEndpoint();
                    } else if (current == headInterruptEndpoint) {
                        updateInterruptHeadED(0);
                        headInterruptEndpoint = current->nextEndpoint();
                    }

                    // modify tail
                    switch (current->getType()) {
                        case BULK_ENDPOINT:
                            tailBulkEndpoint = prec;
                            break;
                        case INTERRUPT_ENDPOINT:
                            tailInterruptEndpoint = prec;
                            break;
                        default:
                            break;
                    }
                }
                current->setState(USB_TYPE_FREE);
                return;
            }
            prec = current;
            current = current->nextEndpoint();
        }
    }
}


USBDeviceConnected * USBHost::getDevice(uint8_t index)
{
    if ((index >= MAX_DEVICE_CONNECTED) || (!deviceInUse[index])) {
        return NULL;
    }
    return (USBDeviceConnected*)&devices[index];
}

void init_hw_ep(uint8_t endpoint, uint32_t maxPacket, ENDPOINT_DIRECTION dir)
{
    uint8_t index;
    uint16_t int_rxe;
    uint16_t int_txe;

    /* select endpoint */
    index = RDA_USB->EPIDX;
    USBH_DBG(" init_hw_ep index is 0x%02x \r\n ",index);
    RDA_USB->EPIDX = endpoint;
    switch (dir) {
        case IN:
            USBH_DBG("init_hw_ep  out \r\n ");
            int_rxe = RDA_USB->INTRRXEN;
            /* Enable endpoint interrupt */
            int_rxe |= BIT(endpoint);
            USBH_DBG("init_hw_ep out  int_rxe is 0x%02x , csr is 0x%04x\r\n ",int_rxe,RDA_USB->RXCSR);
            RDA_USB->INTRRXEN = int_rxe;
            break;
        case OUT:
            int_txe = RDA_USB->INTRTXEN;
            /* Enable endpoint interrupt */
            int_txe |= BIT(endpoint);
            USBH_DBG(" init_hw_ep in int_txe is 0x%02x , csr is 0x%04x\r\n ",int_txe,RDA_USB->TXCSR);
            RDA_USB->INTRTXEN = int_txe;
            break;
    }
    RDA_USB->EPIDX = 0;
}

// create an USBEndpoint descriptor. the USBEndpoint is not linked
USBEndpoint * USBHost::newEndpoint(ENDPOINT_TYPE type, ENDPOINT_DIRECTION dir, uint32_t size, uint8_t addr)
{
#if defined(TARGET_UNO_91H)
    int i = 0;

    // search a free USBEndpoint
    for (i = 0; i < MAX_ENDPOINT; i++) {
        if (endpoints[i].getState() == USB_TYPE_FREE) {
            if (dir == OUT) {
                out_transfer.direction = dir;
                /* host out ep num : 2 */
                out_transfer.ep_num = EPBULK_OUT;
                /* device ep num */
                out_transfer.dev_epnum = addr;
                endpoints[i].init(&out_transfer, type, dir, size, addr);
                init_hw_ep(out_transfer.ep_num, size, dir);

            } else if (dir == IN) {
                in_transfer.direction = dir;
                /* host in ep num : 1 */
                in_transfer.ep_num = EPBULK_IN;
                /* device ep num */
                in_transfer.dev_epnum = addr;
                endpoints[i].init(&in_transfer, type, dir, size, addr);
                init_hw_ep(in_transfer.ep_num, size, dir);
            }
            USB_INFO("USBEndpoint created (%p): type: %d, dir: %d, size: %d, addr: %d, state: %s", &endpoints[i], type, dir, size, addr, endpoints[i].getStateString());
            return &endpoints[i];
        }
    }
    USB_ERR("could not allocate more endpoints!!!!");
    return NULL;
#else
    int i = 0;
    HCED * ed = (HCED *)getED();
    HCTD* td_list[2] = { (HCTD*)getTD(), (HCTD*)getTD() };

    memset((void *)td_list[0], 0x00, sizeof(HCTD));
    memset((void *)td_list[1], 0x00, sizeof(HCTD));

    // search a free USBEndpoint
    for (i = 0; i < MAX_ENDPOINT; i++) {
        if (endpoints[i].getState() == USB_TYPE_FREE) {
            endpoints[i].init(ed, type, dir, size, addr, td_list);
            USB_DBG("USBEndpoint created (%p): type: %d, dir: %d, size: %d, addr: %d, state: %s", &endpoints[i], type, dir, size, addr, endpoints[i].getStateString());
            return &endpoints[i];
        }
    }
    USB_ERR("could not allocate more endpoints!!!!");
    return NULL;
#endif
}


USB_TYPE USBHost::resetDevice(USBDeviceConnected * dev)
{
    int index = findDevice(dev);
    if (index != -1) {
        USB_DBG("Resetting hub %d, port %d\n", dev->getHub(), dev->getPort());
        Thread::wait(100);
        if (dev->getHub() == 0) {
            resetRootHub();
        }
#if MAX_HUB_NB
        else {
            dev->getHubParent()->portReset(dev->getPort());
        }
#endif

#if defined(TARGET_UNO_91H)
        wait(0.5);
        USB_DBG("resetDevice begin \n");

        uint8_t power = 0;

#ifndef FULL_SPEED
        power = RDA_USB->POWER;

        power &= USB_POWER_HSENAB;
#endif
        RDA_USB->POWER = power | USB_POWER_RESET;
        wait(0.02);
        RDA_USB->POWER = power & ~USB_POWER_RESET;

        /*double reset to avoid suspend */
        wait(0.01);
        RDA_USB->POWER = power | USB_POWER_RESET;
        wait(0.03);
        RDA_USB->POWER = power & ~USB_POWER_RESET;

        power = RDA_USB->POWER;
        if(power & USB_POWER_HSMODE){
            USB_DBG("resetDevice HIGH speed device connect \n");
            wait(0.5);
        }
#endif
        Thread::wait(100);
        deviceReset[index] = true;
        return USB_TYPE_OK;
    }

    return USB_TYPE_ERROR;
}

// link the USBEndpoint to the linked list and attach an USBEndpoint to a device
bool USBHost::addEndpoint(USBDeviceConnected * dev, uint8_t intf_nb, USBEndpoint * ep)
{

    if (ep == NULL) {
        return false;
    }
#if defined(TARGET_UNO_91H)
    USB_DBG("ADD USBEndpoint enter 91h");
    ep->setIntfNb(intf_nb);
#else
    HCED * prevEd;

    // set device address in the USBEndpoint descriptor
    if (dev == NULL) {
        ep->setDeviceAddress(0);
    } else {
        ep->setDeviceAddress(dev->getAddress());
    }

    if ((dev != NULL) && dev->getSpeed()) {
        ep->setSpeed(dev->getSpeed());
    }

    ep->setIntfNb(intf_nb);

    // queue the new USBEndpoint on the ED list
    switch (ep->getType()) {

        case CONTROL_ENDPOINT:
            prevEd = ( HCED*) controlHeadED();
            if (!prevEd) {
                updateControlHeadED((uint32_t) ep->getHCED());
                USB_DBG_TRANSFER("First control USBEndpoint: %08X", (uint32_t) ep->getHCED());
                headControlEndpoint = ep;
                tailControlEndpoint = ep;
                return true;
            }
            tailControlEndpoint->queueEndpoint(ep);
            tailControlEndpoint = ep;
            return true;

        case BULK_ENDPOINT:
            prevEd = ( HCED*) bulkHeadED();
            if (!prevEd) {
                updateBulkHeadED((uint32_t) ep->getHCED());
                USB_DBG_TRANSFER("First bulk USBEndpoint: %08X\r\n", (uint32_t) ep->getHCED());
                headBulkEndpoint = ep;
                tailBulkEndpoint = ep;
                break;
            }
            USB_DBG_TRANSFER("Queue BULK Ed %p after %p\r\n",ep->getHCED(), prevEd);
            tailBulkEndpoint->queueEndpoint(ep);
            tailBulkEndpoint = ep;
            break;

        case INTERRUPT_ENDPOINT:
            prevEd = ( HCED*) interruptHeadED();
            if (!prevEd) {
                updateInterruptHeadED((uint32_t) ep->getHCED());
                USB_DBG_TRANSFER("First interrupt USBEndpoint: %08X\r\n", (uint32_t) ep->getHCED());
                headInterruptEndpoint = ep;
                tailInterruptEndpoint = ep;
                break;
            }
            USB_DBG_TRANSFER("Queue INTERRUPT Ed %p after %p\r\n",ep->getHCED(), prevEd);
            tailInterruptEndpoint->queueEndpoint(ep);
            tailInterruptEndpoint = ep;
            break;
        default:
            return false;
    }
#endif

    ep->dev = dev;
    dev->addEndpoint(intf_nb, ep);

    return true;
}


int USBHost::findDevice(USBDeviceConnected * dev)
{
    for (int i = 0; i < MAX_DEVICE_CONNECTED; i++) {
        if (dev == &devices[i]) {
            return i;
        }
    }
    return -1;
}

int USBHost::findDevice(uint8_t hub, uint8_t port, USBHostHub * hub_parent)
{
    for (int i = 0; i < MAX_DEVICE_CONNECTED; i++) {
        if (devices[i].getHub() == hub && devices[i].getPort() == port) {
            if (hub_parent != NULL) {
                if (hub_parent == devices[i].getHubParent())
                    return i;
            } else {
                return i;
            }
        }
    }
    return -1;
}

void USBHost::printList(ENDPOINT_TYPE type)
{
#if DEBUG_EP_STATE
    volatile HCED * hced;
    switch(type) {
        case CONTROL_ENDPOINT:
            hced = (HCED *)controlHeadED();
            break;
        case BULK_ENDPOINT:
            hced = (HCED *)bulkHeadED();
            break;
        case INTERRUPT_ENDPOINT:
            hced = (HCED *)interruptHeadED();
            break;
    }
    volatile HCTD * hctd = NULL;
    const char * type_str = (type == BULK_ENDPOINT) ? "BULK" :
                            ((type == INTERRUPT_ENDPOINT) ? "INTERRUPT" :
                            ((type == CONTROL_ENDPOINT) ? "CONTROL" : "ISOCHRONOUS"));
    printf("State of %s:\r\n", type_str);
    while (hced != NULL) {
        uint8_t dir = ((hced->control & (3 << 11)) >> 11);
        printf("hced: %p [ADDR: %d, DIR: %s, EP_NB: 0x%X]\r\n", hced,
                                                   hced->control & 0x7f,
                                                   (dir == 1) ? "OUT" : ((dir == 0) ? "FROM_TD":"IN"),
                                                    (hced->control & (0xf << 7)) >> 7);
        hctd = (HCTD *)((uint32_t)(hced->headTD) & ~(0xf));
        while (hctd != hced->tailTD) {
            printf("\thctd: %p [DIR: %s]\r\n", hctd, ((hctd->control & (3 << 19)) >> 19) == 1 ? "OUT" : "IN");
            hctd = hctd->nextTD;
        }
        printf("\thctd: %p\r\n", hctd);
        hced = hced->nextED;
    }
    printf("\r\n\r\n");
#endif
}


// add a transfer on the TD linked list
USB_TYPE USBHost::addTransfer(USBEndpoint * ed, uint8_t * buf, uint32_t len)
{
    td_mutex.lock();

    // allocate a TD which will be freed in TDcompletion
    volatile HCTD * td = ed->getNextTD();
    if (td == NULL) {
        return USB_TYPE_ERROR;
    }

    uint32_t token = (ed->isSetup() ? TD_SETUP : ( (ed->getDir() == IN) ? TD_IN : TD_OUT ));

    uint32_t td_toggle;

    if (ed->getType() == CONTROL_ENDPOINT) {
        if (ed->isSetup()) {
            td_toggle = TD_TOGGLE_0;
        } else {
            td_toggle = TD_TOGGLE_1;
        }
    } else {
        td_toggle = 0;
    }

    td->control      = (TD_ROUNDING | token | TD_DELAY_INT(0) | td_toggle | TD_CC);
    td->currBufPtr   = buf;
    td->bufEnd       = (buf + (len - 1));

    ENDPOINT_TYPE type = ed->getType();

    disableList(type);
    ed->queueTransfer();
    printList(type);
    enableList(type);

    td_mutex.unlock();

    return USB_TYPE_PROCESSING;
}



USB_TYPE USBHost::getDeviceDescriptor(USBDeviceConnected * dev, uint8_t * buf, uint16_t max_len_buf, uint16_t * len_dev_descr)
{
    USB_TYPE t = controlRead(  dev,
                         USB_DEVICE_TO_HOST | USB_RECIPIENT_DEVICE,
                         GET_DESCRIPTOR,
                         (DEVICE_DESCRIPTOR << 8) | (0),
                         0, buf, MIN(DEVICE_DESCRIPTOR_LENGTH, max_len_buf));
    if (len_dev_descr)
        *len_dev_descr = MIN(DEVICE_DESCRIPTOR_LENGTH, max_len_buf);

    return t;
}

USB_TYPE USBHost::getConfigurationDescriptor(USBDeviceConnected * dev, uint8_t * buf, uint16_t max_len_buf, uint16_t * len_conf_descr)
{
    USB_TYPE res;
    uint16_t total_conf_descr_length = 0;

    // fourth step: get the beginning of the configuration descriptor to have the total length of the conf descr
    res = controlRead(  dev,
                        USB_DEVICE_TO_HOST | USB_RECIPIENT_DEVICE,
                        GET_DESCRIPTOR,
                        (CONFIGURATION_DESCRIPTOR << 8) | (0),
                        0, buf, CONFIGURATION_DESCRIPTOR_LENGTH);

    if (res != USB_TYPE_OK) {
        USB_ERR("GET CONF 1 DESCR FAILED");
        return res;
    }
    total_conf_descr_length = buf[2] | (buf[3] << 8);
    total_conf_descr_length = MIN(max_len_buf, total_conf_descr_length);

    if (len_conf_descr)
        *len_conf_descr = total_conf_descr_length;

    USB_DBG("TOTAL_LENGTH: %d \t NUM_INTERF: %d", total_conf_descr_length, buf[4]);

    return controlRead(  dev,
                         USB_DEVICE_TO_HOST | USB_RECIPIENT_DEVICE,
                         GET_DESCRIPTOR,
                         (CONFIGURATION_DESCRIPTOR << 8) | (0),
                         0, buf, total_conf_descr_length);
}


USB_TYPE USBHost::setAddress(USBDeviceConnected * dev, uint8_t address) {
    return controlWrite(    dev,
                            USB_HOST_TO_DEVICE | USB_RECIPIENT_DEVICE,
                            SET_ADDRESS,
                            address,
                            0, NULL, 0);

}

USB_TYPE USBHost::setConfiguration(USBDeviceConnected * dev, uint8_t conf)
{
    return controlWrite( dev,
                         USB_HOST_TO_DEVICE | USB_RECIPIENT_DEVICE,
                         SET_CONFIGURATION,
                         conf,
                         0, NULL, 0);
}

uint8_t USBHost::numberDriverAttached(USBDeviceConnected * dev) {
    int index = findDevice(dev);
    uint8_t cnt = 0;
    if (index == -1)
        return 0;
    for (uint8_t i = 0; i < MAX_INTF; i++) {
        if (deviceAttachedDriver[index][i])
            cnt++;
    }
    return cnt;
}

// enumerate a device with the control USBEndpoint
USB_TYPE USBHost::enumerate(USBDeviceConnected * dev, IUSBEnumerator* pEnumerator)
{
    uint16_t total_conf_descr_length = 0;
    USB_TYPE res;

    do
    {
      Lock lock(this);

      // don't enumerate a device which all interfaces are registered to a specific driver
      int index = findDevice(dev);

      if (index == -1) {
          return USB_TYPE_ERROR;
      }

      uint8_t nb_intf_attached = numberDriverAttached(dev);
      USB_DBG("dev: %p nb_intf: %d", dev, dev->getNbIntf());
      USB_DBG("dev: %p nb_intf_attached: %d", dev, nb_intf_attached);
      if ((nb_intf_attached != 0) && (dev->getNbIntf() == nb_intf_attached)) {
          USB_DBG("Don't enumerate dev: %p because all intf are registered with a driver", dev);
          return USB_TYPE_OK;
      }

      USB_DBG("Enumerate dev: %p", dev);

      // third step: get the whole device descriptor to see vid, pid
      res = getDeviceDescriptor(dev, data, DEVICE_DESCRIPTOR_LENGTH);

      if (res != USB_TYPE_OK) {
          USB_DBG("GET DEV DESCR FAILED");
          return res;
      }

      dev->setClass(data[4]);
      dev->setSubClass(data[5]);
      dev->setProtocol(data[6]);
      dev->setVid(data[8] | (data[9] << 8));
      dev->setPid(data[10] | (data[11] << 8));
      USB_DBG("CLASS: %02X \t VID: %04X \t PID: %04X", data[4], data[8] | (data[9] << 8), data[10] | (data[11] << 8));

      pEnumerator->setVidPid( data[8] | (data[9] << 8), data[10] | (data[11] << 8) );

      res = getConfigurationDescriptor(dev, data, sizeof(data), &total_conf_descr_length);
      if (res != USB_TYPE_OK) {
          return res;
      }

  #if (DEBUG > 3)
      USB_DBG("CONFIGURATION DESCRIPTOR:\r\n");
      for (int i = 0; i < total_conf_descr_length; i++)
          printf("%02X ", data[i]);
      printf("\r\n\r\n");
  #endif

      // Parse the configuration descriptor
      parseConfDescr(dev, data, total_conf_descr_length, pEnumerator);

      // only set configuration if not enumerated before
      if (!dev->isEnumerated()) {

          USB_DBG("Set configuration 1 on dev: %p", dev);
          // sixth step: set configuration (only 1 supported)
          res = setConfiguration(dev, 1);

          if (res != USB_TYPE_OK) {
              USB_DBG("SET CONF FAILED");
              return res;
          }
      }

      dev->setEnumerated();

      // Now the device is enumerated!
      USB_DBG("dev %p is enumerated\r\n", dev);

    } while(0);

    // Some devices may require this delay
    Thread::wait(100);

    return USB_TYPE_OK;
}
// this method fills the USBDeviceConnected object: class,.... . It also add endpoints found in the descriptor.
void USBHost::parseConfDescr(USBDeviceConnected * dev, uint8_t * conf_descr, uint32_t len, IUSBEnumerator* pEnumerator)
{
    uint32_t index = 0;
    uint32_t len_desc = 0;
    uint8_t id = 0;
    int nb_endpoints_used = 0;
    USBEndpoint * ep = NULL;
    uint8_t intf_nb = 0;
    bool parsing_intf = false;
    uint8_t current_intf = 0;

    while (index < len) {
        len_desc = conf_descr[index];
        id = conf_descr[index+1];
        switch (id) {
            case CONFIGURATION_DESCRIPTOR:
                USB_DBG("dev: %p has %d intf", dev, conf_descr[4]);
                dev->setNbIntf(conf_descr[4]);
                break;
            case INTERFACE_DESCRIPTOR:
                if(pEnumerator->parseInterface(conf_descr[index + 2], conf_descr[index + 5], conf_descr[index + 6], conf_descr[index + 7])) {
                    if (intf_nb++ <= MAX_INTF) {
                        current_intf = conf_descr[index + 2];
                        dev->addInterface(current_intf, conf_descr[index + 5], conf_descr[index + 6], conf_descr[index + 7]);
                        nb_endpoints_used = 0;
                        USB_DBG("ADD INTF %d on device %p: class: %d, subclass: %d, proto: %d", current_intf, dev, conf_descr[index + 5],conf_descr[index + 6],conf_descr[index + 7]);
                    } else {
                        USB_DBG("Drop intf...");
                    }
                    parsing_intf = true;
                } else {
                    parsing_intf = false;
                }
                break;
            case ENDPOINT_DESCRIPTOR:
                if (parsing_intf && (intf_nb <= MAX_INTF) ) {
                    if (nb_endpoints_used < MAX_ENDPOINT_PER_INTERFACE) {
                        if( pEnumerator->useEndpoint(current_intf, (ENDPOINT_TYPE)(conf_descr[index + 3] & 0x03), (ENDPOINT_DIRECTION)((conf_descr[index + 2] >> 7) + 1)) ) {
                            // if the USBEndpoint is isochronous -> skip it (TODO: fix this)
                            if ((conf_descr[index + 3] & 0x03) != ISOCHRONOUS_ENDPOINT) {
                                ep = newEndpoint((ENDPOINT_TYPE)(conf_descr[index+3] & 0x03),
                                                 (ENDPOINT_DIRECTION)((conf_descr[index + 2] >> 7) + 1),
                                                 conf_descr[index + 4] | (conf_descr[index + 5] << 8),
                                                 conf_descr[index + 2] & 0x0f);
                                USB_DBG("ADD USBEndpoint %p, on interf %d on device %p", ep, current_intf, dev);
                                if (ep != NULL && dev != NULL) {
                                    addEndpoint(dev, current_intf, ep);
                                } else {
                                    USB_DBG("EP NULL");
                                }
                                nb_endpoints_used++;
                            } else {
                                USB_DBG("ISO USBEndpoint NOT SUPPORTED");
                            }
                        }
                    }
                }
                break;
            case HID_DESCRIPTOR:
                lenReportDescr = conf_descr[index + 7] | (conf_descr[index + 8] << 8);
                break;
            default:
                break;
        }
        index += len_desc;
    }
}




USB_TYPE USBHost::interruptWrite(USBDeviceConnected * dev, USBEndpoint * ep, uint8_t * buf, uint32_t len, bool blocking)
{
    return generalTransfer(dev, ep, buf, len, blocking, INTERRUPT_ENDPOINT, true);
}

USB_TYPE USBHost::interruptRead(USBDeviceConnected * dev, USBEndpoint * ep, uint8_t * buf, uint32_t len, bool blocking)
{
    return generalTransfer(dev, ep, buf, len, blocking, INTERRUPT_ENDPOINT, false);
}

USB_TYPE USBHost::generalTransfer(USBDeviceConnected * dev, USBEndpoint * ep, uint8_t * buf, uint32_t len, bool blocking, ENDPOINT_TYPE type, bool write) {

#if DEBUG_TRANSFER
    const char * type_str = (type == BULK_ENDPOINT) ? "BULK" : ((type == INTERRUPT_ENDPOINT) ? "INTERRUPT" : "ISOCHRONOUS");
    USB_DBG_TRANSFER("----- %s %s [dev: %p - %s - hub: %d - port: %d - addr: %d - ep: %02X]------", type_str, (write) ? "WRITE" : "READ", dev, dev->getName(ep->getIntfNb()), dev->getHub(), dev->getPort(), dev->getAddress(), ep->getAddress());
#endif

    Lock lock(this);

    USB_TYPE res;
    ENDPOINT_DIRECTION dir = (write) ? OUT : IN;

    if (dev == NULL) {
        USB_ERR("dev NULL");
        return USB_TYPE_ERROR;
    }

    if (ep == NULL) {
        USB_ERR("ep NULL");
        return USB_TYPE_ERROR;
    }

    if (ep->getState() != USB_TYPE_IDLE) {
        USB_WARN("[ep: %p - dev: %p - %s] NOT IDLE: %s", ep, ep->dev, ep->dev->getName(ep->getIntfNb()), ep->getStateString());
        return ep->getState();
    }

    if ((ep->getDir() != dir) || (ep->getType() != type)) {
        USB_ERR("[ep: %p - dev: %p] wrong dir or bad USBEndpoint type", ep, ep->dev);
        return USB_TYPE_ERROR;
    }

    if (dev->getAddress() != ep->getDeviceAddress()) {
        USB_ERR("[ep: %p - dev: %p] USBEndpoint addr and device addr don't match", ep, ep->dev);
        return USB_TYPE_ERROR;
    }

#if DEBUG_TRANSFER
    if (write) {
        USB_DBG_TRANSFER("%s WRITE buffer", type_str);
        for (int i = 0; i < ep->getLengthTransferred(); i++)
            printf("%02X ", buf[i]);
        printf("\r\n\r\n");
    }
#endif
    addTransfer(ep, buf, len);

    if (blocking) {

        ep->ep_queue.get();
        res = ep->getState();

        USB_DBG_TRANSFER("%s TRANSFER res: %s on ep: %p\r\n", type_str, ep->getStateString(), ep);

        if (res != USB_TYPE_IDLE) {
            return res;
        }

        return USB_TYPE_OK;
    }

    return USB_TYPE_PROCESSING;

}

#if defined(TARGET_UNO_91H)
USB_TYPE USBHost::controlRead(USBDeviceConnected* dev, uint8_t requestType, uint8_t request, uint32_t value, uint32_t index, uint8_t * buf, uint32_t len) {
    uint8_t addr = 0;
    int timeout = 2000;

    fillControlTransfer(requestType, request, value, index, len, &transfer.setup);
    transfer.buffer_len= len;
    transfer.actual = 0;
    transfer.ptr = buf;
    transfer.direction = requestType & USB_DEVICE_TO_HOST;
    transfer.notify = false;

    USB_DBG("[controlRead]  requestType is %02x ", requestType);
    USB_DBG("[controlRead]  request is %02x  ", request);
    USB_DBG("[controlRead]  value is %08x ", value);
    USB_DBG("[controlRead]  index is %08x ", index);
    USB_DBG("[controlRead]  len is %d ", len);
    //mbed_error_printf("ep0_state is %d \r\n", ep0_state);
    if (!dev->isEnumerated()) {
        if (dev->isActiveAddress()) {
            addr = dev->getAddress();
        } else {
            addr = 0;
        }
        RDA_USB->FUNC_ADDR= addr & 0x7f;
        USB_DBG("controlRead addr is %d",addr);
    }

    if (ep0_state == USB_EP0_IDLE)
        control_transfer((uint8_t *)&transfer.setup, 8);
    USB_DBG("controlRead notify is %d",transfer.notify );

    wait(0.01);
#if 1
    while (--timeout) {
        if (out_transfer.notify == true || timeout == 1 ) {
            break;
        }
        //wait_ms(1);
    }
#else
    while (transfer.notify != true) {
        ;
    }
#endif

    if (transfer.notify == true)
        return USB_TYPE_OK;
    else
        return USB_TYPE_ERROR;
}


USB_TYPE USBHost::controlWrite(USBDeviceConnected* dev, uint8_t requestType, uint8_t request, uint32_t value, uint32_t index, uint8_t * buf, uint32_t len) {
    return controlRead(dev,requestType,request,value,index,buf,len);
}

void USBHost::fillControlTransfer(uint8_t requestType, uint8_t request, uint16_t value, uint16_t index, int len, SETUP_PACKET *packet)
{
    /* Fill in the elements of a SETUP_PACKET structure from raw data */
    packet->bmRequestType = requestType;
    packet->bRequest = request;
    packet->wValue = value;
    packet->wIndex = index;
    packet->wLength = len;
}

bool USBHost::EP0Continue(void)
{
    uint32_t len = 0;
    uint32_t fifo_count;
    uint8_t *fifo_dest;
    bool more = false;
    USBH_DBG("EP0Continue ep0_state is %d \r\n", ep0_state);
    switch (ep0_state) {
        case USB_EP0_IN:
            if (RDA_USB->CSR0 & USB_CSR0_RXPKTRDY)
                len = RDA_USB->RXCOUNT0;
            fifo_count = MIN(len, (transfer.buffer_len- transfer.actual));
            fifo_dest = transfer.ptr + transfer.actual;
            HostEndpointRead(0, fifo_dest, fifo_count);
            transfer.actual += fifo_count;
            if(transfer.actual < transfer.buffer_len)
                more = true;
            break;
        case USB_EP0_START:
            if (!transfer.setup.wLength) {
                USBH_DBG("EP0Continue start-no-data \r\n");
                break;
            } else if (transfer.setup.bmRequestType & USB_DEVICE_TO_HOST) {
                USBH_DBG("EP0Continue usb_ep0_in \r\n");
                ep0_state = USB_EP0_IN;
                more = true;
                break;
            } else {
                USBH_DBG("EP0Continue start-out-data \r\n");
                ep0_state = USB_EP0_OUT;
                more = true;
                break;
            }
        case USB_EP0_OUT:
            break;
    }
    return more;
}

bool USBHost::EP0Status(void)
{
    USBH_DBG("EP0Status enter\r\n");
    return ((!(transfer.setup.bmRequestType & USB_DEVICE_TO_HOST)) || (!transfer.buffer_len));
}

void USBHost::EP0Complete(void)
{
    USBH_DBG("EP0Complete enter\r\n");
    transfer.notify = true;
}

void USBHost::OutEpCallback(uint8_t endpoint)
{
    uint16_t tx_csr;
    int status = 0;
    uint32_t load_count;
    uint8_t *buffer;
    uint32_t len;
    uint8_t ep_num;

    USBH_DBG("OutEpCallback enter endpoint is %d\r\n", endpoint);
    /* select endpoint */
    RDA_USB->EPIDX = endpoint;
    tx_csr = RDA_USB->TXCSR;
    if (out_transfer.notify == true)
        return;
    USBH_DBG("OutEpCallback enter tx_csr is 0x%04x\r\n", tx_csr);

    if (tx_csr & USB_TXCSR_H_WZC_BITS) {
        if (tx_csr & USB_TXCSR_H_RXSTALL) {
            status = -1;
            USBH_DBG("OutEpCallback USB_TXCSR_H_RXSTALL tx_csr is 0x%04x\r\n", tx_csr);
        } else if (tx_csr & USB_TXCSR_H_ERROR) {
            USBH_DBG("OutEpCallback enter USB_TXCSR_H_ERROR is 0x%04x\r\n", tx_csr);
            status = -1;
        } else if (tx_csr & USB_TXCSR_H_NAKTIMEOUT) {
            if (tx_csr & USB_TXCSR_DMAENAB) {
                tx_csr &= ~USB_TXCSR_H_WZC_BITS;
                RDA_USB->TXCSR = tx_csr;
                tx_csr |= USB_TXCSR_AUTOSET;
                RDA_USB->TXCSR = tx_csr;
            } else {
                tx_csr = RDA_USB->TXCSR;
                tx_csr &= ~USB_TXCSR_H_NAKTIMEOUT;
                tx_csr |= USB_TXCSR_TXPKTRDY;
                wait(0.001);
                RDA_USB->TXCSR = tx_csr;
            }
            return;
        }
    }

    if (status) {
        tx_csr = RDA_USB->TXCSR;
            tx_csr &= ~(USB_TXCSR_H_NAKTIMEOUT
            | USB_TXCSR_AUTOSET
            | USB_TXCSR_DMAENAB
            | USB_TXCSR_H_RXSTALL
            | USB_TXCSR_H_ERROR);
        RDA_USB->TXCSR = tx_csr;
        RDA_USB->TXCSR = tx_csr;
        RDA_USB->TXINTERVAL = 0;
    }

    if (!status) {
        if (tx_csr & USB_TXCSR_TXPKTRDY)
            return;
    }
    if (out_transfer.actual == out_transfer.buffer_len) {
        out_transfer.notify = true;
    } else {
            USBH_DBG("actual is %d , buffer_len is %d \r\n",out_transfer.actual,out_transfer.buffer_len);
            len = out_transfer.buffer_len - out_transfer.actual;
            load_count = MIN(len, 512);
            buffer = out_transfer.ptr + out_transfer.actual;
            ep_num = out_transfer.ep_num;

            HostEndpointWrite(ep_num, buffer, load_count);
            out_transfer.actual += load_count;
    }
    USBH_DBG("OutEpCallback enter notify is %d\r\n", out_transfer.notify);
    return;
}

void USBHost::InEpCallback(uint8_t endpoint)
{
    uint16_t csr;
    uint16_t rxcount;
    uint16_t val;
    uint8_t *buf;
    uint32_t length;
    bool done = false;

    USBH_DBG("INEpCallback enter endpoint is %d\r\n", endpoint);
    /* select endpoint */
    RDA_USB->EPIDX = endpoint;
    csr = RDA_USB->RXCSR;
    rxcount = RDA_USB->RXCOUNT;
    val = csr;
    USBH_DBG("INEpCallback enter csr is 0x%04x, notify is %d\r\n", csr,in_transfer.notify);

    if (in_transfer.notify == true)
        return;

    if ((csr & USB_RXCSR_H_ERR_BITS) || !(csr & USB_RXCSR_RXPKTRDY)) {
        switch(csr & USB_RXCSR_H_WZC_BITS)
        {
            case USB_RXCSR_H_RXSTALL:
                USBH_DBG("INEpCallback USB_RXCSR_H_RXSTALL \r\n");
                break;
            case USB_RXCSR_H_ERROR:
                USBH_DBG("INEpCallback USB_RXCSR_H_ERROR \r\n");
                break;
            case USB_RXCSR_DATAERROR:
                USBH_DBG("INEpCallback USB_RXCSR_DATAERROR \r\n");
                break;
            case USB_RXCSR_INCOMPRX:
                USBH_DBG("INEpCallback USB_RXCSR_INCOMPRX \r\n");
                break;
            default:
                break;
        }
        RDA_USB->RXCSR = (csr & ~USB_RXCSR_H_ERR_BITS);

        if (!(csr & USB_RXCSR_H_REQPKT))
            RDA_USB->RXCSR = val;
        return;
    }

    if (csr & USB_RXCSR_DMAENAB) {
        //todo: dma by liliu
    }

    USBH_DBG("INEpCallback  done is %d\r\n", done);
    buf = in_transfer.ptr + in_transfer.actual;
    length = in_transfer.buffer_len - in_transfer.actual;

    if (rxcount < length)
        length = rxcount;
    in_transfer.actual += length;


    if (in_transfer.actual == in_transfer.buffer_len)
        done = true;
    HostEndpointRead(endpoint, buf, length);
    USBH_DBG("INEpCallback done is %d\r\n", done);

    csr = RDA_USB->RXCSR;
    csr |= USB_RXCSR_H_WZC_BITS;

    if (!done) {
        RDA_USB->RXCSR = USB_RXCSR_H_REQPKT;
    } else {
        csr &= ~(USB_RXCSR_RXPKTRDY | USB_RXCSR_H_REQPKT);
        RDA_USB->RXCSR = csr;
        in_transfer.notify = true;
    }
    USBH_DBG("INEpCallback done notify is %d\r\n", in_transfer.notify);
    return;
}

#ifdef CFG_USB_DMA
uint8_t USBHost::get_dma_channel_status(uint8_t channel)
{
    USBH_DBG("get_dma_channel_status channel is %d \r\n", channel);
    if (channel == 0)
        return out_channel.status;
    else
        return in_channel.status;
}

void USBHost::set_dma_channel_status(uint8_t channel, uint8_t status)
{
    if (channel == 0)
        out_channel.status = status;
    else
        in_channel.status = status;
}

void USBHost::dmaCallback(uint8_t channel)
{
    uint8_t devctl;
    uint8_t epnum;
    uint16_t txcsr;
    uint32_t addr;

    USBH_DBG("dmacallback enters \r\n");
    if (channel == 0) {
        addr = RDA_USB->DMAADDR0;
        out_channel.actual_len = addr - out_transfer.transfer_dma;
        out_channel.status = USB_DMA_STATUS_FREE;
        USBH_DBG("dmacallback len is %d, addr is 0x%08x \r\n",out_channel.actual_len, addr);
    } else {
        addr = RDA_USB->DMAADDR1;
        in_channel.actual_len = addr - in_channel.start_addr;
        in_channel.status = USB_DMA_STATUS_FREE;
    }

    devctl = RDA_USB->DEVCTL;

    /* complete */
    if ((devctl & USB_DEVCTL_HM) && (channel == 0)
        && ((out_channel.mode == 0) || (out_channel.actual_len &
        (out_channel.max_packet - 1)))) {
        /* elsect endpoint */
        epnum = out_channel.ep_num;
        RDA_USB->EPIDX = epnum;

        txcsr = RDA_USB->TXCSR;

        txcsr &= ~(USB_TXCSR_DMAENAB | USB_TXCSR_AUTOSET);
        RDA_USB->TXCSR = txcsr;

        /* send out the packet */
        txcsr &= ~USB_TXCSR_DMAMODE;
        txcsr |= USB_TXCSR_TXPKTRDY;
        RDA_USB->TXCSR = txcsr;
    }
    usb_dma_completion(channel);
}

void USBHost::usb_dma_completion(uint8_t channel)
{
    uint8_t devctl;

    USBH_DBG("usb_dma_completion enter \r\n");

    devctl = RDA_USB->DEVCTL;
    if (channel == 0) {
        if (devctl & USB_DEVCTL_HM) {
            uint16_t txcsr;
            bool use_dma;

            /* select enpoint */
            RDA_USB->EPIDX = out_channel.ep_num;
            txcsr = RDA_USB->TXCSR;
            USBH_DBG("usb_dma_completion txcsr is 0x%04x \r\n",txcsr);

            use_dma = out_channel.is_active;
            USBH_DBG("usb_dma_completion txcsr is 0x%04x ,use_dma is %d\r\n",txcsr, use_dma);

            if (out_channel.status == USB_DMA_STATUS_BUSY)
                return;

            if (use_dma) {
                out_transfer.actual = out_channel.actual_len;
                if(txcsr & USB_TXCSR_DMAMODE) {
                }

                txcsr = RDA_USB->TXCSR;
                if (txcsr & (USB_TXCSR_FIFONOTEMPTY | USB_TXCSR_TXPKTRDY)) {
                    USBH_DBG("usb_dma_completion  txcsr is 0x%04x \r\n",txcsr);
                    while (txcsr & USB_TXCSR_FIFONOTEMPTY)
                        txcsr = RDA_USB->TXCSR; //????? liliu
                }
            }

            /* for mass storege, do not need to send zlp*/
            if (0) {
                if (!(out_channel.actual_len & (out_channel.max_packet - 1))) {
                    USBH_DBG("usb_dma_completion send zero pkt 0614\r\n");
                            RDA_USB->EPIDX = out_channel.ep_num;;
                            txcsr = RDA_USB->TXCSR;
                            RDA_USB->TXCSR |= USB_TXCSR_TXPKTRDY |USB_TXCSR_H_WZC_BITS;
                            RDA_USB->TXCSR = txcsr;
                            txcsr &= ~(USB_TXCSR_DMAENAB | USB_TXCSR_TXPKTRDY);
                            RDA_USB->TXCSR = txcsr;
                }
            }
            if (out_channel.actual_len == out_transfer.buffer_len) {
                out_transfer.notify = true;
                USBH_DBG("usb_dma_completion notify is true\r\n");
            }
        }
    } else {
        if (devctl & USB_DEVCTL_HM) {
            uint16_t rxcsr;
            uint32_t pkt_cnt;

            /* select enpoint */
            RDA_USB->EPIDX = in_channel.ep_num;
            rxcsr = RDA_USB->RXCSR;

            pkt_cnt = RDA_USB->PKCNT1;
            USBH_DBG("usb_dma_completion pkt_cnt is %d\r\n", pkt_cnt);

            if (in_transfer.notify == true)
                return;
            rxcsr &= ~(USB_RXCSR_AUTOCLEAR | USB_RXCSR_H_AUTOREQ | USB_RXCSR_DMAENAB);
            RDA_USB->RXCSR = rxcsr;

            rxcsr &= ~USB_RXCSR_DMAMODE;
            RDA_USB->RXCSR = rxcsr;

            RDA_USB->RXCSR = ((rxcsr & USB_RXCSR_RXPKTRDY) ? USB_RXCSR_FLUSHFIFO : 0);
            in_transfer.actual = in_channel.actual_len;
            if (in_transfer.actual == in_transfer.buffer_len) {
#ifdef CFG_USB_DMA_SHAREMEMORY
                memcpy(in_transfer.ptr, a0, in_transfer.actual);
#endif
                in_transfer.notify = true;
            }
        }
    }
}
#endif

USB_TYPE USBHost::bulkWrite(USBDeviceConnected * dev, USBEndpoint * ep, uint8_t * buf, uint32_t len, bool blocking)
{
    uint8_t ep_num;
    uint16_t csr = 0;
    uint16_t load_count;
    uint8_t *buffer;
    uint32_t max_packet;
    int retries;
    uint16_t int_txe;
    uint8_t type_reg;
    uint32_t timeout = 2000;
    bool use_dma = true;
    uint8_t ret;

    USB_DBG("bulkWrite enter  dev is %p , ep is %p, len is %d \r\n", dev, ep, len);

    if (dev == NULL) {
        USB_ERR("dev NULL");
        return USB_TYPE_ERROR;
    }

    if (ep == NULL) {
        USB_ERR("ep NULL");
        return USB_TYPE_ERROR;
    }

    if (ep->getState() != USB_TYPE_IDLE) {
        USB_WARN("[ep: %p - dev: %p - %s] NOT IDLE: %s", ep, ep->dev, ep->dev->getName(ep->getIntfNb()), ep->getStateString());
        return ep->getState();
    }

    out_transfer.buffer_len= len;
    out_transfer.actual = 0;
    out_transfer.ptr = buf;
    out_transfer.notify = false;
#ifdef CFG_USB_DMA
#ifdef CFG_USB_DMA_SHAREMEMORY
    memcpy(a0, buf, len);
    out_transfer.transfer_dma = (uint32_t)a0;
    //out_transfer.transfer_dma &= 0x0fffffff;
#else
    out_transfer.transfer_dma = (uint32_t) buf;
#endif /* if 0 */
#endif /* CFG_USB_DMA */

    /* elsect endpoint */
    ep_num = out_transfer.ep_num;
    USB_DBG("BULK WRITE ep_num is %d",ep_num);

    RDA_USB->EPIDX = ep_num;

    max_packet = ep->getMaxSize();
    USB_DBG("BULK WRITE max_packet is %d", max_packet);

    if (len <  max_packet) {
        use_dma =  false;
        csr = RDA_USB->TXCSR;
        csr &= ~USB_TXCSR_DMAENAB;
        RDA_USB->TXCSR = csr;
    }
#ifdef CFG_USB_DMA
    if (use_dma) {
        /* init dma channel structure*/
        out_channel.ep_num = out_transfer.ep_num;
        out_channel.transmit = 1;
        out_channel.index = 0;
        out_channel.status = USB_DMA_STATUS_FREE;
        out_channel.mode = 1;
        out_channel.max_packet = max_packet;
        out_transfer.channel_num = 0;
    }
#endif
    /* disable interrupt in case we flush */
    int_txe = RDA_USB->INTRTXEN;
    RDA_USB->INTRTXEN = int_txe & ~(1 << ep_num);

    csr = RDA_USB->TXCSR;

    /* flush fifo */
    while (csr & USB_TXCSR_FIFONOTEMPTY) {
        csr |= USB_TXCSR_FLUSHFIFO | USB_TXCSR_TXPKTRDY;
        RDA_USB->TXCSR = csr;
        csr = RDA_USB->TXCSR;
        if (retries-- < 1)
            break;
    }

    csr &= ~(USB_TXCSR_H_NAKTIMEOUT \
            | USB_TXCSR_AUTOSET \
            | USB_TXCSR_DMAENAB \
            | USB_TXCSR_FRCDATATOG \
            | USB_TXCSR_H_RXSTALL \
            | USB_TXCSR_H_ERROR \
            | USB_TXCSR_TXPKTRDY);

    csr |= USB_TXCSR_MODE;
    csr |= USB_TXCSR_H_DATATOGGLE;
    RDA_USB->TXCSR = csr;

    csr &= ~USB_TXCSR_DMAMODE;
    RDA_USB->TXCSR = csr;

    type_reg = (ep->getType() << 4) | (out_transfer.dev_epnum);
    USB_DBG("bulk write type_reg is 0x%02x", type_reg);


    /* config regs */
    if (RDA_USB->POWER & USB_POWER_HSMODE)
        RDA_USB->TXTYPE = type_reg | 0x40;
    else
        RDA_USB->TXTYPE = type_reg | 0x80;
    USB_DBG("bulk write TXTYPE is 0x%02x", RDA_USB->TXTYPE);

    uint8_t reg = RDA_USB->FIFOSIZE;
    USB_DBG("bulk write FIFOSIZE is 0x%02x", reg);

    RDA_USB->TXMAXPKTSIZE = 1 << (reg & 0x0f);
    RDA_USB->TXINTERVAL = 8;

    USB_DBG("bulk write TXMAXPKTSIZE is 0x%04x",RDA_USB->TXMAXPKTSIZE);

    load_count = MIN(len, max_packet);
    buffer = out_transfer.ptr + out_transfer.actual;
#ifdef CFG_USB_DMA
    if (use_dma) {
        csr = RDA_USB->TXCSR;
        if (len > out_channel.max_len)
            len = out_channel.max_len;
        if (out_channel.mode) {
            csr |= USB_TXCSR_DMAENAB | USB_TXCSR_DMAMODE | USB_TXCSR_H_WZC_BITS;
            csr |= USB_TXCSR_AUTOSET;
        }
         RDA_USB->TXCSR = csr;
        out_channel.is_active = true;
        out_channel.actual_len = 0;
        out_channel.length = len;
        out_channel.status = USB_DMA_STATUS_BUSY;
        (*(volatile uint32_t*)(0x10000008)) = 0xaa;

        ret = dma_channel_program(out_channel.ep_num, out_channel.transmit, out_channel.mode, out_transfer.transfer_dma + out_transfer.actual, len);
        if (!ret) {
            printf("bulk write dma return false \r\n");
            out_channel.is_active = false;
            csr = RDA_USB->TXCSR;
            csr &= ~(USB_TXCSR_AUTOSET | USB_TXCSR_DMAENAB);
            RDA_USB->TXCSR = csr | USB_TXCSR_H_WZC_BITS;
        } else {
            load_count = 0;
        }
    }
#endif
    if (load_count) {
        HostEndpointWrite(ep_num, buffer, load_count);
        out_transfer.actual += load_count;
    }
    /* re-enable interrupts*/
    RDA_USB->INTRTXEN = int_txe;

    USB_DBG("BULK WRITE notify is %d",out_transfer.notify);

    while (--timeout) {
        if (out_transfer.notify == true || timeout == 1 ) {
            break;
        }
        wait(0.001);
    }

    if (out_transfer.notify == true) {
        return USB_TYPE_OK;
    } else {
        USB_ERR("BULK WRITE timeout is %d, actual is %d, len is %d, txcsr is 0x%04x!!!",
            timeout, out_transfer.actual, out_transfer.buffer_len,RDA_USB->TXCSR);
        return USB_TYPE_OK;
        }
    }

USB_TYPE USBHost::bulkRead(USBDeviceConnected * dev, USBEndpoint * ep, uint8_t * buf, uint32_t len, bool blocking)
{
    uint8_t epnum;
    uint32_t timeout = 2000;
    bool use_dma = true;
    uint32_t rx_req_count;
    uint8_t ret = false;
    uint32_t max_packet;
    uint16_t csr;
    uint16_t clear_rxrdy;

    USB_DBG("bulkRead enter  dev is %p , ep is %p, len is %d", dev, ep, len);

    if (dev == NULL) {
        USB_ERR("dev NULL");
        return USB_TYPE_ERROR;
    }

    if (ep == NULL) {
        USB_ERR("ep NULL");
        return USB_TYPE_ERROR;
    }

    if (ep->getState() != USB_TYPE_IDLE) {
        USB_WARN("[ep: %p - dev: %p - %s] NOT IDLE: %s", ep, ep->dev, ep->dev->getName(ep->getIntfNb()), ep->getStateString());
        return ep->getState();
    }

    in_transfer.buffer_len= len;
    in_transfer.actual = 0;
    in_transfer.ptr = buf;
    in_transfer.notify = false;
#ifdef CFG_USB_DMA
#ifdef CFG_USB_DMA_SHAREMEMORY
    in_transfer.transfer_dma = (uint32_t)a0;
    //in_transfer.transfer_dma &= 0x0fffffff;
#else
    in_transfer.transfer_dma = (uint32_t)buf;
#endif /* CFG_USB_DMA_SHAREMEMORY */
#endif /* CFG_USB_DMA */
    max_packet = ep->getMaxSize();
    if (len <= max_packet) {
        use_dma = false;
    }

#ifdef CFG_USB_DMA
    if (use_dma) {
        in_channel.ep_num = in_transfer.ep_num;
        in_channel.transmit = 0;
        in_channel.index = 1;
        in_channel.status = USB_DMA_STATUS_FREE;
        in_channel.mode = 1;
        in_channel.max_packet = max_packet;
        in_transfer.channel_num = 1;
        }
#endif

    /* select endpoint */
    epnum = in_transfer.ep_num;
    RDA_USB->EPIDX = epnum;

    if (RDA_USB->POWER & USB_POWER_HSMODE)
        RDA_USB->RXTYPE = (ep->getType() << 4) | (in_transfer.dev_epnum) | 0x40;
    else
        RDA_USB->RXTYPE = (ep->getType()<< 4) | (in_transfer.ep_num) | 0x80;

    uint8_t reg = RDA_USB->FIFOSIZE;
    USB_DBG("bulk read FIFOSIZE is 0x%02x",reg );
    RDA_USB->RXMAXPKTSIZE = 1 << ((reg & 0xf0) >> 4);
    RDA_USB->RXINTERVAL = 8;

#ifdef CFG_USB_DMA
    if (len > max_packet) {
        rx_req_count = len / max_packet;
        if (len % max_packet)
            rx_req_count += 1;
        RDA_USB->PKCNT1 = rx_req_count;
        in_channel.is_active = true;
        in_channel.actual_len = 0;
        in_channel.length = len;
        in_channel.status = USB_DMA_STATUS_BUSY;
        USBH_DBG("ep_num is %d, transmit is %d \r\n",in_channel.ep_num, in_channel.transmit );

        ret = dma_channel_program( in_channel.ep_num,in_channel.transmit, in_channel.mode, in_transfer.transfer_dma + in_transfer.actual, len);
        if (!ret) {
            in_channel.is_active = false;
        }
    }
    if (ret) {
        csr = RDA_USB->RXCSR;
        csr |= USB_RXCSR_DMAMODE;
        csr |= USB_RXCSR_DMAENAB
                | USB_RXCSR_AUTOCLEAR
                | USB_RXCSR_H_AUTOREQ;
        RDA_USB->RXCSR = csr;
        csr = USB_RXCSR_H_REQPKT;
        clear_rxrdy = RDA_USB->RXCSR;
        if (clear_rxrdy & USB_RXCSR_RXPKTRDY) {
            RDA_USB->RXCSR = clear_rxrdy ;
        } else {
            RDA_USB->RXCSR = USB_RXCSR_H_REQPKT;
        }
    }
#endif
    if (!ret) {
        RDA_USB->RXCSR = USB_RXCSR_H_REQPKT;
    }
    USB_DBG("bulk read  notify is %d" ,in_transfer.notify );

    wait(0.0001);
    while (--timeout) {
        if (in_transfer.notify == true || timeout == 1 ) {
            break;
        }
        wait(0.001);
    }

    if (in_transfer.notify == true) {
        USB_DBG("bulk read done !!!!" );
        return USB_TYPE_OK;
    } else {
        USB_ERR("bulk read timeout!!!");
        return USB_TYPE_ERROR;
    }
}

#else
USB_TYPE USBHost::bulkWrite(USBDeviceConnected * dev, USBEndpoint * ep, uint8_t * buf, uint32_t len, bool blocking)
{
    return generalTransfer(dev, ep, buf, len, blocking, BULK_ENDPOINT, true);
}

USB_TYPE USBHost::bulkRead(USBDeviceConnected * dev, USBEndpoint * ep, uint8_t * buf, uint32_t len, bool blocking)
{
    return generalTransfer(dev, ep, buf, len, blocking, BULK_ENDPOINT, false);
}

USB_TYPE USBHost::controlRead(USBDeviceConnected * dev, uint8_t requestType, uint8_t request, uint32_t value, uint32_t index, uint8_t * buf, uint32_t len) {
    return controlTransfer(dev, requestType, request, value, index, buf, len, false);
}

USB_TYPE USBHost::controlWrite(USBDeviceConnected * dev, uint8_t requestType, uint8_t request, uint32_t value, uint32_t index, uint8_t * buf, uint32_t len) {
    return controlTransfer(dev, requestType, request, value, index, buf, len, true);
}
#endif
USB_TYPE USBHost::controlTransfer(USBDeviceConnected * dev, uint8_t requestType, uint8_t request, uint32_t value, uint32_t index, uint8_t * buf, uint32_t len, bool write)
{
    Lock lock(this);
    USB_DBG_TRANSFER("----- CONTROL %s [dev: %p - hub: %d - port: %d] ------", (write) ? "WRITE" : "READ", dev, dev->getHub(), dev->getPort());

    int length_transfer = len;
    USB_TYPE res;
    uint32_t token;

    control->setSpeed(dev->getSpeed());
    control->setSize(dev->getSizeControlEndpoint());
    if (dev->isActiveAddress()) {
        control->setDeviceAddress(dev->getAddress());
    } else {
        control->setDeviceAddress(0);
    }

    USB_DBG_TRANSFER("Control transfer on device: %d\r\n", control->getDeviceAddress());
    fillControlBuf(requestType, request, value, index, len);

#if DEBUG_TRANSFER
    USB_DBG_TRANSFER("SETUP PACKET: ");
    for (int i = 0; i < 8; i++)
        printf("%01X ", setupPacket[i]);
    printf("\r\n");
#endif

    control->setNextToken(TD_SETUP);
    addTransfer(control, (uint8_t*)setupPacket, 8);

    control->ep_queue.get();
    res = control->getState();

    USB_DBG_TRANSFER("CONTROL setup stage %s", control->getStateString());

    if (res != USB_TYPE_IDLE) {
        return res;
    }

    if (length_transfer) {
        token = (write) ? TD_OUT : TD_IN;
        control->setNextToken(token);
        addTransfer(control, (uint8_t *)buf, length_transfer);

        control->ep_queue.get();
        res = control->getState();

#if DEBUG_TRANSFER
        USB_DBG_TRANSFER("CONTROL %s stage %s", (write) ? "WRITE" : "READ", control->getStateString());
        if (write) {
            USB_DBG_TRANSFER("CONTROL WRITE buffer");
            for (int i = 0; i < control->getLengthTransferred(); i++)
                printf("%02X ", buf[i]);
            printf("\r\n\r\n");
        } else {
            USB_DBG_TRANSFER("CONTROL READ SUCCESS [%d bytes transferred]", control->getLengthTransferred());
            for (int i = 0; i < control->getLengthTransferred(); i++)
                printf("%02X ", buf[i]);
            printf("\r\n\r\n");
        }
#endif

        if (res != USB_TYPE_IDLE) {
            return res;
        }
    }

    token = (write) ? TD_IN : TD_OUT;
    control->setNextToken(token);
    addTransfer(control, NULL, 0);

    control->ep_queue.get();
    res = control->getState();

    USB_DBG_TRANSFER("CONTROL ack stage %s", control->getStateString());

    if (res != USB_TYPE_IDLE)
        return res;

    return USB_TYPE_OK;
}


void USBHost::fillControlBuf(uint8_t requestType, uint8_t request, uint16_t value, uint16_t index, int len)
{
    setupPacket[0] = requestType;
    setupPacket[1] = request;
    setupPacket[2] = (uint8_t) value;
    setupPacket[3] = (uint8_t) (value >> 8);
    setupPacket[4] = (uint8_t) index;
    setupPacket[5] = (uint8_t) (index >> 8);
    setupPacket[6] = (uint8_t) len;
    setupPacket[7] = (uint8_t) (len >> 8);
}
