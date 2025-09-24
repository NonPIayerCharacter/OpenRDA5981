#if defined(TARGET_UNO_91H)

#include "RDA5991H.h"
#include "mbed.h"
#include "USBHALHost.h"
#include "usb_host.h"
#include "USBHALHost_UNO_91H.h"
#include "critical.h"

// #define FULL_SPEED   1
#define usb_device_detect() (usb_host_mode_detect() && usb_hw_detect())

#define USB_IRQ USB_IRQn
uint8_t ep0_state = USB_EP0_IDLE;

//#define CONFIG_USB_DEBUG
#ifdef CONFIG_USB_DEBUG
#define USBH_DBG(fmt,args...) \
    mbed_error_printf("DBG: %s " fmt "\r",__PRETTY_FUNCTION__,##args)
#else
#define USBH_DBG(fmt,args...)
#endif

bool usb_host_mode_detect(void) {
    return (!(RDA_USB->DEVCTL & USB_DEVCTL_BDEVICE));
}

bool usb_hw_detect() {
    return (RDA_USB->DEVCTL & USB_DEVCTL_HM);
}
void usbh_mode_reset (void) {
    uint8_t power = 0;
    power = RDA_USB->POWER;

    RDA_USB->POWER = power | USB_POWER_RESET;
    wait(0.1);
    RDA_USB->POWER = power & (~USB_POWER_RESET);
}

void usbh_recovery_host_mode() {
    uint32_t ana_reg2 = 0;
    uint8_t power = 0;
    uint8_t devctl = 0;

    ana_reg2 = RDA_USB->ANAREG2;
    ana_reg2 &= ~USB_ANAREG2_OTGAVFILTER;
    ana_reg2 |= 0x1000;
    RDA_USB->ANAREG2 = ana_reg2;

    wait(0.01);
    ana_reg2 &= ~USB_ANAREG2_OTGAVFILTER;
    ana_reg2 |= USB_ANAREG2_EXCHECKENABLE;
    RDA_USB->ANAREG2 = ana_reg2;
    wait(0.001);

    power= RDA_USB->POWER;
    power |= USB_POWER_RESET;
    RDA_USB->POWER = power;

    wait(0.02);
    devctl = RDA_USB->DEVCTL;
    devctl |= USB_DEVCTL_SESSION;
    devctl &= ~USB_POWER_RESET; //???
    RDA_USB->DEVCTL = devctl;
}

void wr_rf_usb_reg(unsigned char a, unsigned short d, int isusb) {
    while (RF_SPI_REG & (0x01UL << 31));
    while (RF_SPI_REG & (0x01UL << 31));
    RF_SPI_REG = (unsigned int)d | ((unsigned int)a << 16) | (0x01UL << 25) | ((isusb) ? (0x01UL << 27) : 0x00UL);
}

void rd_rf_usb_reg(unsigned char a, unsigned short *d, int isusb) {
    while (RF_SPI_REG & (0x01UL << 31));
    while (RF_SPI_REG & (0x01UL << 31));
    RF_SPI_REG = ((unsigned int)a << 16) | (0x01UL << 24) | (0x01UL << 25) | ((isusb) ? (0x01UL << 27) : 0x00UL);
    __asm volatile ("nop");
    while (RF_SPI_REG & (0x01UL << 31));
    while (RF_SPI_REG & (0x01UL << 31));
    *d = (unsigned short)(RF_SPI_REG & 0xFFFFUL);
}

USBHALHost * USBHALHost::instHost;

USBHALHost::USBHALHost() {
    instHost = this;
    memInit();
    for (int i = 0; i < MAX_ENDPOINT; i++) {
        edBufAlloc[i] = false;
    }
    for (int i = 0; i < MAX_TD; i++) {
        tdBufAlloc[i] = false;
    }
}

#ifdef CFG_USB_DMA
void init_dma_controller(void) {
    uint8_t channel;

    /* clear all dma interupts (read clean) */
    channel = RDA_USB->DMAINTR;

    /* init all dma channels */
    for (channel = 0; channel < USB_DMA_CHANNELS; channel++) {
        /* Reset DMA channel registers */
        switch (channel){
            case 0:
                RDA_USB->DMACTRL0 = 0;
                RDA_USB->DMAADDR0 = 0;
                RDA_USB->COUNT0 = 0;
                break;
            case 1:
                RDA_USB->DMACTRL1 = 0;
                RDA_USB->DMAADDR1 = 0;
                RDA_USB->COUNT1 = 0;
                break;
            default:
                break;
        }
    }
}
#endif /* CFG_USB_DMA */

void USBHALHost::init() {
    uint16_t temp;
    uint8_t devctl;
    uint8_t power;
    unsigned short val;
    uint32_t i = 0;
    bool result = false;
    //int retry_times = 0;
    uint32_t ana_reg2 = 0;
    uint8_t index;

    wr_rf_usb_reg(0x83, 0x444f, 1);

    printf("USBHALHost init  begin \r\n");
    /* enable USB host mode */
    rd_rf_usb_reg(0xA9, &val, 0);
    val |= (0x01U << 15);
    wr_rf_usb_reg(0xA9, val, 0);

    /* Disable IRQ */
    NVIC_DisableIRQ(USB_IRQ);

    /* disable interrupts */
    RDA_USB->INTREN = 0;
    RDA_USB->INTRTXEN = 0;
    RDA_USB->INTRRXEN = 0;

    RDA_USB->DEVCTL = 0;

    /* flush pending interrupts */
    temp = RDA_USB->INTR;
    temp = RDA_USB->INTRTX;
    temp = RDA_USB->INTRRX;

    index = RDA_USB->EPIDX;

    /* config register, enable interupts (musb_active())*/
    /* reset usb hardware */
    RDA_USB->INTRTXEN = BIT(0);
    RDA_USB->INTRRXEN = 0;
    RDA_USB->INTREN = USB_INTR_DISCONNECT | USB_INTR_SESSREQ;
    RDA_USB->TESTMODE = 0;

#ifdef FULL_SPEED
    RDA_USB->POWER = USB_POWER_SOFTCONN;
#else
    RDA_USB->POWER = USB_POWER_SOFTCONN | USB_POWER_HSENAB;
#endif
    devctl = RDA_USB->DEVCTL;
    devctl &= ~USB_DEVCTL_BDEVICE;

    /* assume ID pin is hard-wired to ground */
    devctl |= USB_DEVCTL_SESSION;
    RDA_USB->DEVCTL = devctl;

    ana_reg2 = RDA_USB->ANAREG2;
    ana_reg2 |= USB_ANAREG2_EXCHECKENABLE;
    RDA_USB->ANAREG2 = ana_reg2;


    /* Enable the USB Interrupt */
    NVIC_SetVector(USB_IRQn, (uint32_t)(_usbisr));
    NVIC_EnableIRQ(USB_IRQn);
#ifdef CFG_USB_DMA
    init_dma_controller();
    NVIC_SetVector(USBDMA_IRQn, (uint32_t)_usbisr);
    NVIC_EnableIRQ(USBDMA_IRQn);
#endif

    do {
        /* host mode reset */
        usbh_mode_reset();

        wait(0.01);
        if (!usb_host_mode_detect()) {
            printf("musb change to bdevice after usbc reset \r\n");
            usbh_recovery_host_mode();
            wait(0.02);
        }
        printf("devctl is %02x \r\n",RDA_USB->DEVCTL);
        for (i = 0; i < 10; i++) {
            if(usb_device_detect()){
                printf("usb_device_detect \r\n");
                printf("devctl is %02x, power is %02x\r\n",RDA_USB->DEVCTL, RDA_USB->POWER);
                power = RDA_USB->POWER;
                power &= ~USB_POWER_RESET;
                RDA_USB->POWER = power;
                deviceConnected(0, 1, !(RDA_USB->POWER & USB_POWER_HSMODE));
                result =  true;
                /* enable connect interupt */
                temp = RDA_USB->INTR;
                RDA_USB->INTREN |= USB_INTR_CONNECT;
                break;
            } else {
                wait(1);
            }
        }
        #if 0
        if(!result)
            break;
        #endif
    }while (!result);
    //while (!result && retry_times++ < 4);

    /* Disable Double FIFO */
    RDA_USB->FIFO_CTRL &= 0xFFFFFFFC;
}



void USBHALHost::memInit() {

}

uint32_t USBHALHost::controlHeadED() {
    return 1;
}

uint32_t USBHALHost::bulkHeadED() {
    return 1;
}

uint32_t USBHALHost::interruptHeadED() {
    return 1;
}

void USBHALHost::updateBulkHeadED(uint32_t addr) {
}

void USBHALHost::updateControlHeadED(uint32_t addr) {
}

void USBHALHost::updateInterruptHeadED(uint32_t addr) {
}

void USBHALHost::enableList(ENDPOINT_TYPE type) {
}

bool USBHALHost::disableList(ENDPOINT_TYPE type) {
    switch(type) {
        case CONTROL_ENDPOINT:
            RDA_USB->EPIDX = 0;
            RDA_USB->CSR0 |= USB_CSR0_FLUSHFIFO;
            RDA_USB->CSR0 &= ~USB_CSR0_H_SETUPPKT;
            return true;
        case ISOCHRONOUS_ENDPOINT:
            return false;
        case BULK_ENDPOINT:
            RDA_USB->EPIDX = EPBULK_OUT;
            RDA_USB->TXCSR |= USB_TXCSR_FLUSHFIFO;
            RDA_USB->EPIDX = EPBULK_IN;
            RDA_USB->RXCSR |= USB_RXCSR_FLUSHFIFO;
            return false;
        case INTERRUPT_ENDPOINT:
            return false;
    }
    return true;
}

volatile uint8_t * USBHALHost::getED() {
    return NULL;
}

volatile uint8_t * USBHALHost::getTD() {
    return NULL;
}

void USBHALHost::freeED(volatile uint8_t * ed) {
}

void USBHALHost::freeTD(volatile uint8_t * td) {
}

void USBHALHost::resetRootHub() {
}

void endpointWrite(uint8_t endpoint, uint8_t *data, uint32_t size) {
    uint32_t fifo_addr = (uint32_t)(RDA_USB->FIFOs + endpoint);
    uint16_t i = 0;

    //USBH_DBG("endpointWrite enter endpoint is %d , size is %d ,fifo_addr is 0x%08x, data is %p\r\n",endpoint, size, fifo_addr,data);

    /* we can't assume unaligned reads work */
    if (((uint32_t)data & 0x01) == 0) {
        uint16_t actual_len = 0;
        uint16_t loop = 0;

        /* best case is 32bit-alligned source address */
        if (((uint32_t)data & 0x02) == 0) {
            if (size >= 4) {
                loop = size >> 2;
                for (i = 0; i < loop; i++) {
                    *((volatile uint32_t *)fifo_addr) = *((uint32_t *)(data + (i << 2)));
                }
                actual_len = size & (~0x03);
            }

            if (size & 0x02) {
                *((volatile uint16_t *)fifo_addr) = *((uint16_t *)(data + actual_len));
                actual_len += 2;
            }
        }
        else {
            if (size >= 2) {
                loop = size >> 1;
                for (i = 0; i < loop; i++) {
                    *((volatile uint16_t *)fifo_addr) = *((uint16_t *)(data + (i << 1)));
                }
                actual_len = size & (~0x01);
            }
        }

        if (size & 0x01) {
            *((volatile uint8_t *)fifo_addr) = *((uint8_t *)(data + actual_len));
        }
    }
    else {
        /* byte aligned */
        for (i = 0; i < size; i++) {
            *((volatile unsigned char *)fifo_addr) =  data[i];
        }
    }

    if (endpoint != 0) {
        uint16_t csr= 0;

        csr = RDA_USB->TXCSR;
        USBH_DBG("endpointWrite txcsr is 0x%04x \r\n", csr);

        /* select endpoint */
        RDA_USB->EPIDX = endpoint;
        RDA_USB->TXCSR |= USB_TXCSR_TXPKTRDY |USB_TXCSR_H_WZC_BITS;
    }
}

void EP0write(uint8_t *buffer, uint32_t size) {
    uint16_t csr = 0;
    uint32_t retries = 5;

    USBH_DBG("EP0write size is %d \r\n",size);

    RDA_USB->EPIDX = 0;
    do {
        csr = RDA_USB->CSR0;
        if (!(csr & USB_CSR0_TXPKTRDY))
            break;
        RDA_USB->CSR0 = USB_CSR0_FLUSHFIFO;
        wait(0.001);
    } while (--retries);

    if (!retries)
        USBH_DBG("could not flush fifo , csr is 0x%04x \r\n", RDA_USB->CSR0);
    RDA_USB->CSR0 = 0;//??? liliu
    RDA_USB->TXINTERVAL = 8;
    endpointWrite(0, buffer, size);
}

void endpointRead(uint8_t endpoint, uint8_t *buffer, uint32_t len) {
    uint32_t fifo_addr = (uint32_t)(RDA_USB->FIFOs + endpoint);
    uint16_t i = 0;

    USBH_DBG("endpointRead enter endpoint is %d , size is %d \r\n",endpoint, len);

    if (((uint32_t)buffer & 0x01) == 0) {
        uint16_t actual_len = 0;
        uint16_t loop = 0;

        if (((uint32_t)buffer & 0x02) == 0) {
            if (len >= 4) {
                loop = len >> 2;
                for (i = 0; i < loop; i++) {
                    *((uint32_t*)(buffer + (i<<2))) = *((volatile uint32_t *)fifo_addr);
                }
                actual_len = len & (~0x03);
            }

            if (len & 0x02) {
                *((uint16_t *)(buffer + actual_len)) = *((volatile uint16_t *)fifo_addr);
                actual_len += 2;
            }
        }
        else {
            if (len >= 2) {
                loop = len >> 1;
                for (i = 0; i < loop; i++) {
                    *((uint16_t *)(buffer + (i<<1))) = *((volatile uint16_t *)fifo_addr);
                }
                actual_len = len & (~0x01);
            }
        }

        if (len & 0x01) {
            buffer[actual_len] = *((volatile uint8_t *)fifo_addr);
        }
    }
    else {
        for (i = 0; i < len; i++) {
            buffer[i] =  *((volatile uint8_t *)fifo_addr);
        }
    }
    USBH_DBG("RDAendpointRead data : len is %d\r\n",len);
#if 0
    /* for debug */
    for (i = 0; i < len; i++) {
        if ((i%8) == 0)
            USBH_DBG("\r\n");
        USBH_DBG("%02x ", buffer[i]);
        if (i == len)
            USBH_DBG("\r\n");
    }
#endif
}

int USBHALHost::control_transfer(uint8_t *data, uint16_t wLength) {
    uint16_t csr = 0;

    ep0_state = USB_EP0_START;
    EP0write(data, (uint32_t)wLength);
    csr = RDA_USB->CSR0;
    csr = USB_CSR0_H_SETUPPKT | USB_CSR0_TXPKTRDY;
    RDA_USB->CSR0 = csr;
    return 8;
}

void USBHALHost::HostEndpointWrite(uint8_t endpoint, uint8_t *buffer, uint32_t len) {
    endpointWrite(endpoint, buffer, len);
}

void USBHALHost::HostEndpointRead(uint8_t endpoint, uint8_t *buffer, uint32_t len) {
    endpointRead(endpoint, buffer, len);
}

#ifdef CFG_USB_DMA
bool USBHALHost::dma_channel_program(uint8_t ep_num,uint8_t transmit,uint8_t mode, uint32_t dma_addr, uint32_t len){
    uint16_t csr = 0;

    USBH_DBG("dma_channel_program ep_num is %d,transmit is %d, mode is %d, len is %d \r\n",
    ep_num, transmit, mode , len);
    if (mode) {
        csr |= 1 << USB_HSDMA_MODE1_SHIFT;
    }

    csr |= USB_HSDMA_BURSTMODE_INCR16 << USB_HSDMA_BURSTMODE_SHIFT;

    csr |= (ep_num << USB_HSDMA_ENDPOINT_SHIFT)
            | (1 << USB_HSDMA_ENABLE_SHIFT)
            | (1 << USB_HSDMA_IRQENABLE_SHIFT)
            | (transmit ? (1 << USB_HSDMA_TRANSMIT_SHIFT) : 0);
    if (transmit) {
        USBH_DBG("addr0 is 0x%08x, count0 is 0x%08x, dmactrl is 0x%08x , devctl is 0x%08x , csr is 0x%04x\r\n",
            &(RDA_USB->DMAADDR1),&(RDA_USB->COUNT1),&(RDA_USB->DMACTRL1),&(RDA_USB->DEVCTL),csr );

        /* address / count / control*/
        RDA_USB->DMAADDR0 = dma_addr;
        USBH_DBG(" dma_addr is 0x%08x \r\n", dma_addr);

        RDA_USB->COUNT0 = len;
        RDA_USB->DMACTRL0 = csr;
    } else {
    USBH_DBG("addr1 is 0x%08x, count1 is 0x%08x, dmactrl is 0x%08x ,  csr is 0x%04x\r\n",
            &(RDA_USB->DMAADDR1),&(RDA_USB->COUNT1),&(RDA_USB->DMACTRL1), csr);
        USBH_DBG(" dma_addr is 0x%08x \r\n", dma_addr);
        /* address / count / control*/
        RDA_USB->DMAADDR1 = dma_addr;
        RDA_USB->COUNT1 = len;
        RDA_USB->DMACTRL1 = csr;
    }


    return true;
}

void USBHALHost::usb_dma_isr(uint8_t hsdma){
    uint8_t bchannel;
    uint32_t count;
    uint16_t csr;

    USBH_DBG(" usb_dma_isr enter hsdma is 0x%02x \r\n", hsdma);

    if (!hsdma) {
        USBH_DBG("spurious DMA irq \r\n");

        for    (bchannel = 0; bchannel < USB_DMA_CHANNELS; bchannel++) {
            if (get_dma_channel_status(bchannel) == USB_DMA_STATUS_BUSY) {
                /* channel 0 : OUT_CHANNEL
                 * channel 1: IN_CHANNEL
                 */
                if (bchannel == 0)
                    count = RDA_USB->COUNT0;
                else
                    count = RDA_USB->COUNT1;
                if (count == 0)
                    hsdma |= (1 << bchannel);
            } else {
                USBH_DBG("usb_dma_isr get status error hsdms is 0x%02x \r\n", hsdma);
            }
        }
        USBH_DBG("usb_dma_isr hsdms is 0x%02x \r\n", hsdma);

        if (!hsdma)
            return;
    }

    for (bchannel = 0; bchannel < USB_DMA_CHANNELS; bchannel++) {
        if (hsdma & (1 << bchannel)) {
            if (bchannel == 0)
                csr = RDA_USB->DMACTRL0;
            else
                csr = RDA_USB->DMACTRL1;
            USBH_DBG("dma irq csr is 0x%04x \r\n",csr);
            if (csr & (1 << USB_HSDMA_BUSERROR_SHIFT)) {
                set_dma_channel_status(bchannel, USB_DMA_STATUS_BUS_ABORT);
            } else {
                dmaCallback(bchannel);
            }
        }
    }
}
#endif

void USBHALHost::_usbisr(void) {
    if (instHost) {
        instHost->UsbIrqhandler();
    }
}

void USBHALHost::UsbIrqhandler(void) {
    uint16_t int_rx = 0;
    uint16_t int_tx = 0;
    uint8_t ep_num = 0;
    uint8_t current_ep_num = 0;
    uint8_t devctl = 0;
    uint8_t hsdma = 0;
    uint8_t int_usb = 0;

    /* get_current endpoint number */
    current_ep_num = RDA_USB->EPIDX;
    devctl = RDA_USB->DEVCTL;

    int_usb = RDA_USB->INTR;
    int_rx = RDA_USB->INTRRX;
    int_rx &= RDA_USB->INTRRXEN;

    int_tx = RDA_USB->INTRTX;
    int_tx &= RDA_USB->INTRTXEN;

    hsdma = RDA_USB->DMAINTR;
    USBH_DBG("irq enter int_tx is 0x%04x, int_rx is 0x%04x, int_usb is 0x%02x, devctl is 0x%02x\r\n",
        int_tx, int_rx, int_usb, devctl);

#ifdef CFG_USB_DMA
    /* handle usb dma interrupt */
    if (hsdma){
        usb_dma_isr(hsdma);
    }
#endif
    if (int_usb & USB_INTR_DISCONNECT) {
        deviceDisconnectSendMsg();
        RDA_USB->INTREN &= ~(USB_INTR_DISCONNECT);
        RDA_USB->INTREN &= ~(USB_INTR_CONNECT);
        core_util_critical_section_enter();
        USBH_DBG("devctl is 0x%02x, power is 0x%02x\r\n", RDA_USB->DEVCTL, RDA_USB->POWER);
        usbh_mode_reset();
        usbh_recovery_host_mode();
        deviceDisconnect(0, 1, NULL, RDA_USB->FUNC_ADDR);
        RDA_USB->INTREN |= (USB_INTR_DISCONNECT|USB_INTR_CONNECT);
        core_util_critical_section_exit();
    } else if (int_usb & USB_INTR_CONNECT) {
        RDA_USB->INTREN &= ~(USB_INTR_DISCONNECT);
        RDA_USB->INTREN &= ~(USB_INTR_CONNECT);
        if (RDA_USB->DEVCTL & USB_DEVCTL_SESSION)
            deviceConnected(0, 1, !(RDA_USB->POWER & USB_POWER_HSMODE));
    }
    /* handle ep0 interrupt */
    if(int_tx & BIT0) {
        if (devctl & USB_DEVCTL_HM){
            uint16_t csr = 0;
            bool complete = false;
            int status = 0;
            int retries = 5;

            RDA_USB->EPIDX = 0;
            csr = RDA_USB->CSR0;

            if (USB_EP0_STATUS == ep0_state)
                complete = true;

            if (csr & USB_CSR0_H_ERROR) {
                RDA_USB->CSR0 = csr & ~USB_CSR0_H_ERROR;
                return;
                USBH_DBG("csr0 error ,stage is %d , csr is 0x%04x\r\n", ep0_state, csr);

                if (csr & USB_CSR0_H_RXSTALL) {
                    status = -1;
                } else if (csr & USB_CSR0_H_ERROR) {
                    status = -1;
                } else if (csr & USB_CSR0_H_NAKTIMEOUT) {
                    if (complete) {
                    } else if (USB_EP0_START == ep0_state) {
                    }
                    RDA_USB->CSR0 = csr & ~USB_CSR0_H_ERROR;
                    if (csr & USB_CSR0_H_REQPKT)
                        return;
                }
            }
            if (status) {
                complete = true;
                if(csr & USB_CSR0_H_REQPKT) {
                    csr &= ~USB_CSR0_H_REQPKT;
                    RDA_USB->CSR0 = csr & 0xff;
                    csr &= ~USB_CSR0_H_ERROR;
                    RDA_USB->CSR0 = csr & 0xff;
                } else {
                    /* flush fifo */
                    /* scrub any data left in the fifo */
                    do {
                        if (!(csr & (USB_CSR0_TXPKTRDY | USB_CSR0_RXPKTRDY)))
                            break;
                        RDA_USB->CSR0 = USB_CSR0_FLUSHFIFO;
                        csr = RDA_USB->CSR0;
                        wait(10);
                    } while (--retries);
                }
                RDA_USB->TXINTERVAL = 0;
                RDA_USB->CSR0 = 0;
            }
                if (!complete) {
                    if (EP0Continue()) {
                        csr = (USB_EP0_IN == ep0_state)
                            ? USB_CSR0_H_REQPKT : USB_CSR0_TXPKTRDY;
                    } else {
                        if (EP0Status())
                            csr = USB_CSR0_H_REQPKT | USB_CSR0_H_STATUSPKT;
                        else
                            csr = USB_CSR0_H_STATUSPKT | USB_CSR0_TXPKTRDY;
                        csr |= USB_CSR0_H_DIS_PING;
                        ep0_state = USB_EP0_STATUS;
                    }
                    RDA_USB->CSR0 = csr;
                } else {
                    ep0_state = USB_EP0_IDLE;
                }

                if (complete)
                    EP0Complete();
            }

        }
            int_tx &= ~BIT0;

    /* handle Rx endpooint interrupt(EP0 has no RX isr) */
    for (ep_num = USB_MIN_EP_NUM; (ep_num < USB_MAX_EP_NUM) && (int_rx != 0); ep_num ++) {
        if (int_rx & EP(ep_num)) {
            InEpCallback(ep_num);
            ///TODO: make sure: it seems that there is no need to clear isr
            USBH_DBG("UsbIrqhandler InEpCallback done \r\n");
        }
    }

    /* handle Tx endpoint interrupt */
    for(ep_num = USB_MIN_EP_NUM; (ep_num < USB_MAX_EP_NUM) && (int_tx != 0); ep_num ++) {
        if(int_tx & EP(ep_num)) {
            OutEpCallback(ep_num);
        }
    }
}
#endif
