
#if defined(TARGET_UNO_91H)

#include "USBHAL.h"
#include "RDA5991H.h"
#include "USBEndpoints_UNO_91H.h"
#include "usbddbg.h"
#include "usbdtypes.h"
#include "USBDeviceMsg.h"

USBHAL *USBHAL::instance;

#define USB_IRQ USB_IRQn

uint8_t g_ep0_state = USB_EP0_STAGE_IDLE;
uint8_t g_address = 0;
bool set_addr = 0;
bool set_config = 0;

#ifdef CONFIG_USB_DEBUG
#define USBD_DBG(fmt,args...) \
    USBD_DBG("DBG: %s " fmt "\r",__PRETTY_FUNCTION__,##args)
#else
#define USBD_DBG(fmt,args...)
#endif
extern int stopped;
USBHAL::USBHAL(void) {
    /* Disable IRQ */
    NVIC_DisableIRQ(USB_IRQ);

    /* fill in callback array */
    epCallback[0] = &USBHAL::EP1_OUT_callback;
    epCallback[1] = &USBHAL::EP1_IN_callback;
    epCallback[2] = &USBHAL::EP2_OUT_callback;
    epCallback[3] = &USBHAL::EP2_IN_callback;
    epCallback[4] = &USBHAL::EP3_OUT_callback;
    epCallback[5] = &USBHAL::EP3_IN_callback;
    epCallback[6] = &USBHAL::EP4_OUT_callback;
    epCallback[7] = &USBHAL::EP4_IN_callback;

    /* disconnect from bus: un-plug  */
    RDA_USB->POWER = 0;
    RDA_USB->INTREN = 0;
    RDA_USB->INTRTXEN = 0;
    RDA_USB->INTRRXEN = 0;
    RDA_USB->FUNC_ADDR = 0;

    /* reset usb hardware */
    RDA_USB->INTRTXEN = BIT(0);
    RDA_USB->INTRRXEN = 0;
    RDA_USB->INTREN = USB_INTR_RESET | USB_INTR_DISCONNECT;

    /* DMA RELEATED NOT ADD */
    wait(0.5);
    /* Attach IRQ */
    instance = this;
    NVIC_SetVector(USB_IRQn, (uint32_t)&_usbisr);
    NVIC_EnableIRQ(USB_IRQn);

}

USBHAL::~USBHAL(void) {

}

void USBHAL::connect(void) {
    USBD_DBG(USBD_DEBUG_LEVEL, "usbd connect\r\n");

    //wait(2.0);
    /* reset usb hardware */
    RDA_USB->INTRTXEN = BIT(0);
    RDA_USB->INTRRXEN = 0;
    RDA_USB->INTREN = USB_INTR_RESET | USB_INTR_DISCONNECT;

    RDA_USB->POWER = USB_POWER_SOFTCONN | USB_POWER_HSENAB;

    /* Disable Double FIFO */
    RDA_USB->FIFO_CTRL &= 0xFFFFFFFC;
}

void USBHAL::disconnect(void) {
    /* disconnect from bus: un-plug  */
    RDA_USB->POWER = 0;
    RDA_USB->INTREN = 0;
    RDA_USB->INTRTXEN = 0;
    RDA_USB->INTRRXEN = 0;
    RDA_USB->FUNC_ADDR = 0;
}

void USBHAL::configureDevice(void) {
    g_ep0_state = USB_EP0_STAGE_ACKWAIT;
    set_config = 1;
}

void USBHAL::unconfigureDevice(void) {
}

void USBHAL::setAddress(uint8_t address) {
    uint32_t cmd = 0;

    cmd &= ~DEV_ADDR_MASK;
    cmd |= DEV_ADDR(address);

    USBD_DBG("setAddress cmd is  0x%02x, address is 0x%02x\r\n", cmd, address);
    g_address = cmd;
    g_ep0_state = USB_EP0_STAGE_ACKWAIT;
    set_addr = 1;
}

void USBHAL::remoteWakeup(void) {
}

void USBHAL::_usbisr(void) {
    instance->usbisr();
}

void USBHAL::usbisr(void) {
    uint16_t int_stat = 0;
    uint8_t ep_num = 0;
    uint8_t current_ep_num = 0;

    USBD_DBG("usbisr enter\r\n");

    /* get_current endpoint number */
    current_ep_num = RDA_USB->EPIDX;
    USBD_DBG("usbisr current_ep_num is 0x%02X \r\n", current_ep_num);

    /* handle Rx endpooint interrupt(EP0 has no RX isr) */
    int_stat = RDA_USB->INTRRX;
    USBD_DBG("rx interrupt INTRRX is 0x%04X , INTRRXEN is 0x%02x\r\n",
                      int_stat, RDA_USB->INTRRXEN);

    int_stat &= RDA_USB->INTRRXEN;
    USBD_DBG("rx interrupt INTRRXEN is 0x%04X \r\n", int_stat);

    for (ep_num = USB_MIN_EP_NUM; (ep_num < USB_MAX_EP_NUM) && (int_stat != 0); ep_num ++) {
        if (int_stat & EP(ep_num)) {
            (instance->*(epCallback[(ep_num - 1) << 1]))();
            int_stat &= ~(EP(ep_num));
            ///TODO: make sure: it seems that there is no need to clear isr
        }
    }

    int_stat = RDA_USB->INTRTX;
    int_stat &= RDA_USB->INTRTXEN;

    /* handle ep0 interrupt */
    if (int_stat & BIT0) {
        USBD_DBG("EP0 interrupt %d \r\n", g_ep0_state);
        uint16_t csr = 0;

        RDA_USB->EPIDX = 0;
        csr = RDA_USB->CSR0;
        USBD_DBG("csr is 0x%04X \r\n", csr);
        if (csr & USB_CSR0_P_SENTSTALL) {
            USBD_DBG("EP0 STALL\r\n");
            csr &= ~USB_CSR0_P_SENTSTALL;
            RDA_USB->CSR0 = csr;
            g_ep0_state = USB_EP0_STAGE_IDLE;
        }

        if (csr & USB_CSR0_P_SETUPEND) {
            USBD_DBG("EP0 SETUPEND\r\n");
            csr &= ~USB_CSR0_P_SETUPEND;
            RDA_USB->CSR0 = csr | USB_CSR0_P_SVDSETUPEND;
            g_ep0_state = USB_EP0_STAGE_IDLE;
        }

        switch (g_ep0_state) {
            case USB_EP0_STAGE_TX: {
                if ((csr & USB_CSR0_TXPKTRDY) == 0) {
                    USBD_DBG("EP0 in\r\n");
                    EP0in();
                }
            }
                break;
            case USB_EP0_STAGE_RX: {
                if ((csr & USB_CSR0_RXPKTRDY) == 1) {
                    USBD_DBG("EP0 out\r\n");
                    EP0out();
                }
            }
                break;
            case USB_EP0_STAGE_ACKWAIT: {
                USBD_DBG("EP0 ack wait!!!!\r\n");
                if (set_addr) {
                    RDA_USB->FUNC_ADDR = g_address;
                    set_addr = 0;
                } else if (set_config) {
                    RDA_USB->INTREN |= USB_INTR_SUSPEND;
                    set_config = 0;
                }
                g_ep0_state = USB_EP0_STAGE_IDLE;
            }
                break;
            case USB_EP0_STAGE_STATUSIN: {
                g_ep0_state = USB_EP0_STAGE_IDLE;
                USBD_DBG("EP0 status in\r\n");
                goto setup;
            }
                break;
            case USB_EP0_STAGE_STATUSOUT: {
                g_ep0_state = USB_EP0_STAGE_IDLE;
                USBD_DBG("EP0 status out\r\n");
                goto setup;
            }
            case USB_EP0_STAGE_IDLE: {
setup:
                USBD_DBG("EP0 idle\r\n");
                if (csr & USB_CSR0_RXPKTRDY)
                    EP0setupCallback();
            }
                break;
            default:
                break;
        }
        int_stat &= ~BIT0;
    }

    /* handle Tx endpoint interrupt */
    for (ep_num = USB_MIN_EP_NUM; (ep_num < USB_MAX_EP_NUM) && (int_stat != 0); ep_num ++) {
        if (int_stat & EP(ep_num)) {
            uint16_t csr;

            RDA_USB->EPIDX = ep_num;
            csr = RDA_USB->TXCSR;
            if (csr & USB_TXCSR_P_UNDERRUN) {
                csr &= ~(USB_TXCSR_P_UNDERRUN);
                csr = RDA_USB->TXCSR;
            }
            USBD_DBG("tx interrupt ep_num is %d, txcsr is 0x%04x\r\n", ep_num, csr);

            if ((csr & USB_TXCSR_TXPKTRDY) == 0)
                (instance->*(epCallback[((ep_num - 1) << 1) + 1]))();
            int_stat &= ~(EP(ep_num));
            ///TODO: make sure: it seems that there is no need to clear isr
        }
    }

    int_stat = RDA_USB->INTR;
    int_stat &= RDA_USB->INTREN;
    USBD_DBG("bus interrupt int_stat is 0x%04x \r\n", int_stat);

    if (int_stat) {
        if (int_stat & USB_INTR_RESET) {
            USBD_DBG("reset \r\n");
            /* reset usb hardware */
            RDA_USB->INTRTXEN = BIT(0);
            RDA_USB->INTRRXEN = 0;
            //RDA_USB->INTREN = USB_INTR_RESET | USB_INTR_DISCONNECT;
            RDA_USB->INTREN &= ~USB_INTR_RESET;// | USB_INTR_DISCONNECT;
            busReset();
        }

        if (int_stat & USB_INTR_SUSPEND) {
            uint8_t address = RDA_USB->FUNC_ADDR;
            //mbed_error_printf("address is %x \r\n", address);
            if (address > 0) {
                stopped = 0;
                g_address = 0;
                connectStateChanged(USB_DISCONNECT);
            }
        }

        if (int_stat & USB_INTR_RESUME) {
        }

        if (int_stat & USB_INTR_DISCONNECT) {
        }
    }

    RDA_USB->EPIDX = current_ep_num;
}

void RDAendpointRead(uint8_t endpoint, uint8_t *buffer, uint32_t len) {
    uint32_t fifo_addr = (uint32_t)(RDA_USB->FIFOs + endpoint);
    uint16_t i = 0;

    if (((uint32_t)buffer & 0x01) == 0) {
        uint16_t actual_len = 0;
        uint16_t loop = 0;

        if (((uint32_t)buffer & 0x02) == 0) {
            if (len >= 4) {
                loop = len >> 2;
                for (i = 0; i < loop; i++) {
                    *((uint32_t*)(buffer + (i << 2))) = *((volatile uint32_t *)fifo_addr);
                }
                actual_len = len & (~0x03);
            }

            if (len & 0x02) {
                *((uint16_t *)(buffer + actual_len)) = *((volatile uint16_t *)fifo_addr);
                actual_len += 2;
            }
        } else {
            if (len >= 2) {
                loop = len >> 1;
                for (i = 0; i < loop; i++) {
                    *((uint16_t *)(buffer + (i << 1))) = *((volatile uint16_t *)fifo_addr);
                }
                actual_len = len & (~0x01);
            }
        }

        if (len & 0x01) {
            buffer[actual_len] = *((volatile uint8_t *)fifo_addr);
        }
    } else {
        for (i = 0; i < len; i++) {
            buffer[i] =  *((volatile uint8_t *)fifo_addr);
        }
    }

    /* for debug: dump buffer */
    for (i = 0; i < len; i++) {
        if ((i % 8) == 0)
            USBD_DBG("\r\n");
        USBD_DBG("%02x ", buffer[i]);
        if (i == len)
            USBD_DBG("\r\n");
    }
}


void USBHAL::EP0setup(uint8_t *buffer) {
    RDAendpointRead(0, buffer, sizeof(SETUP_PACKET_T));
}

void USBHAL::EP0read(void) {
}

EP_STATUS USBHAL::endpointWrite(uint8_t endpoint, uint8_t *data, uint32_t size) {
    uint32_t fifo_addr = (uint32_t)(RDA_USB->FIFOs + endpoint);
    uint16_t i = 0;

    USBD_DBG("endpointWrite enter endpoint is %d , size is %d \r\n", endpoint, size);

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
        } else {
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
    } else {
        /* byte aligned */
        for (i = 0; i < size; i++) {
            *((volatile uint8_t *)fifo_addr) = data[i];
        }
    }

    if (endpoint != 0) {
        /* select endpoint */
        RDA_USB->EPIDX = endpoint;
        RDA_USB->TXCSR |= USB_TXCSR_TXPKTRDY;
        return EP_PENDING;
    }
}

void USBHAL::EP0write(uint8_t *buffer, uint32_t size) {
    USBD_DBG("EP0write size is %d \r\n", size);
    endpointWrite(0, buffer, size);
}

EP_STATUS USBHAL::endpointRead(uint8_t endpoint, uint32_t maximumSize) {
        return EP_PENDING;
}

uint32_t USBHAL::EP0getReadResult(uint8_t *buffer) {
    uint16_t count0 = 0;

    count0 = RDA_USB->RXCOUNT0;
    USBD_DBG("EP0getReadResult count0 is %d\r\n", count0);

    RDAendpointRead(0, buffer, count0);
    return count0;
}

void USBHAL::EP0readStage(void) {
}

void USBHAL::stallEndpoint(uint8_t endpoint) {
    uint16_t csr;

    if (endpoint == EP1IN) {
        RDA_USB->EPIDX = endpoint;
        csr = RDA_USB->TXCSR;
        if (csr & USB_TXCSR_FIFONOTEMPTY) {
            mbed_error_printf("ep busy, can not halt \r\n");
            return;
        }
        csr |= USB_TXCSR_P_WZC_BITS
            |  USB_TXCSR_CLRDATATOG;
        csr |= USB_TXCSR_P_SENDSTALL;
        csr &= ~USB_TXCSR_TXPKTRDY;
        RDA_USB->TXCSR = csr;
        if (csr & USB_TXCSR_P_SENTSTALL) {
            
        }
    }
    
}

void USBHAL::EP0stall(void) {
}

bool USBHAL::realiseEndpoint(uint8_t endpoint, uint32_t maxPacket, uint32_t options) {
    uint16_t csr;
    /* select endpoint */
    uint8_t index;

    index = RDA_USB->EPIDX;
    USBD_DBG("realise endpoint index is 0x%02x \r\n ", index);
    RDA_USB->EPIDX = endpoint;
	
	uint16_t int_txe, int_rxe;

    switch (endpoint) {
        case EPBULK_IN:
        case EPISO_IN:
        case EPINT_IN:
            int_txe = RDA_USB->INTRTXEN;

            /* Enable endpoint interrupt */
            int_txe |= BIT(endpoint);
            RDA_USB->INTRTXEN = int_txe;

            /* set MAX packet size */
            RDA_USB->TXMAXPKTSIZE = maxPacket;

            csr = USB_TXCSR_MODE | USB_TXCSR_CLRDATATOG;

            /* Set FlushFIFO flag if FIFO not empty */
            if (RDA_USB->TXCSR & USB_TXCSR_FIFONOTEMPTY) {
                csr |= USB_TXCSR_FLUSHFIFO;
            }
            RDA_USB->TXCSR = csr;
            break;
        case EPBULK_OUT:
        case EPISO_OUT:
        case EPINT_OUT:
            int_rxe = RDA_USB->INTRRXEN;

            /* Enable endpoint interrupt */
            int_rxe |= BIT(endpoint);
            USBD_DBG("realise endpoint int_rxe is 0x%02x , csr is 0x%04x\r\n ", int_rxe, RDA_USB->RXCSR);

            RDA_USB->INTRRXEN = int_rxe;
            /* set MAX packet size */
            RDA_USB->RXMAXPKTSIZE = maxPacket;
            /* Init RxCSR */
            csr = USB_RXCSR_FLUSHFIFO | USB_RXCSR_CLRDATATOG;

            /* Bulk/Interrupt Transcations: The CPU sets this bit to
             * disable the sending of NYET handshake. When set, all
             * successfully receive Rx packets are ACK'd including at
             * the point at which the FIFO becomes full.
             */
            if (endpoint == EPINT_OUT) {
                csr |= USB_RXCSR_DISNYET;
            }
            RDA_USB->RXCSR = csr;
            break;
        default:
            break;
    }
    RDA_USB->EPIDX = 0;
    return true;
}

void USBHAL::unstallEndpoint(uint8_t endpoint) {
    RDA_USB->EPIDX = endpoint;
    if (endpoint == EP1IN) {
        uint16_t csr;
        csr = RDA_USB->TXCSR;
        csr |= USB_TXCSR_P_WZC_BITS
            |  USB_TXCSR_CLRDATATOG;
        csr &= ~(USB_TXCSR_P_SENDSTALL
            | USB_TXCSR_P_SENTSTALL);
        csr &= ~USB_TXCSR_TXPKTRDY;
        RDA_USB->TXCSR = csr;
    }
    g_ep0_state = USB_EP0_STAGE_ACKWAIT;
    RDA_USB->EPIDX = 0;
    
}

bool USBHAL::getEndpointStallState(unsigned char endpoint) {
    return false;
}

EP_STATUS USBHAL::endpointReadResult(uint8_t endpoint, uint8_t *data, uint32_t *bytesRead) {
    uint16_t csr = 0;
    uint16_t fifo_count = 0;
    bool use_dma = false;
    uint16_t wait_fifo = 0;

    USBD_DBG("endpointReadResult enter \r\n");
    /* select endpoint */
    RDA_USB->EPIDX = endpoint;

    /* get endpoint Control/Status register */
    csr = RDA_USB->RXCSR;
    if (csr & USB_RXCSR_P_SENTSTALL) {
        csr &= (~USB_RXCSR_P_SENTSTALL);
        RDA_USB->RXCSR = csr;
        return EP_STALLED;
    }
    USBD_DBG("endpointReadResult rxcsr is 0x%04x ,endpoint is %d\r\n", csr, endpoint);

    if (csr & USB_RXCSR_RXPKTRDY) {
        fifo_count = RDA_USB->RXCOUNT;
        USBD_DBG("endpointReadResult fifo_count is %d \r\n", fifo_count);

        if (!use_dma) {
            if (fifo_count) {
                RDAendpointRead(endpoint, data, fifo_count);
            }
            *bytesRead = fifo_count;

            /* read RXCSR until USB FIFO become null */
            wait_fifo = csr;
            while (wait_fifo & BIT2) {
                wait_fifo = RDA_USB->RXCSR;
            }
            csr &= (~USB_RXCSR_RXPKTRDY);
            RDA_USB->RXCSR = csr;
        }
    }
    USBD_DBG("endpointReadResult success \r\n");

    return EP_COMPLETED;

}

EP_STATUS USBHAL::endpointWriteResult(uint8_t endpoint) {
    uint16_t csr = 0;

    /* select endpoint */
    RDA_USB->EPIDX = endpoint;
    csr = RDA_USB->TXCSR;
    USBD_DBG("endpointWriteResult csr is 0x%04X\r\n", csr);

    if (csr & USB_TXCSR_TXPKTRDY)
        return EP_PENDING;
    else
        return EP_COMPLETED;
}

#endif

