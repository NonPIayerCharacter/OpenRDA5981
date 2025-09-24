/* LWIP implementation of NetworkInterfaceAPI
 * Copyright (c) 2015 ARM Limited
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

#include "nsapi.h"
#include "mbed_interface.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>


#include "wifi_arch.h"
#include "lwip/opt.h"
#include "lwip/api.h"
#include "lwip/inet.h"
#include "lwip/netif.h"
#include "lwip/dhcp.h"
#include "lwip/tcpip.h"
#include "lwip/tcp.h"
#include "lwip/ip.h"
#include "lwip/mld6.h"
#include "lwip/dns.h"
#include "lwip/udp.h"
#include "emac_api.h"

#include "rda59xx_lwip.h"
#include "rda59xx_wifi_include.h"
#include "rda59xx_daemon.h"

#if DEVICE_EMAC
    #define MBED_NETIF_INIT_FN emac_lwip_if_init
#else
    #define MBED_NETIF_INIT_FN eth_arch_enetif_init
#endif


//#define DHCP_TIMEOUT 15000

/* Static arena of sockets */
static struct lwip_socket {
    bool in_use;

    struct netconn *conn;
    struct netbuf *buf;
    u16_t offset;

    void (*cb)(void *);
    void *data;
} lwip_arena[MEMP_NUM_NETCONN];

/* Static arena of sockets */

#if defined(TARGET_UNO_91H)
static bool mbed_lwip_arena_init_flag = false;
#endif
static void mbed_lwip_arena_init(void)
{
    memset(lwip_arena, 0, sizeof lwip_arena);
#if defined(TARGET_UNO_91H)
    mbed_lwip_arena_init_flag = true;
#endif

}

static struct lwip_socket *mbed_lwip_arena_alloc(void)
{
    sys_prot_t prot = sys_arch_protect();

    for (int i = 0; i < MEMP_NUM_NETCONN; i++) {
        if (!lwip_arena[i].in_use) {
            struct lwip_socket *s = &lwip_arena[i];
            memset(s, 0, sizeof *s);
            s->in_use = true;
            sys_arch_unprotect(prot);
            return s;
        }
    }

    sys_arch_unprotect(prot);
    return 0;
}

static void mbed_lwip_arena_dealloc(struct lwip_socket *s)
{
    s->in_use = false;
}

static void mbed_lwip_socket_callback(struct netconn *nc, enum netconn_evt eh, u16_t len)
{
    sys_prot_t prot = sys_arch_protect();

    for (int i = 0; i < MEMP_NUM_NETCONN; i++) {
        if (lwip_arena[i].in_use
            && lwip_arena[i].conn == nc
            && lwip_arena[i].cb) {
            lwip_arena[i].cb(lwip_arena[i].data);
        }
    }

    sys_arch_unprotect(prot);
}

/*sockets end*/

static bool lwip_connected = false;
static bool lwip_connected_ap = false;

/* TCP/IP and Network Interface Initialisation */
//static struct netif lwip_netif;
//static bool lwip_dhcp = false;
static char lwip_mac_address[NSAPI_MAC_SIZE];
static char lwip_mac_address_ap[NSAPI_MAC_SIZE];

#if !LWIP_IPV4 || !LWIP_IPV6
static bool all_zeros(const uint8_t *p, int len)
{
    for (int i = 0; i < len; i++) {
        if (p[i]) {
            return false;
        }
    }

    return true;
}
#endif

static bool convert_mbed_addr_to_lwip(ip_addr_t *out, const nsapi_addr_t *in)
{
#if LWIP_IPV6
    if (in->version == NSAPI_IPv6) {
         IP_SET_TYPE(out, IPADDR_TYPE_V6);
         MEMCPY(ip_2_ip6(out), in->bytes, sizeof(ip6_addr_t));
         return true;
    }
#if !LWIP_IPV4
    /* For bind() and other purposes, need to accept "null" of other type */
    /* (People use IPv4 0.0.0.0 as a general null) */
    if (in->version == NSAPI_UNSPEC ||
        (in->version == NSAPI_IPv4 && all_zeros(in->bytes, 4))) {
        ip_addr_set_zero_ip6(out);
        return true;
    }
#endif
#endif

#if LWIP_IPV4
    if (in->version == NSAPI_IPv4) {
         IP_SET_TYPE(out, IPADDR_TYPE_V4);
         MEMCPY(ip_2_ip4(out), in->bytes, sizeof(ip4_addr_t));
         return true;
    }
#if !LWIP_IPV6
    /* For symmetry with above, accept IPv6 :: as a general null */
    if (in->version == NSAPI_UNSPEC ||
        (in->version == NSAPI_IPv6 && all_zeros(in->bytes, 16))) {
        ip_addr_set_zero_ip4(out);
        return true;
    }
#endif
#endif

#if LWIP_IPV4 && LWIP_IPV6
    if (in->version == NSAPI_UNSPEC) {
#if IP_VERSION_PREF == PREF_IPV4
        ip_addr_set_zero_ip4(out);
#else
        ip_addr_set_zero_ip6(out);
#endif
        return true;
    }
#endif

    return false;
}

static bool convert_lwip_addr_to_mbed(nsapi_addr_t *out, const ip_addr_t *in)
{
#if LWIP_IPV6
    if (IP_IS_V6(in)) {
        out->version = NSAPI_IPv6;
        MEMCPY(out->bytes, ip_2_ip6(in), sizeof(ip6_addr_t));
        return true;
    }
#endif
#if LWIP_IPV4
    if (IP_IS_V4(in)) {
        out->version = NSAPI_IPv4;
        MEMCPY(out->bytes, ip_2_ip4(in), sizeof(ip4_addr_t));
        return true;
    }
#endif
    return false;
}

static void mbed_lwip_set_mac_address(int mac_no)
{
    char mac[6];
    rda59xx_get_macaddr((u8_t *)mac, mac_no);
    //mbed_mac_address(mac);
    if(mac_no == 0){
        snprintf(lwip_mac_address, NSAPI_MAC_SIZE, "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }else if(mac_no == 1){
        snprintf(lwip_mac_address_ap, NSAPI_MAC_SIZE, "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

/* LWIP interface implementation */
const char *mbed_lwip_get_mac_address(int mac_no)
{
    if(mac_no == 0)
        return lwip_mac_address[0] ? lwip_mac_address : 0;
    else if(mac_no == 1)
        return lwip_mac_address_ap[0] ? lwip_mac_address_ap : 0;
    return NULL;
}

static const ip_addr_t *mbed_lwip_get_ipv4_addr(const struct netif *netif)
{
#if LWIP_IPV4
    if (!netif_is_up(netif)) {
        return NULL;
    }

    if (!ip4_addr_isany(netif_ip4_addr(netif))) {
        return netif_ip_addr4(netif);
    }
#endif

    return NULL;
}

static const ip_addr_t *mbed_lwip_get_ipv6_addr(const struct netif *netif)
{
#if LWIP_IPV6
    if (!netif_is_up(netif)) {
        return NULL;
    }

    for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        if (ip6_addr_isvalid(netif_ip6_addr_state(netif, i)) &&
                !ip6_addr_islinklocal(netif_ip6_addr(netif, i))) {
            return netif_ip_addr6(netif, i);
        }
    }
#endif

    return NULL;

}

const ip_addr_t *mbed_lwip_get_ip_addr(bool any_addr, const struct netif *netif)
{
    const ip_addr_t *pref_ip_addr = 0;
    const ip_addr_t *npref_ip_addr = 0;

#if IP_VERSION_PREF == PREF_IPV4
    pref_ip_addr = mbed_lwip_get_ipv4_addr(netif);
    npref_ip_addr = mbed_lwip_get_ipv6_addr(netif);
#else
    pref_ip_addr = mbed_lwip_get_ipv6_addr(netif);
    npref_ip_addr = mbed_lwip_get_ipv4_addr(netif);
#endif

    if (pref_ip_addr) {
        return pref_ip_addr;
    } else if (npref_ip_addr && any_addr) {
        return npref_ip_addr;
    }

    return NULL;
}

char *mbed_lwip_get_ip_address_ap(char *buf, nsapi_size_t buflen)
{
	return rda59xx_get_ip_address(buf, buflen, 1);
}

#if LWIP_IPV6
void mbed_lwip_clear_ipv6_addresses(struct netif *lwip_netif)
{
    for (u8_t i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
        netif_ip6_addr_set_state(lwip_netif, i, IP6_ADDR_INVALID);
    }
}
#endif

nsapi_error_t mbed_lwip_init(emac_interface_t *emac)
{
    // Check if we've already brought up lwip
    if (!mbed_lwip_get_mac_address(0)) {
        // Set up network
        mbed_lwip_set_mac_address(0);
    }
	rda59xx_wifi_init();
    return NSAPI_ERROR_OK;
}
size_t mbed_lwip_scan_inf(rda59xx_scan_info* r_scan_info)
{
	mbed_lwip_init(NULL);
    return rda59xx_scan_internal(r_scan_info);
}
size_t mbed_lwip_get_scan_result(rda59xx_scan_result *bss_list, const u8_t num)
{
	mbed_lwip_init(NULL);
    return rda59xx_get_scan_result(bss_list, num);
}
size_t mbed_lwip_get_ap_join_info(rda59xx_apsta_info_t *sta_list, const size_t num)
{
	return rda59xx_get_ap_join_info(sta_list, num);
}

nsapi_error_t mbed_lwip_bringup_inf(rda59xx_sta_info* r_sta_info)
{
	mbed_lwip_init(NULL);
    // Check if we've already connected
    //if (lwip_connected) {
    if(rda59xx_get_wifi_state() == EVENT_STA_GOT_IP) {
        return NSAPI_ERROR_PARAMETER;
    }
    // Check if we've already brought up lwip
    if (!mbed_lwip_get_mac_address(0)) {
        // Set up network
        mbed_lwip_set_mac_address(0);
    }
    // Zero out socket set
    if(mbed_lwip_arena_init_flag == false)
        mbed_lwip_arena_init();

    rda59xx_sta_connect(r_sta_info);

    if(rda59xx_get_wifi_state() == EVENT_STA_GOT_IP)
        lwip_connected = true;
    return 0;
}

nsapi_error_t mbed_lwip_bringup(const char *ssid, const char *pass, const char *bssid,
        bool dhcp, const char *ip, const char *netmask, const char *gw)
{
    rda59xx_sta_info r_sta_info;
    //Set up wifi connect

    memset((void*)&r_sta_info, 0, sizeof(rda59xx_sta_info));

    memcpy(r_sta_info.ssid, ssid, strlen(ssid));
    memcpy(r_sta_info.pw, pass, strlen(pass));
    r_sta_info.ssid[strlen(ssid)] = r_sta_info.pw[strlen(pass)] = '\0';

    if(bssid != NULL)
        memcpy(r_sta_info.bssid, bssid, NSAPI_MAC_BYTES);
    else
        memset(r_sta_info.bssid, 0, NSAPI_MAC_BYTES);
    r_sta_info.ip = inet_addr(ip);
    r_sta_info.netmask = inet_addr(netmask);
    r_sta_info.gateway = inet_addr(gw);
    r_sta_info.dhcp = (unsigned char)dhcp;

    mbed_lwip_bringup_inf(&r_sta_info);
}

nsapi_error_t mbed_lwip_startap_inf(rda59xx_ap_info* r_ap_info)
{
	mbed_lwip_init(NULL);

    // Check if we've already connected
    //if (lwip_connected_ap) {
    if (rda59xx_get_wifi_state_ap() == EVENT_AP_STARTED) {
        return NSAPI_ERROR_PARAMETER;
    }
    if (!mbed_lwip_get_mac_address(1)) {
        mbed_lwip_set_mac_address(1);
    }
    if(mbed_lwip_arena_init_flag == false)
        mbed_lwip_arena_init();

    //Start AP
    rda59xx_ap_enable(r_ap_info);

    if(rda59xx_get_wifi_state_ap() == EVENT_AP_STARTED)
        lwip_connected_ap = true;

    return NSAPI_ERROR_OK;
}

nsapi_error_t mbed_lwip_startap(const char *ssid, const char *pass, const char *ip, const char *netmask, const char *gw,
                        const char *dhcp_start, const char *dhcp_end, int channel, char mode)
//nsapi_error_t mbed_lwip_startap_v2(rda_ap_info *r_ap_info)
{
    rda59xx_ap_info r_ap_info;
    char addrtemp[NSAPI_IPv4_SIZE];

    //Start AP
    memset((void*)&r_ap_info, 0, sizeof(rda59xx_ap_info));
    memcpy(r_ap_info.ssid, ssid, strlen(ssid));
    memcpy(r_ap_info.pw, pass, strlen(pass));
    r_ap_info.ssid[strlen(ssid)] = r_ap_info.pw[strlen(pass)] = '\0';
    if(channel>0 && channel<14)
        r_ap_info.channel = (unsigned char)channel;
    r_ap_info.mode = mode;

    memcpy(addrtemp, inet_ntoa(*(unsigned int *)ip), NSAPI_IPv4_SIZE);
    r_ap_info.ip = inet_addr(addrtemp);
    memcpy(addrtemp, inet_ntoa(*(unsigned int *)netmask), NSAPI_IPv4_SIZE);
    r_ap_info.netmask = inet_addr(addrtemp);
    memcpy(addrtemp, inet_ntoa(*(unsigned int *)gw), NSAPI_IPv4_SIZE);
    r_ap_info.gateway= inet_addr(addrtemp);	
    memcpy(addrtemp, inet_ntoa(*(unsigned int *)dhcp_start), NSAPI_IPv4_SIZE);
    r_ap_info.dhcps= inet_addr(addrtemp);	
    memcpy(addrtemp, inet_ntoa(*(unsigned int *)dhcp_end), NSAPI_IPv4_SIZE);
    r_ap_info.dhcpe= inet_addr(addrtemp);

    mbed_lwip_startap_inf(&r_ap_info);

}

nsapi_error_t mbed_lwip_stopap(u8_t state)
{
    // Check if we've connected
    //if (!lwip_connected_ap) {
    if (rda59xx_get_wifi_state_ap() == EVENT_AP_STOPED) {
        return NSAPI_ERROR_PARAMETER;
    }
    if(state == 0)
        rda59xx_ap_disable();
    if(rda59xx_get_wifi_state_ap() != EVENT_AP_STARTED)
        lwip_connected_ap = false;

    return 0;
}

nsapi_error_t mbed_lwip_bringdown(void)
{
    // Check if we've connected
    //if (!lwip_connected) {
    if(rda59xx_get_wifi_state() == EVENT_STA_DISCONNECTTED) {
        return NSAPI_ERROR_PARAMETER;
    }

    rda59xx_sta_disconnect();
    if(rda59xx_get_wifi_state() != EVENT_STA_GOT_IP)
        lwip_connected = false;
    return 0;
}
nsapi_error_t mbed_lwip_status(void)
{
    return lwip_connected;
}

nsapi_error_t mbed_lwip_ap_status(void)
{
    return lwip_connected_ap;
}
size_t mbed_lwip_get_joined_AP(rda59xx_scan_result *bss)
{
	return rda59xx_get_joined_AP(bss);
}
char *mbed_lwip_get_gateway(char *buf, size_t buflen)
{
	return rda59xx_get_gateway(buf, buflen ,0);
}
char *mbed_lwip_get_ip_address(char *buf, size_t buflen)
{
	return rda59xx_get_ip_address(buf, buflen, 0);
}
char *mbed_lwip_get_netmask(char *buf, size_t buflen)
{
	return rda59xx_get_netmask(buf, buflen, 0);
}
int mbed_lwip_same_mac(const char *mac1, const char *mac2)
{
    return (mac1[0] == mac2[0] && mac1[1] == mac2[1] && mac1[2] == mac2[2] \
        && mac1[3] == mac2[3] && mac1[4] == mac2[4] && mac1[5] == mac2[5]);
}

int mbed_lwip_zero_mac(const char *mac)
{
    return !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]);
}
int mbed_lwip_set_channel(int chn)
{
   	rda59xx_set_channel(chn);
    return 0;
}

/* LWIP error remapping */
static nsapi_error_t mbed_lwip_err_remap(err_t err) {
    switch (err) {
        case ERR_OK:
        case ERR_CLSD:
        case ERR_RST:
            return 0;
        case ERR_MEM:
            return NSAPI_ERROR_NO_MEMORY;
        case ERR_CONN:
            return NSAPI_ERROR_NO_CONNECTION;
        case ERR_TIMEOUT:
        case ERR_RTE:
        case ERR_INPROGRESS:
        case ERR_WOULDBLOCK:
            return NSAPI_ERROR_WOULD_BLOCK;
        case ERR_VAL:
        case ERR_USE:
        case ERR_ISCONN:
        case ERR_ARG:
            return NSAPI_ERROR_PARAMETER;
        default:
            return NSAPI_ERROR_DEVICE_ERROR;
    }
}

/* LWIP network stack implementation */
static nsapi_error_t mbed_lwip_gethostbyname(nsapi_stack_t *stack, const char *host, nsapi_addr_t *addr, nsapi_version_t version)
{
    ip_addr_t lwip_addr;

#if LWIP_IPV4 && LWIP_IPV6
    u8_t addr_type;
    if (version == NSAPI_UNSPEC) {
        const ip_addr_t *ip_addr;
        ip_addr = mbed_lwip_get_ip_addr(true, &lwip_sta_netif);
        if (IP_IS_V6(ip_addr)) {
            addr_type = NETCONN_DNS_IPV6;
        } else {
            addr_type = NETCONN_DNS_IPV4;
        }
    } else if (version == NSAPI_IPv4) {
        addr_type = NETCONN_DNS_IPV4;
    } else if (version == NSAPI_IPv6) {
        addr_type = NETCONN_DNS_IPV6;
    }
    err_t err = netconn_gethostbyname_addrtype(host, &lwip_addr, addr_type);
#elif LWIP_IPV4
    if (version != NSAPI_IPv4 && version != NSAPI_UNSPEC) {
        return NSAPI_ERROR_DNS_FAILURE;
    }
    err_t err = netconn_gethostbyname(host, &lwip_addr);
#elif LWIP_IPV6
    if (version != NSAPI_IPv6 && version != NSAPI_UNSPEC) {
        return NSAPI_ERROR_DNS_FAILURE;
    }
    err_t err = netconn_gethostbyname(host, &lwip_addr);
#endif

    if (err != ERR_OK) {
        return NSAPI_ERROR_DNS_FAILURE;
    }

    convert_lwip_addr_to_mbed(addr, &lwip_addr);

    return 0;
}

static nsapi_error_t mbed_lwip_add_dns_server(nsapi_stack_t *stack, nsapi_addr_t addr)
{
    // Shift all dns servers down to give precedence to new server
    for (int i = DNS_MAX_SERVERS-1; i > 0; i--) {
        dns_setserver(i, dns_getserver(i-1));
    }

    ip_addr_t ip_addr;
    if (!convert_mbed_addr_to_lwip(&ip_addr, &addr)) {
        return NSAPI_ERROR_PARAMETER;
    }

    dns_setserver(0, &ip_addr);
    return 0;
}

static nsapi_error_t mbed_lwip_socket_open(nsapi_stack_t *stack, nsapi_socket_t *handle, nsapi_protocol_t proto)
{
    // check if network is connected
    if (!lwip_connected && !lwip_connected_ap) {
        return NSAPI_ERROR_NO_CONNECTION;
    }

    // allocate a socket
    struct lwip_socket *s = mbed_lwip_arena_alloc();
    if (!s) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    u8_t lwip_proto = proto == NSAPI_TCP ? NETCONN_TCP : NETCONN_UDP;

#if LWIP_IPV6 && LWIP_IPV4
    const ip_addr_t *ip_addr;
    ip_addr = mbed_lwip_get_ip_addr(true, &lwip_sta_netif);

    if (IP_IS_V6(ip_addr)) {
        // Enable IPv6 (or dual-stack). LWIP dual-stack support is
        // currently incomplete as of 2.0.0rc2 - eg we will only be able
        // to do a UDP sendto to an address matching the type selected
        // here. Matching "get_ip_addr" and DNS logic, use v4 if
        // available.
        lwip_proto |= NETCONN_TYPE_IPV6;
    }
#elif LWIP_IPV6
    lwip_proto |= NETCONN_TYPE_IPV6;
#endif

    s->conn = netconn_new_with_callback((enum netconn_type)lwip_proto, mbed_lwip_socket_callback);

    if (!s->conn) {
        mbed_lwip_arena_dealloc(s);
        return NSAPI_ERROR_NO_SOCKET;
    }

    netconn_set_recvtimeout(s->conn, 1);
    *(struct lwip_socket **)handle = s;
    return 0;
}

static nsapi_error_t mbed_lwip_socket_close(nsapi_stack_t *stack, nsapi_socket_t handle)
{
    struct lwip_socket *s = (struct lwip_socket *)handle;
    netbuf_delete(s->buf);
    s->buf = 0;
    err_t err = netconn_delete(s->conn);
    mbed_lwip_arena_dealloc(s);
    return mbed_lwip_err_remap(err);
}

static nsapi_error_t mbed_lwip_socket_bind(nsapi_stack_t *stack, nsapi_socket_t handle, nsapi_addr_t addr, uint16_t port)
{
    struct lwip_socket *s = (struct lwip_socket *)handle;
    ip_addr_t ip_addr;

    if ((s->conn->type == NETCONN_TCP && s->conn->pcb.tcp->local_port != 0) ||
        (s->conn->type == NETCONN_UDP && s->conn->pcb.udp->local_port != 0)) {
        return NSAPI_ERROR_PARAMETER;
    }

    if (!convert_mbed_addr_to_lwip(&ip_addr, &addr)) {
        return NSAPI_ERROR_PARAMETER;
    }

    err_t err = netconn_bind(s->conn, &ip_addr, port);
    return mbed_lwip_err_remap(err);
}

static nsapi_error_t mbed_lwip_socket_listen(nsapi_stack_t *stack, nsapi_socket_t handle, int backlog)
{
    struct lwip_socket *s = (struct lwip_socket *)handle;

    err_t err = netconn_listen_with_backlog(s->conn, backlog);
    return mbed_lwip_err_remap(err);
}

static nsapi_error_t mbed_lwip_socket_connect(nsapi_stack_t *stack, nsapi_socket_t handle, nsapi_addr_t addr, uint16_t port)
{
    struct lwip_socket *s = (struct lwip_socket *)handle;
    ip_addr_t ip_addr;

    if (!convert_mbed_addr_to_lwip(&ip_addr, &addr)) {
        return NSAPI_ERROR_PARAMETER;
    }

    netconn_set_nonblocking(s->conn, false);
    err_t err = netconn_connect(s->conn, &ip_addr, port);
    netconn_set_nonblocking(s->conn, true);

    return mbed_lwip_err_remap(err);
}

static nsapi_error_t mbed_lwip_socket_accept(nsapi_stack_t *stack, nsapi_socket_t server, nsapi_socket_t *handle, nsapi_addr_t *addr, uint16_t *port)
{
    struct lwip_socket *s = (struct lwip_socket *)server;
    struct lwip_socket *ns = mbed_lwip_arena_alloc();
    if (!ns) {
        return NSAPI_ERROR_NO_SOCKET;
    }

    err_t err = netconn_accept(s->conn, &ns->conn);
    if (err != ERR_OK) {
        mbed_lwip_arena_dealloc(ns);
        return mbed_lwip_err_remap(err);
    }

    netconn_set_recvtimeout(ns->conn, 1);
    *(struct lwip_socket **)handle = ns;

    ip_addr_t peer_addr;
    (void) netconn_peer(ns->conn, &peer_addr, port);
    convert_lwip_addr_to_mbed(addr, &peer_addr);

    return 0;
}

static nsapi_size_or_error_t mbed_lwip_socket_send(nsapi_stack_t *stack, nsapi_socket_t handle, const void *data, nsapi_size_t size)
{
    struct lwip_socket *s = (struct lwip_socket *)handle;
    size_t bytes_written = 0;

    err_t err = netconn_write_partly(s->conn, data, size, NETCONN_COPY, &bytes_written);
    if (err != ERR_OK) {
        return mbed_lwip_err_remap(err);
    }

    return (nsapi_size_or_error_t)bytes_written;
}

static nsapi_size_or_error_t mbed_lwip_socket_recv(nsapi_stack_t *stack, nsapi_socket_t handle, void *data, nsapi_size_t size)
{
    struct lwip_socket *s = (struct lwip_socket *)handle;

    if (!s->buf) {
        err_t err = netconn_recv(s->conn, &s->buf);
        s->offset = 0;

        if (err != ERR_OK) {
            return mbed_lwip_err_remap(err);
        }
    }

    u16_t recv = netbuf_copy_partial(s->buf, data, (u16_t)size, s->offset);
    s->offset += recv;

    if (s->offset >= netbuf_len(s->buf)) {
        netbuf_delete(s->buf);
        s->buf = 0;
    }

    return recv;
}

static nsapi_size_or_error_t mbed_lwip_socket_sendto(nsapi_stack_t *stack, nsapi_socket_t handle, nsapi_addr_t addr, uint16_t port, const void *data, nsapi_size_t size)
{
    struct lwip_socket *s = (struct lwip_socket *)handle;
    ip_addr_t ip_addr;

    if (!convert_mbed_addr_to_lwip(&ip_addr, &addr)) {
        return NSAPI_ERROR_PARAMETER;
    }

    struct netbuf *buf = netbuf_new();
    err_t err = netbuf_ref(buf, data, (u16_t)size);
    if (err != ERR_OK) {
        netbuf_free(buf);
        return mbed_lwip_err_remap(err);
    }

    err = netconn_sendto(s->conn, buf, &ip_addr, port);
    netbuf_delete(buf);
    if (err != ERR_OK) {
        return mbed_lwip_err_remap(err);
    }

    return size;
}

static nsapi_size_or_error_t mbed_lwip_socket_recvfrom(nsapi_stack_t *stack, nsapi_socket_t handle, nsapi_addr_t *addr, uint16_t *port, void *data, nsapi_size_t size)
{
    struct lwip_socket *s = (struct lwip_socket *)handle;
    struct netbuf *buf;

    err_t err = netconn_recv(s->conn, &buf);
    if (err != ERR_OK) {
        return mbed_lwip_err_remap(err);
    }

    convert_lwip_addr_to_mbed(addr, netbuf_fromaddr(buf));
    *port = netbuf_fromport(buf);

    u16_t recv = netbuf_copy(buf, data, (u16_t)size);
    netbuf_delete(buf);

    return recv;
}

static nsapi_error_t mbed_lwip_setsockopt(nsapi_stack_t *stack, nsapi_socket_t handle, int level, int optname, const void *optval, unsigned optlen)
{
    struct lwip_socket *s = (struct lwip_socket *)handle;

    switch (optname) {
        case NSAPI_KEEPALIVE:
            if (optlen != sizeof(int) || s->conn->type != NETCONN_TCP) {
                return NSAPI_ERROR_UNSUPPORTED;
            }

            s->conn->pcb.tcp->so_options |= SOF_KEEPALIVE;
            return 0;

        case NSAPI_KEEPIDLE:
            if (optlen != sizeof(int) || s->conn->type != NETCONN_TCP) {
                return NSAPI_ERROR_UNSUPPORTED;
            }

            s->conn->pcb.tcp->keep_idle = *(int*)optval;
            return 0;

        case NSAPI_KEEPINTVL:
            if (optlen != sizeof(int) || s->conn->type != NETCONN_TCP) {
                return NSAPI_ERROR_UNSUPPORTED;
            }

            s->conn->pcb.tcp->keep_intvl = *(int*)optval;
            return 0;

        case NSAPI_REUSEADDR:
            if (optlen != sizeof(int)) {
                return NSAPI_ERROR_UNSUPPORTED;
            }

            if (*(int *)optval) {
                s->conn->pcb.tcp->so_options |= SOF_REUSEADDR;
            } else {
                s->conn->pcb.tcp->so_options &= ~SOF_REUSEADDR;
            }
            return 0;
        case NSAPI_UDP_BROADCAST:
            if (optlen != sizeof(int) || s->conn->type != NETCONN_UDP) {
                return NSAPI_ERROR_UNSUPPORTED;
            }
            if (*(int *)optval) {
                s->conn->pcb.udp->so_options |= SOF_BROADCAST;
            } else {
                s->conn->pcb.udp->so_options &= ~SOF_BROADCAST;
            }
            return 0;

        default:
            return NSAPI_ERROR_UNSUPPORTED;
    }
}

static void mbed_lwip_socket_attach(nsapi_stack_t *stack, nsapi_socket_t handle, void (*callback)(void *), void *data)
{
    struct lwip_socket *s = (struct lwip_socket *)handle;

    s->cb = callback;
    s->data = data;
}

/* LWIP network stack */
const nsapi_stack_api_t lwip_stack_api = {
    .gethostbyname      = mbed_lwip_gethostbyname,
    .add_dns_server     = mbed_lwip_add_dns_server,
    .socket_open        = mbed_lwip_socket_open,
    .socket_close       = mbed_lwip_socket_close,
    .socket_bind        = mbed_lwip_socket_bind,
    .socket_listen      = mbed_lwip_socket_listen,
    .socket_connect     = mbed_lwip_socket_connect,
    .socket_accept      = mbed_lwip_socket_accept,
    .socket_send        = mbed_lwip_socket_send,
    .socket_recv        = mbed_lwip_socket_recv,
    .socket_sendto      = mbed_lwip_socket_sendto,
    .socket_recvfrom    = mbed_lwip_socket_recvfrom,
    .setsockopt         = mbed_lwip_setsockopt,
    .socket_attach      = mbed_lwip_socket_attach,
};

nsapi_stack_t lwip_stack = {
    .stack_api = &lwip_stack_api,
};

