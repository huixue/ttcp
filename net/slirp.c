/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
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
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "net/slirp.h"

#include "config-host.h"

#ifndef _WIN32
#include <pwd.h>
#include <sys/wait.h>
#endif
#include "net/net.h"
#include "clients.h"
#include "hub.h"
#include "monitor/monitor.h"
#include "qemu/sockets.h"
#include "slirp/libslirp.h"
#include "sysemu/char.h"

static int get_str_sep(char *buf, int buf_size, const char **pp, int sep)
{
    const char *p, *p1;
    int len;
    p = *pp;
    p1 = strchr(p, sep);
    if (!p1)
        return -1;
    len = p1 - p;
    p1++;
    if (buf_size > 0) {
        if (len > buf_size - 1)
            len = buf_size - 1;
        memcpy(buf, p, len);
        buf[len] = '\0';
    }
    *pp = p1;
    return 0;
}

/* slirp network adapter */

#define SLIRP_CFG_HOSTFWD 1
#define SLIRP_CFG_LEGACY  2

struct slirp_config_str {
    struct slirp_config_str *next;
    int flags;
    char str[1024];
    int legacy_format;
};

typedef struct SlirpState {
    NetClientState nc;
    QTAILQ_ENTRY(SlirpState) entry;
    Slirp *slirp;
#ifndef _WIN32
    char smb_dir[128];
#endif
} SlirpState;

static struct slirp_config_str *slirp_configs;
const char *legacy_tftp_prefix;
const char *legacy_bootp_filename;
static QTAILQ_HEAD(slirp_stacks, SlirpState) slirp_stacks =
    QTAILQ_HEAD_INITIALIZER(slirp_stacks);

static int slirp_hostfwd(SlirpState *s, const char *redir_str,
                         int legacy_format);
static int slirp_guestfwd(SlirpState *s, const char *config_str,
                          int legacy_format);

#ifndef _WIN32
static const char *legacy_smb_export;

static int slirp_smb(SlirpState *s, const char *exported_dir,
                     struct in_addr vserver_addr);
static void slirp_smb_cleanup(SlirpState *s);
#else
static inline void slirp_smb_cleanup(SlirpState *s) { }
#endif

#define INBOUND_MSG "\nPACKET_I:"
#define OUTBOUND_MSG "\nPACKET_O:"

#include "hx_libstack.h"

struct eth_hdr get_eth_hdr(const uint8_t *pkt, int len) {
    struct eth_hdr hdr;
    memcpy(&hdr, pkt, sizeof(struct eth_hdr));
    hdr.type = ntohs(hdr.type);
    return hdr;
}
struct arp_pkt get_arp_pkt(const uint8_t *arp_pkt_data, int len) {
    struct arp_pkt pkt;
    memcpy(&pkt, arp_pkt_data, sizeof(struct arp_pkt));
    return pkt;
}
void log_eth_hdr(struct eth_hdr hdr, FILE *fout) {
    fprintf(fout, "ETHER HEADER:\n");
    fprintf(fout, "dmac: 0x%02x:%02x:%02x:%02x:%02x:%02x\n", 
            hdr.dmac[0], hdr.dmac[1], hdr.dmac[2],
            hdr.dmac[3], hdr.dmac[4], hdr.dmac[5]);
    fprintf(fout, "smac: 0x%02x:%02x:%02x:%02x:%02x:%02x\n", 
            hdr.smac[0], hdr.smac[1], hdr.smac[2], 
            hdr.smac[3], hdr.smac[4], hdr.smac[5]);
    fprintf(fout, "frame type: 0x%04x\n", hdr.type);
}
void log_arp(struct arp_pkt pkt, FILE* fout) {
    fprintf(fout, "\tARP htype: 0x%02x%02x\n", pkt.htype[0], pkt.htype[1]);
    fprintf(fout, "\tARP ptype: 0x%02x%02x\n", pkt.ptype[0], pkt.ptype[1]);
    fprintf(fout, "\tARP hlen:  0x%02x    plen: %#04x\n", pkt.hlen, pkt.plen);
    fprintf(fout, "\tARP oper:  0x%02x%02x\n", pkt.oper[0], pkt.oper[1]);
    fprintf(fout, "\tARP smac:  0x%02x:%02x:%02x:%02x:%02x:%02x\n", 
            pkt.smac[0], pkt.smac[1], pkt.smac[2], 
            pkt.smac[3], pkt.smac[4], pkt.smac[5]);
    fprintf(fout, "\tARP sip:   %3d.%3d.%3d.%3d\n",
            pkt.sip[0], pkt.sip[1], pkt.sip[2], pkt.sip[3]);
    fprintf(fout, "\tARP dmac:  0x%02x:%02x:%02x:%02x:%02x:%02x\n", 
            pkt.dmac[0], pkt.dmac[1], pkt.dmac[2], 
            pkt.dmac[3], pkt.dmac[4], pkt.dmac[5]);
    fprintf(fout, "\tARP dip:   %3d.%3d.%3d.%3d\n",
            pkt.dip[0], pkt.dip[1], pkt.dip[2], pkt.dip[3]);    
}

#define IP_GET_VERSION(hdr) (uint8_t) (hdr.version_ihl >> 4)
#define IP_GET_IHL(hdr) (uint8_t) (hdr.version_ihl & 0x0f)
#define IP_GET_DSCP(hdr) (uint8_t) (hdr.dscp_ecn >> 2)
#define IP_GET_ECN(hdr) (uint8_t) (hdr.dscp_ecn & 0x03)
#define IP_GET_FLAGS(hdr) (uint8_t) (hdr.flags_fragoffset >> 13)
#define IP_GET_FRAGOFFSET(hdr) (uint16_t) (hdr.flags_fragoffset & 0x1fff)

struct ip_hdr get_ip_hdr(const uint8_t *ip_pkt_data, int len) {
    struct ip_hdr hdr;
    memcpy(&hdr, ip_pkt_data, sizeof(struct ip_hdr));
    hdr.length = ntohs(hdr.length);
    hdr.id = ntohs(hdr.id);
    hdr.flags_fragoffset = ntohs(hdr.flags_fragoffset);
    hdr.checksum = ntohs(hdr.checksum);
    hdr.options = ntohl(hdr.options);
    return hdr;
}

void log_ip_hdr_raw(const uint8_t *pkg_data, FILE *fout) {
    fprintf(fout, "\tIP HEADER RAW: ");
    for (int i = 0; i < 20; i++) {
        if (i % 4 == 0)
            fprintf(fout, "\n\t");
        if (i % 4 == 2)
            fprintf(fout, " ");
        fprintf(fout, "%02x", *(pkg_data + i));
    }
    fprintf(fout, "\n");
}

void log_ip_hdr(struct ip_hdr hdr, FILE *fout) {
    fprintf(fout, "\tIP version:  0x%01x\n", IP_GET_VERSION(hdr));
    fprintf(fout, "\tIP ihl:      0x%01x\n", IP_GET_IHL(hdr));
    fprintf(fout, "\tIP dscp:     0x%02x\n", IP_GET_DSCP(hdr));
    fprintf(fout, "\tIP ecn:      0x%1x\n", IP_GET_ECN(hdr));
    fprintf(fout, "\tIP length:   0x%04x\n", hdr.length);
    fprintf(fout, "\tIP id:       0x%04x\n", hdr.id);
    fprintf(fout, "\tIP flags:    0x%1x\n", IP_GET_FLAGS(hdr));
    fprintf(fout, "\tIP fragoff:  0x%04x\n", IP_GET_FRAGOFFSET(hdr));
    fprintf(fout, "\tIP ttl:      0x%02x\n", hdr.ttl);
    fprintf(fout, "\tIP protocol: 0x%02x\n", hdr.protocol);
    fprintf(fout, "\tIP checksum: 0x%04x\n", hdr.checksum);
    fprintf(fout, "\tIP sip:      %3d.%3d.%3d.%3d\n",
            hdr.sip[0], hdr.sip[1], hdr.sip[2], hdr.sip[3]);
    fprintf(fout, "\tIP dip:      %3d.%3d.%3d.%3d\n",
            hdr.dip[0], hdr.dip[1], hdr.dip[2], hdr.dip[3]);
    if (IP_GET_IHL(hdr) > 5)
        fprintf(fout, "\tIP options:  0x%8x\n", hdr.options);
}

struct icmp_hdr get_icmp_hdr(const uint8_t *pkt_data, int len) {
    struct icmp_hdr hdr;
    memcpy(&hdr, pkt_data, sizeof(struct icmp_hdr));
    hdr.checksum = ntohs(hdr.checksum);
    hdr.rest = ntohl(hdr.rest);
    return hdr;
}

void log_icmp_hdr(struct icmp_hdr hdr, FILE *fout) {
    fprintf(fout, "\t\tICMP type:       0x%02x\n", hdr.type);
    fprintf(fout, "\t\tICMP code:       0x%02x\n", hdr.code);
    fprintf(fout, "\t\tICMP checksum:   0x%04x\n", hdr.checksum);
    fprintf(fout, "\t\tICMP rest:       0x%08x\n", hdr.rest);
}

struct udp_hdr get_udp_hdr(const uint8_t *pkt_data, int len) {
    struct udp_hdr hdr;
    memcpy(&hdr, pkt_data, sizeof(struct udp_hdr));
    hdr.sport = ntohs(hdr.sport);
    hdr.dport = ntohs(hdr.dport);
    hdr.length = ntohs(hdr.length);
    hdr.checksum = ntohs(hdr.checksum);
    return hdr;
}

void log_udp_hdr(struct udp_hdr hdr, FILE *fout) {
    fprintf(fout, "\t\tUDP sport:    0x%04x\n", hdr.sport);
    fprintf(fout, "\t\tUDP dport:    0x%04x\n", hdr.dport);
    fprintf(fout, "\t\tUDP length:   0x%04x\n", hdr.length);
    fprintf(fout, "\t\tUDP checksum: 0x%04x\n", hdr.checksum);
}

#define _GET_TCP_DATA_OFFSET(hdr) (uint8_t) (hdr.meta >> 12)
#define GET_TCP_DATA_OFFSET(hdr) (uint8_t) (hdr.m.meta >> 12)
#define GET_TCP_RESERVED(hdr) (uint8_t) ((hdr.m.meta >> 9) & 0x07)
#define GET_TCP_NS(hdr) (uint8_t) ((hdr.m.meta >> 8) & 0x01)
#define GET_TCP_CWR(hdr) (uint8_t) ((hdr.m.meta >> 7) & 0x01)
#define GET_TCP_ECE(hdr) (uint8_t) ((hdr.m.meta >> 6) & 0x01)
#define GET_TCP_URG(hdr) (uint8_t) ((hdr.m.meta >> 5) & 0x01)
#define GET_TCP_ACK(hdr) (uint8_t) ((hdr.m.meta >> 4) & 0x01)
#define GET_TCP_PSH(hdr) (uint8_t) ((hdr.m.meta >> 3) & 0x01)
#define GET_TCP_RST(hdr) (uint8_t) ((hdr.m.meta >> 2) & 0x01)
#define GET_TCP_SYN(hdr) (uint8_t) ((hdr.m.meta >> 1) & 0x01)
#define GET_TCP_FIN(hdr) (uint8_t) (hdr.m.meta & 0x01)

struct tcp_hdr get_tcp_hdr(const uint8_t *pkt_data, int len) {
    struct tcp_mandatory man_hdr;
    memcpy(&man_hdr, pkt_data, sizeof(struct tcp_mandatory));
    man_hdr.sport = ntohs(man_hdr.sport);
    man_hdr.dport = ntohs(man_hdr.dport);
    man_hdr.seq = ntohl(man_hdr.seq);
    man_hdr.ack = ntohl(man_hdr.ack);
    man_hdr.meta = ntohs(man_hdr.meta);
    man_hdr.winsz = ntohs(man_hdr.winsz);
    man_hdr.checksum = ntohs(man_hdr.checksum);
    man_hdr.urgptr = ntohs(man_hdr.urgptr);
    struct tcp_hdr hdr;
    hdr.m = man_hdr;
    uint8_t data_offset = _GET_TCP_DATA_OFFSET(man_hdr);
    if (data_offset > 5) {
        memcpy(&hdr.options, pkt_data + 5 * 4, (data_offset - 5) * 4);
        for (int i = 0; i < 10; i++)
            hdr.options[i] = ntohl(hdr.options[i]);
    }
    return hdr;
}

void log_tcp_hdr_raw(const uint8_t *pkt_data, FILE *fout) {
    fprintf(fout, "\t\tTCP WHOLE HEADER:");
    for (int i = 0; i < 20; i++) {
        if (i % 4 == 0)
            fprintf(fout, "\n\t\t");
        if (i % 4 == 2)
            fprintf(fout, " ");
        fprintf(fout, "%02x", *(pkt_data + i));
    }
    fprintf(fout, "\n");
}

void log_tcp_hdr(struct tcp_hdr hdr, FILE *fout) {
    fprintf(fout, "\t\tTCP sport:    0x%02x\n", hdr.m.sport);
    fprintf(fout, "\t\tTCP dport:    0x%02x\n", hdr.m.dport);
    fprintf(fout, "\t\tTCP seq:      0x%04x\n", hdr.m.seq);
    fprintf(fout, "\t\tTCP ack:      0x%04x\n", hdr.m.ack);
    fprintf(fout, "\t\tTCP offset:   0x%01x\n", GET_TCP_DATA_OFFSET(hdr));
    fprintf(fout, "\t\tTCP reserved: 0x%01x\n", GET_TCP_RESERVED(hdr));
    fprintf(fout, "\t\tTCP NS:       0x%01x\n", GET_TCP_NS(hdr));
    fprintf(fout, "\t\tTCP CWR:      0x%01x\n", GET_TCP_CWR(hdr));
    fprintf(fout, "\t\tTCP ECE:      0x%01x\n", GET_TCP_ECE(hdr));
    fprintf(fout, "\t\tTCP URG:      0x%01x\n", GET_TCP_URG(hdr));
    fprintf(fout, "\t\tTCP ACK:      0x%01x\n", GET_TCP_ACK(hdr));
    fprintf(fout, "\t\tTCP PSH:      0x%01x\n", GET_TCP_PSH(hdr));
    fprintf(fout, "\t\tTCP RST:      0x%01x\n", GET_TCP_RST(hdr));
    fprintf(fout, "\t\tTCP SYN:      0x%01x\n", GET_TCP_SYN(hdr));
    fprintf(fout, "\t\tTCP FIN:      0x%01x\n", GET_TCP_FIN(hdr));
}

void log_frame_info(const uint8_t *pkt, int len, int inbound, FILE *fout) {
    struct eth_hdr hdr = get_eth_hdr(pkt, len);
    int offset = 0;
    log_eth_hdr(hdr, fout);
    if (hdr.type == 0x0806) {
        offset = sizeof(struct eth_hdr);
        struct arp_pkt pkt_arp = get_arp_pkt(pkt + offset, len - offset);
        log_arp(pkt_arp, fout);
    }
    if (hdr.type == 0x0800) {
        offset = sizeof(struct eth_hdr);
        struct ip_hdr hdr_ip = get_ip_hdr(pkt + offset, len - offset);
        log_ip_hdr_raw(pkt + offset, fout);
        log_ip_hdr(hdr_ip, fout);


        offset = sizeof(struct eth_hdr) + sizeof(struct ip_hdr);
        if (IP_GET_IHL(hdr_ip) <= 5) {
            //when IHL <= 5, there's no options in IP header
            offset -= sizeof(uint32_t);
        }
        if (hdr_ip.protocol == 0x1) {
            struct icmp_hdr hdr_icmp = get_icmp_hdr(pkt + offset, len - offset);
            log_icmp_hdr(hdr_icmp, fout);
        }
        if (hdr_ip.protocol == 0x11) {
            struct udp_hdr hdr_udp = get_udp_hdr(pkt + offset, len - offset);
            log_udp_hdr(hdr_udp, fout);
        }
        if (hdr_ip.protocol == 0x6) {
            struct tcp_hdr hdr_tcp = get_tcp_hdr(pkt + offset, len - offset);
            log_tcp_hdr_raw(pkt + offset, fout);
            log_tcp_hdr(hdr_tcp, fout);
        }
    }
}

void hx_dump_frame(const uint8_t *pkt, int pkt_len, int inbound) {

    FILE *f = fopen("/tmp/pkg.dat", "a+");
    if (inbound) {
        fwrite(INBOUND_MSG, strlen(INBOUND_MSG), 1, f);
    } else {
        fwrite(OUTBOUND_MSG, strlen(OUTBOUND_MSG), 1, f);
    }
    
    char buf[256];
    sprintf(buf, ":%d:\n", pkt_len);
    fwrite(buf, strlen(buf), 1, f);
    fwrite(pkt, pkt_len, 1, f);
    
    fclose(f);
        
    FILE * f1 = fopen("/tmp/pkg2.dat", "a+");
    log_frame_info(pkt, pkt_len, inbound, f1);
    
    fclose(f1);
    
}

void slirp_output(void *opaque, const uint8_t *pkt, int pkt_len)
{
	hx_dump_frame(pkt, pkt_len, 1);
    SlirpState *s = opaque;

    qemu_send_packet(&s->nc, pkt, pkt_len);
}

static ssize_t net_slirp_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    SlirpState *s = DO_UPCAST(SlirpState, nc, nc);

    slirp_input(s->slirp, buf, size);

    return size;
}

static void net_slirp_cleanup(NetClientState *nc)
{
    SlirpState *s = DO_UPCAST(SlirpState, nc, nc);

    slirp_cleanup(s->slirp);
    slirp_smb_cleanup(s);
    QTAILQ_REMOVE(&slirp_stacks, s, entry);
}

static NetClientInfo net_slirp_info = {
    .type = NET_CLIENT_OPTIONS_KIND_USER,
    .size = sizeof(SlirpState),
    .receive = net_slirp_receive,
    .cleanup = net_slirp_cleanup,
};

#include "hx_debug.h"

static int net_slirp_init(NetClientState *peer, const char *model,
                          const char *name, int restricted,
                          const char *vnetwork, const char *vhost,
                          const char *vhostname, const char *tftp_export,
                          const char *bootfile, const char *vdhcp_start,
                          const char *vnameserver, const char *smb_export,
                          const char *vsmbserver, const char **dnssearch)
{
    hxdbg("%s %s", __FILE__, __FUNCTION__);
    /* default settings according to historic slirp */
    struct in_addr net  = { .s_addr = htonl(0x0a000200) }; /* 10.0.2.0 */
    struct in_addr mask = { .s_addr = htonl(0xffffff00) }; /* 255.255.255.0 */
    struct in_addr host = { .s_addr = htonl(0x0a000202) }; /* 10.0.2.2 */
    struct in_addr dhcp = { .s_addr = htonl(0x0a00020f) }; /* 10.0.2.15 */
    struct in_addr dns  = { .s_addr = htonl(0x0a000203) }; /* 10.0.2.3 */
#ifndef _WIN32
    struct in_addr smbsrv = { .s_addr = 0 };
#endif
    NetClientState *nc;
    SlirpState *s;
    char buf[20];
    uint32_t addr;
    int shift;
    char *end;
    struct slirp_config_str *config;

    if (!tftp_export) {
        tftp_export = legacy_tftp_prefix;
    }
    if (!bootfile) {
        bootfile = legacy_bootp_filename;
    }

    if (vnetwork) {
        if (get_str_sep(buf, sizeof(buf), &vnetwork, '/') < 0) {
            if (!inet_aton(vnetwork, &net)) {
                return -1;
            }
            addr = ntohl(net.s_addr);
            if (!(addr & 0x80000000)) {
                mask.s_addr = htonl(0xff000000); /* class A */
            } else if ((addr & 0xfff00000) == 0xac100000) {
                mask.s_addr = htonl(0xfff00000); /* priv. 172.16.0.0/12 */
            } else if ((addr & 0xc0000000) == 0x80000000) {
                mask.s_addr = htonl(0xffff0000); /* class B */
            } else if ((addr & 0xffff0000) == 0xc0a80000) {
                mask.s_addr = htonl(0xffff0000); /* priv. 192.168.0.0/16 */
            } else if ((addr & 0xffff0000) == 0xc6120000) {
                mask.s_addr = htonl(0xfffe0000); /* tests 198.18.0.0/15 */
            } else if ((addr & 0xe0000000) == 0xe0000000) {
                mask.s_addr = htonl(0xffffff00); /* class C */
            } else {
                mask.s_addr = htonl(0xfffffff0); /* multicast/reserved */
            }
        } else {
            if (!inet_aton(buf, &net)) {
                return -1;
            }
            shift = strtol(vnetwork, &end, 10);
            if (*end != '\0') {
                if (!inet_aton(vnetwork, &mask)) {
                    return -1;
                }
            } else if (shift < 4 || shift > 32) {
                return -1;
            } else {
                mask.s_addr = htonl(0xffffffff << (32 - shift));
            }
        }
        net.s_addr &= mask.s_addr;
        host.s_addr = net.s_addr | (htonl(0x0202) & ~mask.s_addr);
        dhcp.s_addr = net.s_addr | (htonl(0x020f) & ~mask.s_addr);
        dns.s_addr  = net.s_addr | (htonl(0x0203) & ~mask.s_addr);
    }

    if (vhost && !inet_aton(vhost, &host)) {
        return -1;
    }
    if ((host.s_addr & mask.s_addr) != net.s_addr) {
        return -1;
    }

    if (vnameserver && !inet_aton(vnameserver, &dns)) {
        return -1;
    }
    if ((dns.s_addr & mask.s_addr) != net.s_addr ||
        dns.s_addr == host.s_addr) {
        return -1;
    }

    if (vdhcp_start && !inet_aton(vdhcp_start, &dhcp)) {
        return -1;
    }
    if ((dhcp.s_addr & mask.s_addr) != net.s_addr ||
        dhcp.s_addr == host.s_addr || dhcp.s_addr == dns.s_addr) {
        return -1;
    }

#ifndef _WIN32
    if (vsmbserver && !inet_aton(vsmbserver, &smbsrv)) {
        return -1;
    }
#endif

    nc = qemu_new_net_client(&net_slirp_info, peer, model, name);

    snprintf(nc->info_str, sizeof(nc->info_str),
             "net=%s,restrict=%s", inet_ntoa(net),
             restricted ? "on" : "off");

    s = DO_UPCAST(SlirpState, nc, nc);

    s->slirp = slirp_init(restricted, net, mask, host, vhostname,
                          tftp_export, bootfile, dhcp, dns, dnssearch, s);
    QTAILQ_INSERT_TAIL(&slirp_stacks, s, entry);

    for (config = slirp_configs; config; config = config->next) {
        if (config->flags & SLIRP_CFG_HOSTFWD) {
            if (slirp_hostfwd(s, config->str,
                              config->flags & SLIRP_CFG_LEGACY) < 0)
                goto error;
        } else {
            if (slirp_guestfwd(s, config->str,
                               config->flags & SLIRP_CFG_LEGACY) < 0)
                goto error;
        }
    }
#ifndef _WIN32
    if (!smb_export) {
        smb_export = legacy_smb_export;
    }
    if (smb_export) {
        if (slirp_smb(s, smb_export, smbsrv) < 0)
            goto error;
    }
#endif

    return 0;

error:
    qemu_del_net_client(nc);
    return -1;
}

static SlirpState *slirp_lookup(Monitor *mon, const char *vlan,
                                const char *stack)
{

    if (vlan) {
        NetClientState *nc;
        nc = net_hub_find_client_by_name(strtol(vlan, NULL, 0), stack);
        if (!nc) {
            return NULL;
        }
        if (strcmp(nc->model, "user")) {
            monitor_printf(mon, "invalid device specified\n");
            return NULL;
        }
        return DO_UPCAST(SlirpState, nc, nc);
    } else {
        if (QTAILQ_EMPTY(&slirp_stacks)) {
            monitor_printf(mon, "user mode network stack not in use\n");
            return NULL;
        }
        return QTAILQ_FIRST(&slirp_stacks);
    }
}

void net_slirp_hostfwd_remove(Monitor *mon, const QDict *qdict)
{
    struct in_addr host_addr = { .s_addr = INADDR_ANY };
    int host_port;
    char buf[256];
    const char *src_str, *p;
    SlirpState *s;
    int is_udp = 0;
    int err;
    const char *arg1 = qdict_get_str(qdict, "arg1");
    const char *arg2 = qdict_get_try_str(qdict, "arg2");
    const char *arg3 = qdict_get_try_str(qdict, "arg3");

    if (arg2) {
        s = slirp_lookup(mon, arg1, arg2);
        src_str = arg3;
    } else {
        s = slirp_lookup(mon, NULL, NULL);
        src_str = arg1;
    }
    if (!s) {
        return;
    }

    p = src_str;
    if (!p || get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
        goto fail_syntax;
    }

    if (!strcmp(buf, "tcp") || buf[0] == '\0') {
        is_udp = 0;
    } else if (!strcmp(buf, "udp")) {
        is_udp = 1;
    } else {
        goto fail_syntax;
    }

    if (get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
        goto fail_syntax;
    }
    if (buf[0] != '\0' && !inet_aton(buf, &host_addr)) {
        goto fail_syntax;
    }

    host_port = atoi(p);

    err = slirp_remove_hostfwd(QTAILQ_FIRST(&slirp_stacks)->slirp, is_udp,
                               host_addr, host_port);

    monitor_printf(mon, "host forwarding rule for %s %s\n", src_str,
                   err ? "not found" : "removed");
    return;

 fail_syntax:
    monitor_printf(mon, "invalid format\n");
}

static int slirp_hostfwd(SlirpState *s, const char *redir_str,
                         int legacy_format)
{
    struct in_addr host_addr = { .s_addr = INADDR_ANY };
    struct in_addr guest_addr = { .s_addr = 0 };
    int host_port, guest_port;
    const char *p;
    char buf[256];
    int is_udp;
    char *end;

    p = redir_str;
    if (!p || get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
        goto fail_syntax;
    }
    if (!strcmp(buf, "tcp") || buf[0] == '\0') {
        is_udp = 0;
    } else if (!strcmp(buf, "udp")) {
        is_udp = 1;
    } else {
        goto fail_syntax;
    }

    if (!legacy_format) {
        if (get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
            goto fail_syntax;
        }
        if (buf[0] != '\0' && !inet_aton(buf, &host_addr)) {
            goto fail_syntax;
        }
    }

    if (get_str_sep(buf, sizeof(buf), &p, legacy_format ? ':' : '-') < 0) {
        goto fail_syntax;
    }
    host_port = strtol(buf, &end, 0);
    if (*end != '\0' || host_port < 1 || host_port > 65535) {
        goto fail_syntax;
    }

    if (get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
        goto fail_syntax;
    }
    if (buf[0] != '\0' && !inet_aton(buf, &guest_addr)) {
        goto fail_syntax;
    }

    guest_port = strtol(p, &end, 0);
    if (*end != '\0' || guest_port < 1 || guest_port > 65535) {
        goto fail_syntax;
    }

    if (slirp_add_hostfwd(s->slirp, is_udp, host_addr, host_port, guest_addr,
                          guest_port) < 0) {
        error_report("could not set up host forwarding rule '%s'",
                     redir_str);
        return -1;
    }
    return 0;

 fail_syntax:
    error_report("invalid host forwarding rule '%s'", redir_str);
    return -1;
}

void net_slirp_hostfwd_add(Monitor *mon, const QDict *qdict)
{
    const char *redir_str;
    SlirpState *s;
    const char *arg1 = qdict_get_str(qdict, "arg1");
    const char *arg2 = qdict_get_try_str(qdict, "arg2");
    const char *arg3 = qdict_get_try_str(qdict, "arg3");

    if (arg2) {
        s = slirp_lookup(mon, arg1, arg2);
        redir_str = arg3;
    } else {
        s = slirp_lookup(mon, NULL, NULL);
        redir_str = arg1;
    }
    if (s) {
        slirp_hostfwd(s, redir_str, 0);
    }

}

int net_slirp_redir(const char *redir_str)
{
    struct slirp_config_str *config;

    if (QTAILQ_EMPTY(&slirp_stacks)) {
        config = g_malloc(sizeof(*config));
        pstrcpy(config->str, sizeof(config->str), redir_str);
        config->flags = SLIRP_CFG_HOSTFWD | SLIRP_CFG_LEGACY;
        config->next = slirp_configs;
        slirp_configs = config;
        return 0;
    }

    return slirp_hostfwd(QTAILQ_FIRST(&slirp_stacks), redir_str, 1);
}

#ifndef _WIN32

/* automatic user mode samba server configuration */
static void slirp_smb_cleanup(SlirpState *s)
{
    char cmd[128];
    int ret;

    if (s->smb_dir[0] != '\0') {
        snprintf(cmd, sizeof(cmd), "rm -rf %s", s->smb_dir);
        ret = system(cmd);
        if (ret == -1 || !WIFEXITED(ret)) {
            error_report("'%s' failed.", cmd);
        } else if (WEXITSTATUS(ret)) {
            error_report("'%s' failed. Error code: %d",
                         cmd, WEXITSTATUS(ret));
        }
        s->smb_dir[0] = '\0';
    }
}

static int slirp_smb(SlirpState* s, const char *exported_dir,
                     struct in_addr vserver_addr)
{
    static int instance;
    char smb_conf[128];
    char smb_cmdline[128];
    struct passwd *passwd;
    FILE *f;

    passwd = getpwuid(geteuid());
    if (!passwd) {
        error_report("failed to retrieve user name");
        return -1;
    }

    if (access(CONFIG_SMBD_COMMAND, F_OK)) {
        error_report("could not find '%s', please install it",
                     CONFIG_SMBD_COMMAND);
        return -1;
    }

    if (access(exported_dir, R_OK | X_OK)) {
        error_report("error accessing shared directory '%s': %s",
                     exported_dir, strerror(errno));
        return -1;
    }

    snprintf(s->smb_dir, sizeof(s->smb_dir), "/tmp/qemu-smb.%ld-%d",
             (long)getpid(), instance++);
    if (mkdir(s->smb_dir, 0700) < 0) {
        error_report("could not create samba server dir '%s'", s->smb_dir);
        return -1;
    }
    snprintf(smb_conf, sizeof(smb_conf), "%s/%s", s->smb_dir, "smb.conf");

    f = fopen(smb_conf, "w");
    if (!f) {
        slirp_smb_cleanup(s);
        error_report("could not create samba server configuration file '%s'",
                     smb_conf);
        return -1;
    }
    fprintf(f,
            "[global]\n"
            "private dir=%s\n"
            "socket address=127.0.0.1\n"
            "pid directory=%s\n"
            "lock directory=%s\n"
            "state directory=%s\n"
            "log file=%s/log.smbd\n"
            "smb passwd file=%s/smbpasswd\n"
            "security = share\n"
            "[qemu]\n"
            "path=%s\n"
            "read only=no\n"
            "guest ok=yes\n"
            "force user=%s\n",
            s->smb_dir,
            s->smb_dir,
            s->smb_dir,
            s->smb_dir,
            s->smb_dir,
            s->smb_dir,
            exported_dir,
            passwd->pw_name
            );
    fclose(f);

    snprintf(smb_cmdline, sizeof(smb_cmdline), "%s -s %s",
             CONFIG_SMBD_COMMAND, smb_conf);

    if (slirp_add_exec(s->slirp, 0, smb_cmdline, &vserver_addr, 139) < 0) {
        slirp_smb_cleanup(s);
        error_report("conflicting/invalid smbserver address");
        return -1;
    }
    return 0;
}

/* automatic user mode samba server configuration (legacy interface) */
int net_slirp_smb(const char *exported_dir)
{
    struct in_addr vserver_addr = { .s_addr = 0 };

    if (legacy_smb_export) {
        fprintf(stderr, "-smb given twice\n");
        return -1;
    }
    legacy_smb_export = exported_dir;
    if (!QTAILQ_EMPTY(&slirp_stacks)) {
        return slirp_smb(QTAILQ_FIRST(&slirp_stacks), exported_dir,
                         vserver_addr);
    }
    return 0;
}

#endif /* !defined(_WIN32) */

struct GuestFwd {
    CharDriverState *hd;
    struct in_addr server;
    int port;
    Slirp *slirp;
};

static int guestfwd_can_read(void *opaque)
{
    struct GuestFwd *fwd = opaque;
    return slirp_socket_can_recv(fwd->slirp, fwd->server, fwd->port);
}

static void guestfwd_read(void *opaque, const uint8_t *buf, int size)
{
    struct GuestFwd *fwd = opaque;
    slirp_socket_recv(fwd->slirp, fwd->server, fwd->port, buf, size);
}

static int slirp_guestfwd(SlirpState *s, const char *config_str,
                          int legacy_format)
{
    struct in_addr server = { .s_addr = 0 };
    struct GuestFwd *fwd;
    const char *p;
    char buf[128];
    char *end;
    int port;

    p = config_str;
    if (legacy_format) {
        if (get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
            goto fail_syntax;
        }
    } else {
        if (get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
            goto fail_syntax;
        }
        if (strcmp(buf, "tcp") && buf[0] != '\0') {
            goto fail_syntax;
        }
        if (get_str_sep(buf, sizeof(buf), &p, ':') < 0) {
            goto fail_syntax;
        }
        if (buf[0] != '\0' && !inet_aton(buf, &server)) {
            goto fail_syntax;
        }
        if (get_str_sep(buf, sizeof(buf), &p, '-') < 0) {
            goto fail_syntax;
        }
    }
    port = strtol(buf, &end, 10);
    if (*end != '\0' || port < 1 || port > 65535) {
        goto fail_syntax;
    }

    fwd = g_malloc(sizeof(struct GuestFwd));
    snprintf(buf, sizeof(buf), "guestfwd.tcp.%d", port);

    if ((strlen(p) > 4) && !strncmp(p, "cmd:", 4)) {
        if (slirp_add_exec(s->slirp, 0, &p[4], &server, port) < 0) {
            error_report("conflicting/invalid host:port in guest forwarding "
                         "rule '%s'", config_str);
            g_free(fwd);
            return -1;
        }
    } else {
        fwd->hd = qemu_chr_new(buf, p, NULL);
        if (!fwd->hd) {
            error_report("could not open guest forwarding device '%s'", buf);
            g_free(fwd);
            return -1;
        }

        if (slirp_add_exec(s->slirp, 3, fwd->hd, &server, port) < 0) {
            error_report("conflicting/invalid host:port in guest forwarding "
                         "rule '%s'", config_str);
            g_free(fwd);
            return -1;
        }
        fwd->server = server;
        fwd->port = port;
        fwd->slirp = s->slirp;

        qemu_chr_fe_claim_no_fail(fwd->hd);
        qemu_chr_add_handlers(fwd->hd, guestfwd_can_read, guestfwd_read,
                              NULL, fwd);
    }
    return 0;

 fail_syntax:
    error_report("invalid guest forwarding rule '%s'", config_str);
    return -1;
}

void do_info_usernet(Monitor *mon, const QDict *qdict)
{
    SlirpState *s;

    QTAILQ_FOREACH(s, &slirp_stacks, entry) {
        int id;
        bool got_vlan_id = net_hub_id_for_client(&s->nc, &id) == 0;
        monitor_printf(mon, "VLAN %d (%s):\n",
                       got_vlan_id ? id : -1,
                       s->nc.name);
        slirp_connection_info(s->slirp, mon);
    }
}

static void
net_init_slirp_configs(const StringList *fwd, int flags)
{
    while (fwd) {
        struct slirp_config_str *config;

        config = g_malloc0(sizeof(*config));
        pstrcpy(config->str, sizeof(config->str), fwd->value->str);
        config->flags = flags;
        config->next = slirp_configs;
        slirp_configs = config;

        fwd = fwd->next;
    }
}

static const char **slirp_dnssearch(const StringList *dnsname)
{
    const StringList *c = dnsname;
    size_t i = 0, num_opts = 0;
    const char **ret;

    while (c) {
        num_opts++;
        c = c->next;
    }

    if (num_opts == 0) {
        return NULL;
    }

    ret = g_malloc((num_opts + 1) * sizeof(*ret));
    c = dnsname;
    while (c) {
        ret[i++] = c->value->str;
        c = c->next;
    }
    ret[i] = NULL;
    return ret;
}

#include "hx_debug.h"

int net_init_slirp(const NetClientOptions *opts, const char *name,
                   NetClientState *peer)
{
    hxdbg("%s %s\n", __FILE__,  __FUNCTION__);
    struct slirp_config_str *config;
    char *vnet;
    int ret;
    const NetdevUserOptions *user;
    const char **dnssearch;

    assert(opts->kind == NET_CLIENT_OPTIONS_KIND_USER);
    user = opts->user;

    vnet = user->has_net ? g_strdup(user->net) :
           user->has_ip  ? g_strdup_printf("%s/24", user->ip) :
           NULL;

    dnssearch = slirp_dnssearch(user->dnssearch);

    /* all optional fields are initialized to "all bits zero" */

    net_init_slirp_configs(user->hostfwd, SLIRP_CFG_HOSTFWD);
    net_init_slirp_configs(user->guestfwd, 0);

    ret = net_slirp_init(peer, "user", name, user->q_restrict, vnet,
                         user->host, user->hostname, user->tftp,
                         user->bootfile, user->dhcpstart, user->dns, user->smb,
                         user->smbserver, dnssearch);

    while (slirp_configs) {
        config = slirp_configs;
        slirp_configs = config->next;
        g_free(config);
    }

    g_free(vnet);
    g_free(dnssearch);

    return ret;
}

int net_slirp_parse_legacy(QemuOptsList *opts_list, const char *optarg, int *ret)
{
    if (strcmp(opts_list->name, "net") != 0 ||
        strncmp(optarg, "channel,", strlen("channel,")) != 0) {
        return 0;
    }

    /* handle legacy -net channel,port:chr */
    optarg += strlen("channel,");

    if (QTAILQ_EMPTY(&slirp_stacks)) {
        struct slirp_config_str *config;

        config = g_malloc(sizeof(*config));
        pstrcpy(config->str, sizeof(config->str), optarg);
        config->flags = SLIRP_CFG_LEGACY;
        config->next = slirp_configs;
        slirp_configs = config;
        *ret = 0;
    } else {
        *ret = slirp_guestfwd(QTAILQ_FIRST(&slirp_stacks), optarg, 1);
    }

    return 1;
}

