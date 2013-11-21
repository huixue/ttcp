#ifndef HX_LIBSTACK_H
#define HX_LIBSTACK_H
struct eth_hdr {
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
};

struct arp_pkt {
    uint8_t htype[2];
    uint8_t ptype[2];
    uint8_t hlen;
    uint8_t plen;
    uint8_t oper[2];
    uint8_t smac[6];
    uint8_t sip[4];
    uint8_t dmac[6];
    uint8_t dip[4];
};

struct ip_hdr {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t length;
    uint16_t id;
    uint16_t flags_fragoffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t sip[4];
    uint8_t dip[4];
    uint32_t options;
};

struct _ip_hdr {
    uint8_t version;
    uint8_t ihl;
    uint8_t dscp;
    uint8_t ecn;
    uint16_t length;
    uint16_t id;    
    uint8_t flags;
    uint16_t fragoffset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t sip[4];
    uint8_t dip[4];
    uint32_t options;
};

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;
};

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t length;
    uint16_t checksum;
};
struct tcp_mandatory {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint16_t meta;
    uint16_t winsz;
    uint16_t checksum;
    uint16_t urgptr;
};

struct tcp_hdr {
    struct tcp_mandatory m;
    uint32_t options[10];
};

void log_frame_info(const uint8_t *pkt, int len, int inbound, FILE *fout);
void log_arp(struct arp_pkt pkt, FILE* fout);


void log_tcp_hdr_raw(const uint8_t *pkt_data, FILE *fout);
void log_tcp_hdr(struct tcp_hdr hdr, FILE *fout);
void log_udp_hdr(struct udp_hdr hdr, FILE *fout);
void log_icmp_hdr(struct icmp_hdr hdr, FILE *fout);
void log_ip_hdr_raw(const uint8_t *pkg_data, FILE *fout);
void log_ip_hdr(struct ip_hdr hdr, FILE *fout);
void log_eth_hdr(struct eth_hdr hdr, FILE *fout);

struct tcp_hdr get_tcp_hdr(const uint8_t *pkt_data, int len);
struct udp_hdr get_udp_hdr(const uint8_t *pkt_data, int len);

struct icmp_hdr get_icmp_hdr(const uint8_t *pkt_data, int len);

struct ip_hdr get_ip_hdr(const uint8_t *ip_pkt_data, int len);

struct eth_hdr get_eth_hdr(const uint8_t *pkt, int len);

struct arp_pkt handle_arp_pkt(const uint8_t *arp_pkt_data, int len);

struct arp_pkt get_arp_pkt(const uint8_t *arp_pkt_data, int len);
#endif
