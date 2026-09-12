// xdpbench: tiny traffic tool for XDP dataplane measurements.
//   drain  <bind_ip> <port>   UDP sink: recv+count
//   echo   <bind_ip> <port>   UDP echo server
//   flood  <if> <dmac> <sip> <dip> <dport> <sbase> <sspan> <secs> [plen]   (IPv4)
//   flood6 <if> <dmac> <sip6> <dip6> <dport> <sbase> <sspan> <secs> [plen] (IPv6)
//          AF_PACKET raw injector; sport cycles [base, base+span) (span 1 = CT-hit)
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now_s(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}
static unsigned short ip_csum(const void *data, int len) {
    const unsigned short *p = data; unsigned int sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const unsigned char *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)~sum;
}
static int udp_rx_loop(const char *ip, int port, int echo, int v6) {
    int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    int rcv = 16 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    struct sockaddr_storage a = {0}; socklen_t al;
    if (v6) {
        struct sockaddr_in6 *a6 = (void *)&a;
        a6->sin6_family = AF_INET6; a6->sin6_port = htons(port);
        inet_pton(AF_INET6, ip, &a6->sin6_addr); al = sizeof(*a6);
    } else {
        struct sockaddr_in *a4 = (void *)&a;
        a4->sin_family = AF_INET; a4->sin_port = htons(port);
        inet_pton(AF_INET, ip, &a4->sin_addr); al = sizeof(*a4);
    }
    if (bind(fd, (void *)&a, al) < 0) { perror("bind"); return 1; }
    char buf[65536]; struct sockaddr_storage peer; socklen_t pl = sizeof(peer);
    unsigned long long n = 0; double t0 = now_s();
    for (;;) {
        ssize_t r = recvfrom(fd, buf, sizeof(buf), 0, (void *)&peer, &pl);
        if (r < 0) continue;
        n++;
        if (echo) sendto(fd, buf, r, 0, (void *)&peer, pl);
        if ((n & 0x3fffff) == 0) fprintf(stderr, "rx %llu (%.0f pps)\n", n, n / (now_s() - t0));
    }
    return 0;
}
static int raw_sock(const char *ifn, const char *dmac_s, unsigned char *smac,
                    unsigned char *dmac, int *ifindex) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return -1; }
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifn, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return -1; }
    *ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { perror("SIOCGIFHWADDR"); return -1; }
    memcpy(smac, ifr.ifr_hwaddr.sa_data, 6);
    unsigned dm[6];
    sscanf(dmac_s, "%x:%x:%x:%x:%x:%x", &dm[0], &dm[1], &dm[2], &dm[3], &dm[4], &dm[5]);
    for (int i = 0; i < 6; i++) dmac[i] = dm[i];
    return fd;
}
static int flood(const char *ifn, const char *dmac_s, const char *sip_s,
                 const char *dip_s, int dport, int sbase, int sspan,
                 int secs, int plen) {
    unsigned char smac[6], dmac[6]; int ifindex;
    int fd = raw_sock(ifn, dmac_s, smac, dmac, &ifindex);
    if (fd < 0) return 1;
    int tlen = 14 + 20 + 8 + plen;
    unsigned char *pkt = calloc(1, tlen);
    struct ethhdr *eth = (void *)pkt;
    memcpy(eth->h_dest, dmac, 6); memcpy(eth->h_source, smac, 6);
    eth->h_proto = htons(ETH_P_IP);
    struct iphdr *ip = (void *)(pkt + 14);
    ip->version = 4; ip->ihl = 5; ip->ttl = 64; ip->protocol = IPPROTO_UDP;
    ip->tot_len = htons(tlen - 14);
    inet_pton(AF_INET, sip_s, &ip->saddr);
    inet_pton(AF_INET, dip_s, &ip->daddr);
    ip->check = ip_csum(ip, 20);
    struct udphdr *udp = (void *)(pkt + 14 + 20);
    udp->dest = htons(dport); udp->len = htons(8 + plen); udp->check = 0;
    memset(pkt + 14 + 20 + 8, 'x', plen);
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET; sll.sll_ifindex = ifindex; sll.sll_halen = 6;
    memcpy(sll.sll_addr, dmac, 6);
    unsigned long long n = 0;
    double t0 = now_s(), end = t0 + secs;
    unsigned sport = sbase;
    while (now_s() < end) {
        udp->source = htons(sport);
        if (sendto(fd, pkt, tlen, 0, (void *)&sll, sizeof(sll)) < 0) { perror("sendto"); break; }
        n++;
        if (++sport >= sbase + sspan) sport = sbase;
    }
    printf("sent %llu in %.2fs = %.0f pps\n", n, now_s() - t0, n / (now_s() - t0));
    return 0;
}
static int flood6(const char *ifn, const char *dmac_s, const char *sip_s,
                  const char *dip_s, int dport, int sbase, int sspan,
                  int secs, int plen) {
    unsigned char smac[6], dmac[6]; int ifindex;
    int fd = raw_sock(ifn, dmac_s, smac, dmac, &ifindex);
    if (fd < 0) return 1;
    int ulen = 8 + plen;
    int tlen = 14 + 40 + ulen;
    unsigned char *pkt = calloc(1, tlen);
    struct ethhdr *eth = (void *)pkt;
    memcpy(eth->h_dest, dmac, 6); memcpy(eth->h_source, smac, 6);
    eth->h_proto = htons(0x86dd);
    struct ip6_hdr *ip6 = (void *)(pkt + 14);
    ip6->ip6_vfc = 0x60; ip6->ip6_plen = htons(ulen);
    ip6->ip6_nxt = IPPROTO_UDP; ip6->ip6_hlim = 64;
    inet_pton(AF_INET6, sip_s, &ip6->ip6_src);
    inet_pton(AF_INET6, dip_s, &ip6->ip6_dst);
    struct udphdr *udp = (void *)(pkt + 14 + 40);
    udp->dest = htons(dport); udp->len = htons(ulen);
    memset(pkt + 14 + 40 + 8, 'x', plen);
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET; sll.sll_ifindex = ifindex; sll.sll_halen = 6;
    memcpy(sll.sll_addr, dmac, 6);
    unsigned long long n = 0;
    double t0 = now_s(), end = t0 + secs;
    unsigned sport = sbase;
    while (now_s() < end) {
        unsigned int sum = 0;
        const unsigned short *w;
        udp->source = htons(sport);
        udp->check = 0;
        w = (const unsigned short *)&ip6->ip6_src;
        for (int i = 0; i < 16; i++) sum += w[i];
        sum += htons(ulen) + htons(IPPROTO_UDP);
        w = (const unsigned short *)udp;
        for (int i = 0; i < ulen / 2; i++) sum += w[i];
        if (ulen & 1) sum += ((const unsigned char *)udp)[ulen - 1] << 8;
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        udp->check = (unsigned short)~sum;
        if (sendto(fd, pkt, tlen, 0, (void *)&sll, sizeof(sll)) < 0) { perror("sendto"); break; }
        n++;
        if (++sport >= sbase + sspan) sport = sbase;
    }
    printf("sent %llu in %.2fs = %.0f pps\n", n, now_s() - t0, n / (now_s() - t0));
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "drain") && argc >= 4) return udp_rx_loop(argv[2], atoi(argv[3]), 0, 0);
    if (!strcmp(argv[1], "echo") && argc >= 4) return udp_rx_loop(argv[2], atoi(argv[3]), 1, 0);
    if (!strcmp(argv[1], "drain6") && argc == 4) return udp_rx_loop(argv[2], atoi(argv[3]), 0, 1);
    if (!strcmp(argv[1], "echo6") && argc == 4) return udp_rx_loop(argv[2], atoi(argv[3]), 1, 1);
    if (!strcmp(argv[1], "flood") && argc >= 10)
        return flood(argv[2], argv[3], argv[4], argv[5], atoi(argv[6]),
                     atoi(argv[7]), atoi(argv[8]), atoi(argv[9]), argc > 10 ? atoi(argv[10]) : 32);
    if (!strcmp(argv[1], "flood6") && argc >= 10)
        return flood6(argv[2], argv[3], argv[4], argv[5], atoi(argv[6]),
                      atoi(argv[7]), atoi(argv[8]), atoi(argv[9]), argc > 10 ? atoi(argv[10]) : 32);
    fprintf(stderr, "usage: drain[6]|echo[6] <ip> <port> | flood[6] <if> <dmac> <sip> <dip> <dport> <sbase> <sspan> <secs> [plen]\n");
    return 2;
}
