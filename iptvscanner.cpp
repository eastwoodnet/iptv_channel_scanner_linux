/*
 *
 * *iptvscanner.cpp - 多播的客户端
 *
 * */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
using namespace std;

char nicname[1024] = {0};
int iptvscan(unsigned int ip)

{
    char errBuf[PCAP_ERRBUF_SIZE];
    int s; /*套接字文件描述符*/
    int err = -1;
    ip = htonl(ip);
    s = socket(AF_INET, SOCK_DGRAM, 0); /*建立套接字*/
    if (s == -1)
    {
        return -1;
    }

    struct ip_mreq mreq;                           /*加入多播组*/
    mreq.imr_multiaddr.s_addr = ip;         /*多播地址*/
    mreq.imr_interface.s_addr = htonl(INADDR_ANY); /*网络接口为默认*/

    err = setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));
    if (err < 0)
    {
        return -1;
    }

    pcap_t *device = pcap_open_live(nicname, 65535, 1, 1, errBuf); //1ms超时，下边会留出时间填充数据包

    if (!device)
    {
        cout << "error: pcap_open_live():" << errBuf << endl;
        close(s);
        return -1;
    }
    char strfilter[64] = "udp and host ";
    char *strip = strfilter + strlen("udp and host ");
    inet_ntop(AF_INET, &ip, strip, 16);
    /* construct a filter */
    struct bpf_program filter;
    pcap_setnonblock(device, 1, errBuf);
    pcap_compile(device, &filter, strfilter, 1, 0);
    pcap_setfilter(device, &filter);

    usleep(150000);
    struct pcap_pkthdr packet;
    const u_char *pktStr = pcap_next(device, &packet);
    if (pktStr)
    {
        struct udphdr *udphdr = NULL;
        udphdr = (struct udphdr *)(pktStr + 14 + 20);
#ifdef __linux
        printf("#EXTINF:-1,%s:%d\nrtp://%s:%d\n", strip, ntohs(udphdr->dest), strip, ntohs(udphdr->dest));
#elif __APPLE__
	printf("#EXTINF:-1,%s:%d\nrtp://%s:%d\n", strip, ntohs(udphdr->uh_dport), strip, ntohs(udphdr->uh_dport));
#endif
    }
    pcap_close(device);

    err = setsockopt(s, IPPROTO_IP, IP_DROP_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));
    if (err < 0)
    {
        close(s);
        return -1;
    }
    close(s);
    return 0;
}

int main(int argc, char *argv[])
{
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    int inum;
    if (argc != 4)
    {
        cout << "usage:" << endl
             << "\t" << argv[0] <<" \"interfaces\" \"start of ip\" \"end of ip\" " << endl;
        cout << "\t eg.. " << argv[0] << " eno1 239.3.1.1 239.3.1.254" << endl;
        return -1;
    }
    cout << "#EXTM3U name=\"iptvlist\"" << endl;
    strncpy(nicname, argv[1], strlen(argv[1]));
    unsigned int ipstart = 0, ipend = 0;
    inet_pton(AF_INET, argv[2], &ipstart);
    inet_pton(AF_INET, argv[3], &ipend);
    ipstart = ntohl(ipstart);
    ipend = ntohl(ipend);
    for (int ip = ipstart; ip <= ipend; ip++)
    {
        iptvscan(ip);
    }
}
