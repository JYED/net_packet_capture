#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

// IP 헤더 구조체
struct ip *iph;

// TCP 헤더 구조체
struct tcphdr *tcph;

// 패킷을 받아들일경우 이 함수를 호출한다.  
// packet 가 받아들인 패킷이다.
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, 
                const u_char *packet)
{
    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;    
    int chcnt =0;
    int length=pkthdr->len;
    char *ip_src_addr;
    char *ip_dst_addr;
    struct in_addr in_src;
    struct in_addr in_dst;
    struct hostent *myhost_src;
    struct hostent *myhost_dst;
    
    pcap_addr_t *dev_addr; // i dont know what it is


    // 이더넷 헤더를 가져온다. 
    ep = (struct ether_header *)packet;

    // IP 헤더를 가져오기 위해서 
    // 이더넷 헤더 크기만큼 offset 한다.   
    packet += sizeof(struct ether_header);

    // 프로토콜 타입을 알아낸다. 
    ether_type = ntohs(ep->ether_type);

    printf("ether_type: %d\n",ether_type);
    // 만약 IP 패킷이라면 
    if (ether_type == ETHERTYPE_IP) // /usr/include/net/ether_header.h
    {
        iph = (struct ip *)packet;

        in_src=iph->ip_src;
        in_dst=iph->ip_dst;

        myhost_src = gethostbyaddr((char*)&(in_src.s_addr), sizeof(in_src.s_addr), AF_INET);

        myhost_dst = gethostbyaddr((char*)&(in_dst.s_addr), sizeof(in_src.s_addr), AF_INET);

        printf("IP 패킷\n");
        printf("Version     : %d\n", iph->ip_v);
        printf("Header Len  : %d\n", iph->ip_hl);
        printf("Ident       : %d\n", ntohs(iph->ip_id));
        printf("TTL         : %d\n", iph->ip_ttl); 
        printf("Src Address : %s        %s\n", inet_ntoa(iph->ip_src), myhost_src->h_name);
        printf("Dst Address : %s        %s\n", inet_ntoa(iph->ip_dst), myhost_dst->h_name);

        // 만약 TCP 데이타 라면
        // TCP 정보를 출력한다. 
        if (iph->ip_p == IPPROTO_TCP) // netinet/in.h
        {
            tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
            printf("Src Port : %d\n" , ntohs(tcph->source));
            printf("Dst Port : %d\n" , ntohs(tcph->dest));
        }

        // Packet 데이타 를 출력한다. 
        // IP 헤더 부터 출력한다.  
        while(length--)
        {
            printf("%02x", *(packet++)); 
            if ((++chcnt % 16) == 0) 
                printf("\n");
        }
    }
    // IP 패킷이 아니라면 
    else
    {
        printf("NONE IP 패킷\n");
    }
    printf("\n\n");
}    

int main(int argc, char **argv)
{
    char *dev;
    char *net;
    char *mask;
    pcap_if_t *alldevs;
    pcap_if_t *d;
    pcap_addr_t *dev_addr;
    bpf_u_int32 netp,maskp;
    struct in_addr netaddr;
    struct in_addr maskaddr;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret, inum, i=0;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;

    struct bpf_program fp;     

    pcap_t *pcd;  // packet capture descriptor

    // 사용중인 디바이스 이름을 얻어온다. 
    ret = pcap_findalldevs(&alldevs, errbuf);
    if(ret == -1){
        printf("pcap_findalldevs : %s\n", errbuf);

        exit(1);
    }

    for(d=alldevs; d; d=d->next){
        printf("%d : %s : ",++i, d->name);
        if(d->description)
                printf("%d description : %s \n", i, d->description);
        else
                printf("No description available\n");
    }

    // 디바이스 이름에 대한 네트웍/마스크 정보를 얻어온다.
    printf("Enter interface number (1-%d): ",i);
    scanf("%d", &inum);

    for(d=alldevs, i=0; i<(inum-1); d=d->next, i++){
        dev = d->name;
        printf("DEV             : %s\n",dev);
        }

    for(dev_addr=d->addresses; dev_addr!=NULL; dev_addr=dev_addr->next){
        if(dev_addr->addr->sa_family == AF_INET){
                if(dev_addr->addr != NULL){
                        netaddr = (((struct sockaddr_in *)dev_addr->addr)->sin_addr);
                        net = inet_ntoa(netaddr);
                        printf("IP Addr : %s \n", net);

                }
                else
                        printf("NULL Add\n");

                if(dev_addr -> netmask != NULL){
                        maskaddr = (((struct sockaddr_in *)dev_addr->netmask)->sin_addr);
                        mask = inet_ntoa(maskaddr);
                        printf("subnet : %s \n", mask);
                        }
                else
                        printf("NULL subnet Addr\n");

                }
    }
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if(ret == -1){
        printf("pcap_lookupnet: %s\n",errbuf);
        exit(1);
    }
    // 디바이스 dev 에 대한 packet capture 
    // descriptor 를얻어온다.   
    pcd = pcap_open_live(dev, BUFSIZ,  NONPROMISCUOUS, -1, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }


    // 컴파일 옵션을 준다.
    if (pcap_compile(pcd, &fp, argv[2], 0, netp) == -1)
    {
        printf("compile error\n");    
        exit(1);
    }
    // 컴파일 옵션대로 패킷필터 룰을 세팅한다. 
    if (pcap_setfilter(pcd, &fp) == -1)
    {
        printf("setfilter error\n");
        exit(0);    
    }

    // 지정된 횟수만큼 패킷캡쳐를 한다. 
    // pcap_setfilter 을 통과한 패킷이 들어올경우 
    // callback 함수를 호출하도록 한다. 
    pcap_loop(pcd, atoi(argv[1]), callback, NULL);


}
