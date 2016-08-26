#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

u_short ip_sum_calc(u_short len_ip_header, u_short * buff)
{
    u_short word16;
    u_int sum = 0;
    u_short i;
    for(i = 0; i < len_ip_header; i = i+2)
    {
        word16 = ((buff[i]<<8) & 0xFF00)+(buff[i+1] & 0xFF);
        sum = sum + (u_int) word16;
    }
    while(sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum;

    return ((u_short) sum);
}

u_short tcp_sum_calc(u_short len_tcp_header, u_short * buff, struct libnet_ipv4_hdr *iphdr){
    u_short word16;
    u_int sum = 0;
    u_short i;
    for(i = 0; i < len_tcp_header; i = i+2)
    {
        word16 = ((buff[i]<<8) & 0xFF00)+(buff[i+1] & 0xFF);
        sum = sum + (u_int) word16;
    }
    u_int tempip=ntohl(iphdr->ip_src.s_addr);
    sum+=(tempip>>16)+(tempip&0xffff);
    tempip=ntohl(iphdr->ip_dst.s_addr);
    sum+=(tempip>>16)+(tempip&0xffff);
    sum+=iphdr->ip_p;
    sum+=len_tcp_header;
    while(sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    sum = ~sum;

    return ((u_short) sum);
}

int main()
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    bpf_u_int32 pMask;
    bpf_u_int32 pNet;

    dev = pcap_lookupdev(errbuf);
    printf("\n ---You opted for device [%s] to capture packets---\n\n Starting capture...\n", dev);

    if(dev == NULL){
        printf("\n[%s]\n", errbuf);
        return -1;
    }

    pcap_lookupnet(dev, &pNet, &pMask, errbuf);

    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);

    if(descr == NULL){
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return -1;
    }

    int res;
    struct pcap_pkthdr* pkthdr;
    u_char* datas;
    while(1){
        while((res=pcap_next_ex(descr, &pkthdr, (const u_char**)&datas))>=0){
            if(res==0)
                continue;

            static int count = 1;
            const u_char *data = datas;
            int i, j;

            struct libnet_ethernet_hdr *etherhdr;
            struct libnet_ipv4_hdr *iphdr;
            struct libnet_tcp_hdr *tcphdr;

            u_int8_t iphdr_size;
            u_char *ptr;

            char buf[100];

            etherhdr = (struct libnet_ethernet_hdr*)(data);
            data += sizeof(struct libnet_ethernet_hdr);

            iphdr = (struct libnet_ipv4_hdr*)(data);
            iphdr_size = *(u_int8_t*)iphdr;
            iphdr_size = (iphdr_size & 15) * 4;
            data += iphdr_size;

            tcphdr = (struct libnet_tcp_hdr*)(data);

            data = datas;

            printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);

            if (ntohs(etherhdr->ether_type) == ETHERTYPE_IP){
                if (iphdr->ip_p == IPPROTO_TCP){
                    char phttp[5];
                    for(i = 0; i < pkthdr->len; i++){
                        if(*data == 'H'){
                            strncpy(phttp, (char *)data, 4);
                            phttp[4] = '\0';
                            if(!strcmp(phttp, "HTTP")){
                                printf("HTTP PACKET\n");
                                break;
                            }
                        }
                        data++;
                    }

                    if(!strcmp(phttp, "HTTP")){
                        data=datas;
                        char pget[4];
                        for(i = 0; i < pkthdr->len; i++){
                            if(*data == 'G'){
                                strncpy(pget, (char *)data, 3);
                                pget[3] = '\0';
                                if(!strcmp(pget, "GET")){
                                    u_char packet[100];
                                    u_int seq_backup=tcphdr->th_seq;
                                    u_short iplen_backup=iphdr->ip_len;
                                    printf("%d\n", seq_backup);
                                    tcphdr->th_seq=htonl(ntohl(tcphdr->th_seq)+ntohs(iphdr->ip_len)-40);
                                    tcphdr->th_flags=TH_ACK|TH_FIN;
                                    iphdr->ip_len=htons(0x30);
                                    iphdr->ip_sum=0;
                                    tcphdr->th_sum=0;
                                    memcpy(packet, etherhdr, sizeof(struct libnet_ethernet_hdr));
                                    memcpy(packet+sizeof(struct libnet_ethernet_hdr), iphdr, iphdr_size);
                                    memcpy(packet+sizeof(struct libnet_ethernet_hdr)+iphdr_size, tcphdr, 20);
                                    memcpy(packet+sizeof(struct libnet_ethernet_hdr)+iphdr_size+20, "blocked\0", 8);

                                    u_short ipdata[20];
                                    ptr=(u_char *)iphdr;
                                    for (i = 0; i < 20; i ++)
                                        ipdata[i] = *(u_char*)ptr++;

                                    u_short ipsum=ip_sum_calc(iphdr_size, ipdata);

                                    ptr = (u_char *)(packet+sizeof(struct libnet_ethernet_hdr)+iphdr_size);
                                    u_short tcpdata[ntohs(iphdr->ip_len)-iphdr_size];
                                    for(i=0; i<(ntohs(iphdr->ip_len)-iphdr_size); i++)
                                        tcpdata[i]=*(u_char*)ptr++;
                                    u_short tcpsum=tcp_sum_calc(ntohs(iphdr->ip_len)-iphdr_size, tcpdata, iphdr);

                                    iphdr->ip_sum=htons(ipsum);
                                    tcphdr->th_sum=htons(tcpsum);
                                    memcpy(packet+sizeof(struct libnet_ethernet_hdr), iphdr, iphdr_size);
                                    memcpy(packet+sizeof(struct libnet_ethernet_hdr)+iphdr_size, tcphdr, 20);

                                    if(pcap_sendpacket(descr, packet, sizeof(struct libnet_ethernet_hdr)+iphdr_size+28) != 0){
                                        fprintf(stderr,"\n Error sending the packet: %s\n", pcap_geterr(descr));
                                        exit(-1);
                                    }

                                    u_char ethertmp[ETHER_ADDR_LEN];
                                    for(j=0; j<ETHER_ADDR_LEN; j++){
                                        ethertmp[j]=etherhdr->ether_dhost[j];
                                        etherhdr->ether_dhost[j]=etherhdr->ether_shost[j];
                                        etherhdr->ether_shost[j]=ethertmp[j];
                                    }

                                    struct in_addr ip_tmp;
                                    ip_tmp=iphdr->ip_dst;
                                    iphdr->ip_dst=iphdr->ip_src;
                                    iphdr->ip_src=ip_tmp;

                                    u_short tcptmp;
                                    tcptmp=tcphdr->th_dport;
                                    tcphdr->th_dport=tcphdr->th_sport;
                                    tcphdr->th_sport=tcptmp;

                                    iphdr->ip_sum=0;
                                    tcphdr->th_sum=0;

                                    tcphdr->th_seq=tcphdr->th_ack;
                                    tcphdr->th_ack=htonl(ntohl(seq_backup)+ntohs(iplen_backup)-40);

                                    memcpy(packet, etherhdr, sizeof(struct libnet_ethernet_hdr));
                                    memcpy(packet+sizeof(struct libnet_ethernet_hdr), iphdr, iphdr_size);
                                    memcpy(packet+sizeof(struct libnet_ethernet_hdr)+iphdr_size, tcphdr, 20);
                                    memcpy(packet+sizeof(struct libnet_ethernet_hdr)+iphdr_size+20, "blocked\0", 8);

                                    ptr=(u_char *)iphdr;
                                    for (i = 0; i < 20; i ++)
                                        ipdata[i] = *(u_char*)ptr++;
                                    ipsum=ip_sum_calc(iphdr_size, ipdata);

                                    ptr = (u_char *)(packet+sizeof(struct libnet_ethernet_hdr)+iphdr_size);
                                    for(i=0; i<(ntohs(iphdr->ip_len)-iphdr_size); i++)
                                        tcpdata[i]=*(u_char*)ptr++;
                                    tcpsum=tcp_sum_calc(ntohs(iphdr->ip_len)-iphdr_size, tcpdata, iphdr);

                                    iphdr->ip_sum=htons(ipsum);
                                    tcphdr->th_sum=htons(tcpsum);
                                    memcpy(packet+sizeof(struct libnet_ethernet_hdr), iphdr, iphdr_size);
                                    memcpy(packet+sizeof(struct libnet_ethernet_hdr)+iphdr_size, tcphdr, 20);

                                    if(pcap_sendpacket(descr, packet, sizeof(struct libnet_ethernet_hdr)+iphdr_size+28) != 0){
                                        fprintf(stderr,"\n Error sending the packet: %s\n", pcap_geterr(descr));
                                        exit(-1);
                                    }
                                    break;
                                }
                            }
                            data++;
                        }
                    }

                    printf("Src MAC Address : ");
                    for (int i = 0; i < 6; i++){
                        printf("%02X", etherhdr->ether_shost[i]);
                        if(i == 5)
                            printf("\n");
                        else
                            printf(":");
                    }
                    printf("Dst MAC Address : ");
                    for (int i = 0; i < 6; i++){
                        printf("%02X", etherhdr->ether_dhost[i]);
                        if(i == 5)
                            printf("\n");
                        else
                            printf(":");
                    }

                    inet_ntop(AF_INET, &iphdr->ip_src, buf, sizeof(buf));
                    printf("Src IP Address : %s\n", buf);
                    inet_ntop(AF_INET, &iphdr->ip_dst, buf, sizeof(buf));
                    printf("Dst IP Address : %s\n", buf);
                    printf("Src Port : %d\n", ntohs(tcphdr->th_sport));
                    printf("Dst Port : %d\n", ntohs(tcphdr->th_dport));
                }
                else
                    printf("NOT TCP Packet\n");
            }
            else
                printf("NOT IP Packet\n");

            printf("\n\n");
        }
    }
    return 0;
}
