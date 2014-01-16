/*
 * TraceAnalyze.cpp
 *
 * Created by: Qi Alfred Chen, 1/07/2013
 *
 */
#include "TraceAnalyze.h"

TraceAnalyze::TraceAnalyze(){
    pktcnt=0;
    tcpflows.clear();
    dnsquery.clear();
}


double getTime(struct timeval time) {
    return time.tv_sec+(time.tv_usec/1000000.0);
}

void printIP(struct	in_addr ipaddr){
    u_char ip[4];

}

void TraceAnalyze::setNewInFile(int nv){
    newInFile=nv;
}

void TraceAnalyze::bswapIP(struct ip* ip){
    ip->ip_len=bswap16(ip->ip_len);
    ip->ip_id=bswap16(ip->ip_id);
    ip->ip_off=bswap16(ip->ip_off);
    ip->ip_sum=bswap16(ip->ip_sum);
    ip->ip_src.s_addr=bswap32(ip->ip_src.s_addr);
    ip->ip_dst.s_addr=bswap32(ip->ip_dst.s_addr);
}

void TraceAnalyze::bswapTCP(struct tcphdr* tcphdr){
    tcphdr->source=bswap16(tcphdr->source);
    tcphdr->dest=bswap16(tcphdr->dest);
    tcphdr->window=bswap16(tcphdr->window);
    tcphdr->check=bswap16(tcphdr->check);
    tcphdr->urg_ptr=bswap16(tcphdr->urg_ptr);
    tcphdr->seq=bswap32(tcphdr->seq);
    tcphdr->ack_seq=bswap32(tcphdr->ack_seq);
}

void TraceAnalyze::bswapUDP(struct udphdr* udphdr){
    udphdr->source=bswap16(udphdr->source);
    udphdr->dest=bswap16(udphdr->dest);
    udphdr->len=bswap16(udphdr->len);
    udphdr->check=bswap16(udphdr->check);
}

void TraceAnalyze::bswapDNS(struct DNS_HEADER* dnshdr){
    dnshdr->id=bswap16(dnshdr->id);
    dnshdr->q_count=bswap16(dnshdr->q_count);
    dnshdr->ans_count=bswap16(dnshdr->ans_count);
    dnshdr->auth_count=bswap16(dnshdr->auth_count);
    dnshdr->add_count=bswap16(dnshdr->add_count);
}


void TraceAnalyze::feedTracePacket(Context ctx, const struct pcap_pkthdr *header, const u_char *pkt_data) {
 // cout<<"here1\n";
    pktcnt++;
    if (pktcnt<200){
    cout<<pktcnt<<endl;
    double ts = getTime(header->ts);
 //   printf("Frame ts: %f\n",ts);
 //   printf("Frame caplen: %d bytes\n",header->caplen);
 //   printf("Frame len: %d bytes\n",header->len);
    u_short ethertype=bswap16(*((u_short*)(pkt_data+ctx.getEtherLen()-2)));
    u_char* etherdatap=(u_char*)(pkt_data + ctx.getEtherLen());
    switch (ethertype){
        case 0x0800: {
            //IPv4
        //    printf("Network layer protocol: IPv4\n");

            ip* ip = (struct ip*)(etherdatap);
            bswapIP(ip);
       //     long ipsrc=bswap32(ip->ip_src.s_addr);
       //     printf("IP source address: %d \n",(ip->ip_src.s_addr)&0xFF);
       //     printf("IP header len: %d\n",ip->ip_hl*4);

            switch (ip->ip_p){
                case 0x06: {
                //TCP
                   struct tcphdr* tcphdr=(struct tcphdr*)(etherdatap+ip->ip_hl*4);
                   bswapTCP(tcphdr);

              //     printf("dport: %d \n",tcphdr->dest);

                   int belongsToSomeone=0;
                   for (int i=0;i<tcpflows.size();i++){
                       if (tcpflows[i]->isMyPacket(ip,tcphdr)==1){
                           tcpflows[i]->addPacket(ip,tcphdr,ts);
                           belongsToSomeone=1;
                       }
                   }

                   if (belongsToSomeone==0 && TCPFlowStat::isNewFlow(ip,tcphdr)==1){
                       struct TCPFlowStat* tfs=(TCPFlowStat*) malloc(sizeof(struct TCPFlowStat));
                       tfs->addPacket(ip,tcphdr,ts);
                       tcpflows.push_back(tfs);
                   }





                };break;
                case 0x11: {
                //UDP
                   struct udphdr* udphdr=(struct udphdr*)(etherdatap+ip->ip_hl*4);
                   bswapUDP(udphdr);

                   if (udphdr->dest==0x35 || udphdr->source==0x35){

                       struct DNS_HEADER * dns = (struct DNS_HEADER *)(etherdatap+ip->ip_hl*4+sizeof (struct udphdr));
                       bswapDNS(dns);
                       if (dns->qr == 0){
                           printf("DNS query.\n");

                           if (dns->q_count>0){
                            //   printf("qc: %d.\n",dns->q_count);
                               struct DNSQueryComb* newq=(struct DNSQueryComb*)malloc(sizeof(struct DNSQueryComb));
                               newq->ts=ts;
                               newq->trxid=dns->id;
                               getQueryString((char *)dns+sizeof(struct DNS_HEADER), dns->q_count, newq);
                               dnsquery.push_back(newq);
                           }

                       }
                       if (dns->qr == 1){
                          printf("DNS response.\n");

                          if (dns->q_count>0){
                              struct DNSQueryComb* newq=(struct DNSQueryComb*)malloc(sizeof(struct DNSQueryComb));
                              newq->trxid=dns->id;
                              getQueryString((char *)dns+sizeof(struct DNS_HEADER), dns->q_count, newq);

                              struct DNSQueryComb* newansq=(struct DNSQueryComb*)malloc(sizeof(struct DNSQueryComb));
                              newansq->trxid=dns->id;

                              //resolve previous queries
                              for (int i=0;i<dnsquery.size();i++){
                                  if (newq->trxid == dnsquery[i]->trxid){
                                      if (dnsquery[i]->deleteurl(newq, newansq)==1){
                                          newansq->ts=ts-(dnsquery[i])->ts;
                                          ansdnsquery.push_back(newansq);
                                           printf("%f %f %f\n",dnsquery[i]->ts, ts, newansq->ts);
                                          for (int j=0;j<newansq->urlsnum;j++)
                                            printf("%s\n",newansq->urls[j]);

                                          if (dnsquery[i]->urlsnum==0){
                                            dnsquery.erase(dnsquery.begin()+i);
                                            break;
                                          }

                                      };


                                  }
                              }
                          };


                       };
                   };


                };break;
                default: {
                    printf("Unknown tranportation layer protocol in IP.\n");
                };break;

            }
        };break;
        case 0x86DD: {
            //IPv6
            printf("Network layer protocol: IPv6\n");
        };break;
        default: {
            printf("Unknown network layer protocol in ether.\n");
        };break;
    };

 //   u_char c=*(pkt_data);
 //   printf("Ether Protocol: %d %x %x\n",sizeof(u_char), *(pkt_data),*(pkt_data+1));

    };
}
