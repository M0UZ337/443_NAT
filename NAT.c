#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h> // required by "netfilter.h"
#include <arpa/inet.h> // required by ntoh[s|l]()
#include <signal.h> // required by SIGINT
#include <string.h> // required by strerror()
#include <sys/time.h> // required by gettimeofday()
#include <time.h> // required by nanosleep()
#include <errno.h> // required by errno
#include <pthread.h>
#include <netinet/ip.h>        // required by "struct iph"
#include <netinet/tcp.h>    // required by "struct tcph"
#include <netinet/udp.h>    // required by "struct udph"
#include <netinet/ip_icmp.h>    // required by "struct icmphdr"
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "NAT.h"

#include "checksum.h"

static int Callback(struct nfq_q_handle *myQueue, struct nfgenmsg *msg,
                    struct nfq_data *pkt, void *cbData) {

    //nfqueue header
    unsigned int id = 0;
    struct nfqnl_msg_packet_hdr *header;
    assert(header = nfq_get_msg_packet_hdr(pkt));
    id = ntohl(header->packet_id);
    
    //IP header
    unsigned char *pktData;
    int ip_pkt_len = nfq_get_payload(pkt, &pktData);
    
    struct iphdr *iph = (struct iphdr *)pktData;
    
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *);
    
    // Subnet Mask
    int mask_int = atoi(subnet_mask);
    unsigned int local_mask = 0xffffffff << (32 – mask_int);
    
    
    if (iph->protocol == IPPROTO_TCP) {
        // TCP packets
        if (ntohl(iph->saddr) & local_mask) == local_network) {
            // outbound packet
        } else {
            // inbound packet
    
            
        }
    } else {
        // Others, can be ignored
        printf("Non-TCP.");
    }
   
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, const char * argv[])
{
    // Get a queue connection handle from the module
    struct nfq_handle *nfqHandle;
    struct nfq_q_handle *nfQueue;
    struct nfnl_handle *netlinkHandle;
    int fd, res;
    int BUF_SIZE = 4096;
    char buf[BUF_SIZE];
    
    if (!(nfqHandle = nfq_open())) {
        fprintf(stderr, "Error in nfq_open()\n");
        exit(-1);
    }
    
    // Unbind the handler from processing any IP packets
    if (nfq_unbind_pf(nfqHandle, AF_INET) < 0) {
        fprintf(stderr, "Error in nfq_unbind_pf()\n");
        exit(1);
    }
    
    // Bind the handler from processing any IP packets
    if (nfq_bind_pf(nfqHandle, AF_INET) < 0) {
        fprintf(stderr, "Error in nfq_bind_pf()\n");
        exit(1);
    }
    
    // Install a callback on queue 0
    if (!(nfQueue = nfq_create_queue(nfqHandle,  0, &Callback, NULL))) {
        fprintf(stderr, "Error in nfq_create_queue()\n");
        exit(1);
    }
    // nfq_set_mode: I want the entire packet
    if(nfq_set_mode(nfQueue, NFQNL_COPY_PACKET, BUF_SIZE) < 0) {
        fprintf(stderr, "Error in nfq_set_mode()\n");
        exit(1);
    }
    
    netlinkHandle = nfq_nfnlh(nfqHandle);
    
    fd = nfnl_fd(netlinkHandle);
    
    while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
        nfq_handle_packet(nfqHandle, buf, res);
    }
    
    nfq_destroy_queue(nfQueue);
    nfq_close(nfqHandle);
    return 0;
}
