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
#include <netinet/in.h>
#include <netinet/ip.h>        // required by "struct iph"
#include <netinet/tcp.h>    // required by "struct tcph"
#include <netinet/ip_icmp.h>    // required by "struct icmphdr"
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "NAT.h"

#include "checksum.h"

char *subnet_mask;
char *internal_ip;
char *public_ip;
struct IPtable ip_table;

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
    unsigned int local_mask = 0xffffffff << (32 - mask_int);
    struct nfqnl_msg_packet_hdr *nfq_header;
    nfq_header = nfq_get_msg_packet_hdr(pkt);
    unsigned int SYN, RST, FIN, ACK;
    //check the content inside the packet
    char *payload_ptr;
    nfq_get_payload(pkt, payload_ptr);
    
    struct iphdr *iph = (struct iphdr*) payload_ptr;
    
    iph->protocol;
    if (iph->protocol != IPPROTO_TCP) {
        //drop packet
        
    }
    iph->check;
    
    
    struct tcphdr *tcph = (struct tcphdr*)(payload_ptr + iph->hl << 2);
 
    //check the flag of the tcp header
    SYN = tcph->syn;
    ACK = tcph->ack;
    FIN = tcph->fin;
    RST = tcph->rst;
    
    struct Address source_addr;
    source_addr.ip = iph->saddr;
    source_addr.port = tcph->source;
    struct Address dest_addr;
    dest_addr.ip = iph->daddr;
    dest_addr.port = tcp->dest;
    
    
    if (ntohl(iph->saddr) & local_mask) == local_network) {
        // outbound packet
		int found_entry = 0;
		// search for pair
        searchEntry(source_addr, ip_table);
		if (found_entry){
            //found pair
            //translates IP address and source port number
		}
		else {
			//can't find pair
            //see if SYN packet
            if (SYN) {
                // crete entry
            }
            else {
                //drop packet
                
            }

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
    
    if (argc != 4) {
        printf("Wrong no. of argument\n");
        exit(1);
    }
    
    public_ip = argv[1];
    internal_ip = argv[2];
    subnet_mask = argv[3];
    ip_table = makeIPtable();
    
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
