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

char *subnet_mask;
char *internal_ip;
char *public_ip;

static int Callback(struct nfq_q_handle *myQueue, struct nfgenmsg *msg,
                    struct nfq_data *pkt, void *cbData) {
    
    int mask_int = atoi(subnet_mask);
    unsigned int local_mask = 0xffffffff << (32 - mask_int);
    struct nfqnl_msg_packet_hdr *nfq_header;
    nfq_header = nfq_get_msg_packet_hdr(pkt);
    
    char *payload_ptr;
    nfq_get_payload(pkt, payload_ptr);
    
    struct iphdr *iph = (struct iphdr*) payload_ptr;
    
    struct tcphdr *tcph = (struct tcphdr*)(payload_ptr-sizeof(struct iphdr));
    int SYN = 0;
    int RST = 0;
    
    
    //check the content inside the packet
    
    
    if (ntohl(iph->saddr) & local_mask) == local_network) {
        // outbound packet
		int found_entry = 0;
		// search for pair
		if (found_entry){

		}
		else {
			//create new entry

		}

    } else {
        // inbound packet
        
    }
    return 0;
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
