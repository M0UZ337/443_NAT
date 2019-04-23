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
unsigned int wan_ip;
unsigned int wan_port;
struct IPtable ip_table;
int port[2001] = {0};


int assign_port(){
    for (int i = 0; i < 2001; i++) {
        if (port[i] == 0) {
            port[i] = 1;
            return i + 10000;
        }
    }
    return -1;
}

static int Callback(struct nfq_q_handle *myQueue, struct nfgenmsg *msg,
                    struct nfq_data *pkt, void *cbData) {

    //nfqueue header
    unsigned int id = 0;
    struct nfqnl_msg_packet_hdr *header;
    assert(header = nfq_get_msg_packet_hdr(pkt));
    id = ntohl(header->packet_id);
    
    //IP header, check the content inside the packet
    unsigned char *pktData;
    int ip_pkt_len = nfq_get_payload(pkt, &pktData);
    
    struct iphdr *iph = (struct iphdr *)pktData;
    
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *)(pktData + (iph->ihl << 2));;
    
    // Subnet Mask
    int mask_int = atoi(subnet_mask);
    unsigned int local_mask = 0xffffffff << (32 – mask_int);
    
    int SYN, RST, FIN, ACK;
    SYN = RST = FIN = ACK = 0;
 
    //check the flag of the tcp header
    unsigned char pkt_flag = tcph->th_flags;
    
    struct Address source_addr;
    source_addr.ip = iph->saddr;
    source_addr.port = tcph->source;
    struct Address dest_addr;
    dest_addr.ip = iph->daddr;
    dest_addr.port = tcp->dest;
    
    if (iph->protocol == IPPROTO_TCP) {
        // TCP packets
        if (ntohl(iph->saddr) & local_mask) == local_network) {
            // outbound packet
            struct Entry *temp = (struct Entry*)malloc(sizeof(struct Entry));
            // search for pair
            temp = searchEntry(source_addr, ip_table);
            if (temp != NULL){
                //found pair
                if (pkt_flag == TH_RST) {
                    // RST packet arrived
                    // delete entry
                    deleteEntry(temp, ip_table);
                    int freePort = temp->original_address->port;
                    port[freePort + 10000] = 0;
                }
                else if (pkt_flag == TH_FIN) {
                    // FIN packet arrived
                    // check if have handshake before
                    
                }
                //start translation
                iph->saddr = temp->translated_address->ip;
                tcp->source = temp->translated_address->port;
                
                iph->check = ip_checksum((unsigned char *) iph);
                tcph->check = tcp_checksum((unsigned char *) iph);
                return nfq_set_verdict(qh, id, NF_ACCEPT, ip_pkt_len, pktData);
            }
            else {
                //can't find pair
                //see if SYN packet
                if (pkt_flag == TH_SYN) {
                    // find avaliable port
                    wan_port = assign_port();
                    // create entry
                    struct Entry *addEntry = (struct Entry*) malloc(sizeof(struct Entry));
                    addEntry->original_address->ip = source_addr.ip;
                    addEntry->original_address->port = source_addr.port;
                    addEntry->translated_address->ip = wan_ip;
                    addEntry->translated_address->port = wan_port;
                    newEntry(addEntry, ip_table);
                    
                    // start translation
                    iph->saddr = htonl(wan_ip);
                    tcph->source = htons(wan_port);
                    
                    iph->check = ip_checksum((unsigned char *) iph);
                    tcph->check = tcp_checksum((unsigned char *) iph);
                    
                    printTable(ip_table);
                    return nfq_set_verdict(qh, id, NF_ACCEPT, ip_pkt_len, pktData);
                }
                else {
                    //drop packet
                    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                }
                
            }
        } else {
            // inbound packet
            result = searchEntry(iph, ip_table);
            if (result != NULL) {
                //translation
                iph->daddr = htonl(result->translated_address->ip);
                tcph->dest = htons(result->translated_address->port);
                
                //Chekcsum
                iph->check = tcp_checksum((unsigned char *) iph);
                tcph->check = ip_checksum((unsigned char *) iph);
                
                if (tcph->rst) {
                    //handle RST packet
                    deleteEntry(result, ip_table);
                    port[
                }
                else {
                    // 4-way hand shake
                }
                return nfq_set_verdict(qh, id, NF_ACCEPT, ip_pkt_len, pktData);
            }
        }
    }
    else {
        // Others, can be ignored
       return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
   
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
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
    inet_aton(public_ip, &wan_ip);
    wan_ip = ntohl(wan_ip);
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
