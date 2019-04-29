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
#include <assert.h>
#include "iptable.h"
#include "checksum.h"

char *subnet_mask;
char *internal_ip;
char *public_ip;
unsigned int host_ip;
unsigned int nat_port;
struct IPtable *ip_table;
unsigned int local_mask;
int port[2001] = {0};
uint32_t local_network;


int assign_port(){
    int i;
    for (i = 0; i < 2001; i++) {
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
    struct tcphdr *tcph = (struct tcphdr *)(pktData + (iph->ihl << 2));
    
    int SYN, RST, FIN, ACK;
    SYN = RST = FIN = ACK = 0;
 
    //check the flag of the tcp header
    unsigned char pkt_flag = tcph->th_flags;
    printf("flag of pkt: %u\n", pkt_flag);
    
    struct Address source_addr;
    source_addr.ip = ntohl(iph->saddr);
    source_addr.port = ntohs(tcph->source);
    struct Address dest_addr;
    dest_addr.ip = ntohl(iph->daddr);
    dest_addr.port = ntohs(tcph->dest);
    
    
    

    
    if (iph->protocol == IPPROTO_TCP) {
        // TCP packets
        if ((ntohl(iph->saddr) & local_mask) == local_network) {
            // outbound packet
            printf("outbound\n");
            struct Entry *temp = (struct Entry*)malloc(sizeof(struct Entry));
            // search for pair
            temp = searchEntry(&source_addr, ip_table, 0);

            if (temp != NULL){
                //found pair
                printf("found entry\n");
                if (pkt_flag == TH_RST) {
                    printf("RST pkt\n");
                    // RST packet arrived
                    // delete entry
                    deleteEntry(temp->original_address, ip_table);
                    int freePort = temp->translated_address->port;
                    port[freePort + 10000] = 0;
                    printTable(ip_table);
                }
                else if (pkt_flag == TH_FIN) {
                    printf("FIN pkt\n");
                    // FIN packet arrived
                    // check if have handshake before
                    if (temp->state[0] == 2) {
                        // have receive FIN before, we are going to reply with FIN
                        temp->state[1] = 1;
                    }
                    else {
                        temp->state[1] = 2;
                    }
                }
                else if (pkt_flag == TH_ACK) {
                    printf("ACK pkt\n");
                    printTable(ip_table);                    
                    if (temp->state[0] == 1 && temp->state[1] == 2) {
                        deleteEntry(temp->original_address, ip_table);
                        int freePort = temp->original_address->port;
                        port[freePort + 10000] = 0;
                        printTable(ip_table);
                    }
                }
                else if (pkt_flag == TH_ACK + TH_FIN) {
                    printf("FIN + ACK pkt\n");
                    // FIN packet arrived
                    // check if have handshake before
                    if (temp->state[0] == 2) {
                        // have receive FIN before, we are going to reply with FIN
                        temp->state[1] = 1;
                    }
                    else {
                        temp->state[1] = 2;
                    }
                    printf("Current state is : %d %d", temp->state[0], temp->state[1]);
                }
                //start translation
                iph->saddr = htonl(temp->translated_address->ip);
                tcph->source = htons(temp->translated_address->port);
                
                tcph->check = 0;
                iph->check = 0;
                tcph->check = tcp_checksum((unsigned char *) iph);
                iph->check = ip_checksum((unsigned char *) iph);

                return nfq_set_verdict(myQueue, id, NF_ACCEPT, ip_pkt_len, pktData);
            }
            else {
                //can't find pair
                //see if SYN packet
                if (pkt_flag == TH_SYN) {
                    printf("new entry+SYN packet\n");
                    // find avaliable port
                    nat_port = assign_port();
                    // create entry
                    printf("adding new entry: %d\n", source_addr.ip);
                    struct Entry *addEntry = (struct Entry*) malloc(sizeof(struct Entry));
                    struct Address *taddr = (struct Address*) malloc(sizeof(struct Address));
                    taddr->ip = host_ip;
                    taddr->port = nat_port;
                    struct Address *syn_temp = (struct Address*) malloc(sizeof(struct Address));
                    syn_temp->ip = source_addr.ip;
                    syn_temp->port = source_addr.port;
                    newEntry(makeEntry(syn_temp, taddr), ip_table);
                    /*
                    addEntry->original_address->ip = 123;
                    printf("adding new entry2\n");
                    addEntry->original_address->port = source_addr.port;
                    printf("adding new entry3\n");
                    addEntry->translated_address->ip = host_ip;
                    addEntry->translated_address->port = nat_port; */
                    //newEntry(addEntry, ip_table);
                    // update packet
                    iph->saddr = htonl(host_ip);
                    tcph->source = htons(nat_port);
                    iph->check = ip_checksum((unsigned char *) iph);
                    tcph->check = tcp_checksum((unsigned char *) iph);
                    
                    printTable(ip_table);
                    return nfq_set_verdict(myQueue, id, NF_ACCEPT, ip_pkt_len, pktData);
                }
                else {
                    //drop packet
                    printf("NOT SYN: drop packet\n");
                    return nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);
                }
            }
        }
        else {
            // inbound packet
            printf("inbound\n");
            struct Entry *result = (struct Entry*)malloc(sizeof(struct Entry));
            result = searchEntry(&dest_addr, ip_table, 1);
            if (result != NULL) {
                printf("found entry\n");
                printf("show the result port: %8d\n", result->original_address->port);
                //translation
                iph->daddr = htonl(result->original_address->ip);
                tcph->dest = htons(result->original_address->port);
                
                struct in_addr temp;
                temp.s_addr = iph->daddr;
                printf("testing:   %15s%8d ",(char*)inet_ntoa(temp),  ntohs(tcph->dest));
                //Checksum
                tcph->check = 0;
                iph->check = 0;
                
                tcph->check = tcp_checksum((unsigned char *) iph);
                iph->check = ip_checksum((unsigned char *) iph);
                
                printf("showing checksum:   ");
                show_checksum(pktData, 1);
                
                /*
                //print result
                printTable(ip_table);
                struct in_addr temp;
                printf("verify address\n");
                temp.s_addr = htonl(result->original_address->ip);
                printf("         %15s%8d ",(char*)inet_ntoa(temp), source_addr.port);
                temp.s_addr = htonl(result->translated_address->ip);
                printf("|        %15s%8d ",(char*)inet_ntoa(temp), source_addr.port);
                temp.s_addr = htonl(source_addr.ip);
                printf("|        %15s%8d ",(char*)inet_ntoa(temp), source_addr.port);
                temp.s_addr = htonl(iph->daddr);
                printf("|         %15s%8d\n",(char*)inet_ntoa(temp), dest_addr.port);
                */
                
                if (pkt_flag == TH_RST) {
                    printf("RST pkt\n");
                    //handle RST packet
                    deleteEntry(result->original_address, ip_table);
                    port[result->translated_address->port-10000] = 0;
                    printTable(ip_table);
                }
                else {
                    // 4-way hand shake
                    if (pkt_flag == TH_FIN) {
                        // FIN packet
                        printf("FIN pkt\n");
                        if (result->state[1] == 2) {
                            result->state[0] = 1;
                        }
                        else {
                            result->state[0] = 2;
                        }
                    }
                    else if (pkt_flag == TH_ACK) {
                        // ACK packet
                        printf("ACK pkt\n");
                        if (result->state[0] == 2 && result->state[1] == 1) {
                            deleteEntry(result->original_address, ip_table);
                            int freeport = result->translated_address->port;
                            port[10000+ freeport] = 0;
                            printTable(ip_table);
                        }
                    }
                    else if (pkt_flag == TH_FIN + TH_ACK){
                        printf("FIN + ACK!!!\n");
                        if (result->state[1] == 2) {
                            result->state[0] = 1;
                        }
                        else {
                            result->state[0] = 2;
                        }
                        printf("Current state is : %d %d", result->state[0], result->state[1]);
                    }
                }
                return nfq_set_verdict(myQueue, id, NF_ACCEPT, ip_pkt_len, pktData);
            }
            else {
                printf("not entry found, dropping packet\n");
                return nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);
            }
        }
    }
    else {
        // Others, can be ignored
        return nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);
    }
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
    int test;
    public_ip = argv[1];
    inet_aton(public_ip, &host_ip);
    host_ip = ntohl(host_ip);
    internal_ip = argv[2];
    struct in_addr temp;
    inet_aton(internal_ip, &temp);
    subnet_mask = argv[3];
    int mask_int = atoi(subnet_mask);
    local_mask = 0xffffffff << (32 - mask_int);
    local_network = ntohl(temp.s_addr) & local_mask;
    ip_table = makeIPtable();
    
    if (!(nfqHandle = nfq_open())) {
        fprintf(stderr, "Error in nfq_open()\n");
        exit(-1);
    }
    
    // Unbind the handler from processing any IP packets
    if ((test = nfq_unbind_pf(nfqHandle, AF_INET)) < 0) {
        printf("Error code: %d\n", test);
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
    
 //   netlinkHandle = nfq_nfnlh(nfqHandle);
    
    fd = nfq_fd(nfqHandle);
    
    while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0) {
        printf("Handle packet\n");
        nfq_handle_packet(nfqHandle, buf, res);
    }
    
    nfq_destroy_queue(nfQueue);
    nfq_close(nfqHandle);
    return 0;
}
