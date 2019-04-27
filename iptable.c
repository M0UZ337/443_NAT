//
//  iptable.c
//  443_NAT
//
//  Created by Mo Mo on 22/4/2019.
//  Copyright © 2019 Mo Mo. All rights reserved.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "iptable.h"

IPtable* makeIPtable()
{
    IPtable *iptable = (IPtable *)malloc(sizeof(IPtable));
    memset(iptable,0,sizeof(IPtable));
    iptable->head = iptable->tail = NULL;
    return iptable;
}

Entry* makeEntry(Address *original_address, Address *translated_address)
{
    Entry *entry = (Entry *)malloc(sizeof(Entry));
    memset(entry,0,sizeof(Entry));
    entry->next = NULL;
    entry->original_address = original_address;
    entry->translated_address = translated_address;
    entry->state[0] = 0;
    entry->state[1] = 0;
    return entry;
}

void printTable(IPtable *iptable)
{
    printf("Original:%15s%8s | Translated:%15s%8s\n","IP","PORT","IP","PORT");
    printf("---------------------------------------------------------------------\n");
    Entry *reader = (Entry *)malloc(sizeof(Entry));
    memset(reader,0,sizeof(Entry));
    reader = iptable->head;
    if (reader == NULL)
    {
        printf("---------------------------------------------------------------------\n");
    }
    while (reader != NULL)
    {
        struct in_addr temp;
        temp.s_addr = htonl(reader->original_address->ip);
        printf("         %15s%8d ",(char*)inet_ntoa(temp), reader->original_address->port);
        temp.s_addr = htonl(reader->translated_address->ip);
        printf("|            %15s%8d\n",(char*)inet_ntoa(temp), reader->translated_address->port);
        printf("---------------------------------------------------------------------\n");
        reader = reader->next;
    }
    printf("\n");
    return;
}

void newEntry(Entry *entry, IPtable *iptable)
{
    if (iptable->head == NULL)
    {
        iptable->head = entry;
        iptable->tail = entry;
    }
    else
    {
        iptable->tail->next = entry;
        iptable->tail = entry;
    }
    return;
}

Entry *searchEntry(Address *address, IPtable *iptable, int flag)
{
    Entry *search = (Entry *)malloc(sizeof(Entry));
    search = iptable->head;
    while (search != NULL)
    {
        if (search->translated_address == address && flag == 1)
        {
            break;
        }
        else {
        }
        if (search->original_address == address && flag == 0)
        {
            break;
        }
        search = search->next;
    }
    return search;
}

int deleteEntry(Address *original_address, IPtable *iptable)
{
    int state = 0;
    Entry *prev = (Entry *)malloc(sizeof(Entry));
    Entry *search = (Entry *)malloc(sizeof(Entry));
    prev = NULL;
    search = iptable->head;
    while (search != NULL)
    {
        if (search->original_address == original_address)
        {
            //If the target is head
            if (prev == NULL)
            {
                iptable->head = iptable->head->next;
                state = 1;
                break;
            }
            else
            {
                prev->next = search->next;
                state = 1;
                break;
            }
        }
        prev = search;
        search = search->next;
    }
    return state;
}

// How to use:
// gcc -o iptable iptable.c
// ./iptable 111.111.111.111 12345 222.222.222.222 10086
//////////////////////////////////////////////////////////
/*
int main(int argc, const char * argv[])
{
    IPtable *iptable = makeIPtable();
    char *original_ip = argv[1];
    char *original_port = argv[2];
    char *translated_ip = argv[3];
    char *translated_port = argv[4];
    unsigned int original;
    unsigned int translated;
    inet_aton(original_ip, &original);
    original = ntohl(original);
    inet_aton(translated_ip, &translated);
    translated = ntohl(translated);
    
    Address *ori = (Address *)malloc(sizeof(Address));
    Address *tran = (Address *)malloc(sizeof(Address));
    memset(ori,0,sizeof(Address));
    memset(tran,0,sizeof(Address));
    ori->ip = original;
    ori->port = atoi(original_port);
    tran->ip = translated;
    tran->port = atoi(translated_port);
    Entry *entry = (Entry*)malloc(sizeof(Entry));
    entry = makeEntry(ori, tran);
    newEntry(entry, iptable);
    printTable(iptable);
    Entry *search = (Entry*)malloc(sizeof(Entry));
    search = searchEntry(ori, iptable);
    deleteEntry(ori, iptable);
    printTable(iptable);
    newEntry(search, iptable);
    printTable(iptable);
}
*/
