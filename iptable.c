//
//  iptable.c
//  443_NAT
//
//  Created by Mo Mo on 22/4/2019.
//  Copyright © 2019 Mo Mo. All rights reserved.
//

#include "iptable.h"

IPtable* makeIPtable()
{
    IPtable *iptable = (IPtable *)malloc(sizeof(IPtable));
    iptable->head = iptable->tail = NULL;
    return iptable;
}

Entry* makeEntry(Address *original_address, Address *translated_address)
{
    Entry *entry = (Entry *)malloc(sizeof(Entry));
    entry->next = NULL;
    entry->original_address = original_address;
    entry->translated_address = translated_address;
    return entry;
}

void printTable(IPtable *iptable)
{
    printf("Original:%24s%8s | Translated:%24s%8s\n","IP","PORT","IP","PORT");
    Entry *reader = (Entry *)malloc(sizeof(Entry));
    reader = iptable->head;
    while (reader != NULL)
    {
        printf("         %24u%8d |            %24u%8d\n",reader->original_address->ip, reader->original_address->port, reader->translated_address->ip, reader->translated_address->port);
        reader = reader->next;
    }
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
            //Head is the target
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
