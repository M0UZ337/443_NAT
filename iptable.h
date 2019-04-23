//
//  iptable.h
//  443_NAT
//
//  Created by Mo Mo on 22/4/2019.
//  Copyright © 2019 Mo Mo. All rights reserved.
//

#ifndef iptable_h
#define iptable_h

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>


//Structure List

typedef struct Address Address;
typedef struct Entry Entry;
typedef struct IPtable IPtable;

struct Address
{
    uint32_t ip;
    uint16_t port;
};

struct Entry
{
    Entry *next;
    Address *original_address;
    Address *translated_address;
};

struct IPtable
{
    Entry *head;
    Entry *tail;
};


//Function List

//Make IPtable
IPtable* makeIPtable();
//Make Entry
Entry* makeEntry(Address *original_address, Address *translated_address);
//Print the iptable, from head to tail
void printTable(IPtable *iptable);
//Translate the Address first and pass into the function
void newEntry(Entry *entry, IPtable *iptable);
//Search the corisponding Entry from iptable
Entry *searchEntry(Address *original_address, IPtable *iptable);
//Delete the Entry by searching it using original address (return 0 if fail/ 1 if success)
int deleteEntry(Address *original_address, IPtable *iptable);

#endif /* iptable_h */
