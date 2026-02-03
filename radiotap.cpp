#include <stdio.h>
#include <pcap.h>
#include "radiotap.h"

// https://www.radiotap.org
ST_RDT capRdt(const u_char* packet)
{
    ST_RDT *pHdr = (ST_RDT*)packet;
    //printf("len = %d -> ", pHdr->len);
    return *pHdr;
}