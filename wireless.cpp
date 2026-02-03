#include <stdio.h>
#include <string>
#include <pcap.h>
#include "mac.h"
#include "wireless.h"

ST_WL capWl(const u_char* packet)
{
    ST_WL *pHdr = (ST_WL*)packet;
    return *pHdr;
}

bool chkBeacon(const ST_WL *target)
{
    // wifi 00, type 00(관리), subtypes 1000(비콘) [리틀엔디안]
    if ((target->framControl & 0x00FF) == 0x80) return true;
    return false;
}