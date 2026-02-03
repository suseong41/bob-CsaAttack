#pragma once
#pragma pack(push, 1)
struct ST_WL
{
    uint16_t framControl;
    uint16_t duration_id;
    ST_MAC da;
    ST_MAC sa;
    ST_MAC bssid;
    uint16_t seqControl;
};
#pragma pack(pop)

ST_WL capWl(const u_char* packet);
bool chkBeacon(const ST_WL *target);