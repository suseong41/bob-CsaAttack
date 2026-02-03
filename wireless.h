#pragma once
#pragma pack(push, 1)
struct ST_WL
{
    uint16_t framControl;
    uint16_t duration_id;
    uint8_t da[6];
    uint8_t sa[6];
    uint8_t bssid[6];
    uint16_t seqControl;
};
#pragma pack(pop)

ST_WL capWl(const u_char* packet);
bool chkBeacon(ST_WL *target);