#pragma once
#pragma pack(push, 1)
struct ST_WL
{
    uint16_t framControl;
    uint16_t duration_id;
    ST_MAC receiver;
    ST_MAC transmitter;
    ST_MAC bssid;
    uint16_t seqControl;
};
struct ST_BC_COMMON
{
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capacity;
};
#pragma pack(pop)

ST_WL capWl(const u_char* packet);
bool chkBeacon(ST_WL *target);
int getInsertTagLoc(const u_char* beaconTagPacket, int tagTotalLen, int insertTagId);