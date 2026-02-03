#pragma once
#pragma pack(push, 1)
struct ST_RDT
{
    uint8_t version;
    uint8_t padding;
    uint16_t len;
    uint32_t present;
};
#pragma pack(pop)

ST_RDT capRdt(const u_char* packet);
int isPresentCount(const u_char* packet);
bool hasFcs(const u_char* packet, const ST_RDT *rdt, int presentCount);