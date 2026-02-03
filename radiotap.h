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