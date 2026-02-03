#include <stdio.h>
#include <pcap.h>
#include "radiotap.h"

// https://www.radiotap.org 비트로 관리
// https://www.radiotap.org/fields/defined 에서 present를 빡세게 분석해봐야함..
// 문서상 31번째 비트(MSB)가 켜지면 다음 it_present가 있고, 꺼지면 이제 데이터가 옴 -> 0x80000000 비트마스크

// https://www.radiotap.org/fields/Flags.html flags 데이터가 0x10이면 fcs가 있다.
// 28, 29 namespace로 3번째가 나오는 것 같은데 뭐지..
// 일단 첫 번째 present에서 1번 TSFT 있는지 보고, 2번 flags를 보자.
static bool hasNextPresent(uint32_t present)
{
    if ((present & 0x80000000) != 0)
    {
        return true;
    }
    return false;
}

ST_RDT capRdt(const u_char* packet)
{
    ST_RDT *pHdr = (ST_RDT*)packet;
    //printf("len = %d -> ", pHdr->len);
    return *pHdr;
}

int isPresentCount(const u_char* packet)
{
    int count = 0;
    uint32_t* presentPtr = (uint32_t*)(packet+4);
    while (true)
    {
        uint32_t present = *presentPtr;
        count ++;
        if(hasNextPresent(present))
        {
            presentPtr++;
        }
        else break;
    }
    return count;
}
// 메모리 정렬은 규격의 배수로 정해짐..
bool hasFcs(const u_char* packet, const ST_RDT *rdt, int presentCount)
{
    uint32_t present = rdt->present;
    const u_char* data = (packet+4+4*presentCount);
    int alignment = 0;
    if ((present & 0x00000001) != 0)
    {
        if ((presentCount%2) == 0) alignment = 4;
        //uint64_t mactime = (uint64_t)*(data+alignment); // 8바이트단위 아니면 정렬 필요.
        if ((present & 0x00000002) != 0)
        {
            uint8_t flags = *(data+8+alignment);
            if ((flags & 0x10) != 0) return true;
        }
    }
    else
    {
        if ((present & 0x00000002) != 0)
        {
            uint8_t flags = *data;
            if ((flags & 0x10) != 0) return true;
        }
    }

    return false;
}