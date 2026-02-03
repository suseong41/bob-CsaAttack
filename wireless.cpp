#include <stdio.h>
#include <string>
#include <pcap.h>
#include <vector>
#include "mac.h"
#include "wireless.h"



ST_WL capWl(const u_char* packet)
{
    ST_WL *pHdr = (ST_WL*)packet;
    return *pHdr;
}

bool chkBeacon(ST_WL *target)
{
    // wifi 00, type 00(관리), subtypes 1000(비콘) [리틀엔디안]
    if ((target->framControl & 0x00FF) == 0x80) return true;
    return false;
}

int getInsertTagLoc(const u_char* beaconTagPacket, int tagTotalLen, int insertTagId)
{
    const u_char* index = beaconTagPacket;
    const u_char* end = index + tagTotalLen;
    int prev = -1;
    int currentLoc = 0;
    int insertLoc = 0;

    while (index + 2 < end)
    {
        uint8_t tagId = index[0];
        uint8_t tagLen = index[1];
        int totalTagLen = (2 + tagLen);
        if (end < index + 2 + tagLen) break;
        if (tagId < insertTagId && prev < tagId)
        {
            prev = tagId;
            insertLoc = currentLoc + totalTagLen;
        }
        index += totalTagLen;
        currentLoc += totalTagLen;
    }

    return insertLoc;
}







/* 구조가 안예뻐서 폐기..
// 반환: 37과 가까운 태그에 id와 위치 정보
// prev만 사용하면 편할 것 같은데, 수업때 앞, 뒤 태그를 구해봐서 이렇게 해봤습니다.
std::vector<std::pair<int, int>> getNearTag(const u_char* beaconTagPacket, int tagTotalLen)
{
    // 태그 id, tag 위치
    std::vector<std::pair<uint8_t, int>> tags;

    const u_char* index = beaconTagPacket;
    const u_char* end = index + tagTotalLen;
    int tagEndLoc = 0; // tag가 끝나는 위치

    while (index + 2 < end)
    {
        uint8_t tagId = index[0];
        uint8_t tagLen = index[1];
        if (end < index + 2 + tagLen) break;
        const u_char* data = (index + 2);
        tagEndLoc += (2 + tagLen);
        tags.emplace_back(tagId, tagEndLoc);
        index += (2 + tagLen);

    }

    std::vector<std::pair<int, int>> nearTag;
    int prev = NO_PREV;
    int prevEndLoc = 0;
    int next = NO_NEXT;
    int nextEndLoc = 0;
    for (uint64_t i=0; i<tags.size(); i++)
    {
        int tagId = tags[i].first;
        if (tagId < 37 && prev < tagId )
        {
            prev = tagId;
            prevEndLoc = tags[i].second;
        }
        if (37 < tagId && tagId < next)
        {
            next = tagId;
            nextEndLoc = tags[i].second;
        }
    }
    if (prev == NO_PREV)
    {
        nearTag.emplace_back(NO_PREV,NO_PREV);
        nearTag.emplace_back(next,nextEndLoc);
    }
    else if (next == NO_NEXT)
    {
        nearTag.emplace_back(prev,prevEndLoc);
        nearTag.emplace_back(NO_NEXT, NO_NEXT);
    }
    else
    {
    nearTag.emplace_back(prev,prevEndLoc);
    nearTag.emplace_back(next,nextEndLoc);
    }
    // 이걸 꺼내서 37보다 작거나 큰지 검증 후 사용.

    return nearTag;
}
*/