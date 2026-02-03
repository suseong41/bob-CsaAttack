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
    /*
        printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
        ap_mac.mac[0], ap_mac.mac[1], ap_mac.mac[2],
        ap_mac.mac[3], ap_mac.mac[4], ap_mac.mac[5]);
    */
    ST_MAC st_mac = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

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
        if (hasFcs(packet, &rdt, presentCount))
        {
            //printf("FCS Found\n");
            caplen = caplen - 4;
        }

        // phase 2: insert channel switch announcement
        // 패킷을 추가해가면 어떨까?

        // phase 3: send beacon attack frame

    }

    pcap_close(pcap);

    return 0;
}