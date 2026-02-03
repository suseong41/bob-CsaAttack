#include <stdio.h>
#include <string>
#include <pcap.h>
#include <unistd.h>
#include "mac.h"
#include "radiotap.h"
#include "wireless.h"

// todo: 비콘 프레임 캡처, 5바이트의 채널 스위치 알림 삽입하여 전송하도록.


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

    ST_MAC ap_mac;
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
        // page 1: beacon frame capture
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

        ST_RDT rdt = capRdt(packet);
        ST_WL wl = capWl(packet+rdt.len);
        uint64_t wlLen = sizeof(wl);
        if (!chkBeacon(&wl)) continue;
        printf("beacon frame captured\n");

        // page 2: insert channel switch announcement

        // page 3: send beacon attack frame

    }

    pcap_close(pcap);

    return 0;
}