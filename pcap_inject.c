#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>


struct radiotap_header {
    unsigned char it_version;
    unsigned char it_pad;
    unsigned short it_len;
    unsigned int it_present;
};

struct ieee80211_header {
    unsigned short frame_control;
    unsigned short duration_id;
    unsigned char addr1[6]; 
    unsigned char addr2[6]; 
    unsigned char addr3[6]; 
    unsigned short seq_ctrl;
};

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const unsigned char *packet;

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", argv[1], errbuf);
        return 2;
    }

    struct radiotap_header radiotap_hdr;
    radiotap_hdr.it_version = 0;
    radiotap_hdr.it_pad = 0;
    radiotap_hdr.it_len = 0x08; 
    radiotap_hdr.it_present = 0; 

    struct ieee80211_header wifi_hdr;
    unsigned char payload[] = "Testing packet injection";

    wifi_hdr.frame_control = htons(0x0800); 
    wifi_hdr.duration_id = htons(0x0000); 
    memset(wifi_hdr.addr1, 0xff, 6); 
    memset(wifi_hdr.addr2, 0x11, 6); 
    memset(wifi_hdr.addr3, 0x11, 6); 
    wifi_hdr.seq_ctrl = htons(0x0000); 

    int packet_size = sizeof(struct radiotap_header) + sizeof(struct ieee80211_header) + sizeof(payload);

    unsigned char *complete_packet = (unsigned char *)malloc(packet_size);

    memcpy(complete_packet, &radiotap_hdr, sizeof(struct radiotap_header));
    memcpy(complete_packet + sizeof(struct radiotap_header), &wifi_hdr, sizeof(struct ieee80211_header));
    memcpy(complete_packet + sizeof(struct radiotap_header) + sizeof(struct ieee80211_header), payload, sizeof(payload));

    int ret = pcap_inject(handle, complete_packet, packet_size);
    printf("%d\n", ret);
    
    free(complete_packet);

    pcap_close(handle);

    return 0;
}
