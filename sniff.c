#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <signal.h>

#define ETHER_ADDR_LEN 6

struct radiotap_header
{
    unsigned char it_version;
    unsigned char it_pad;
    unsigned short it_len;
    unsigned int it_present;
};

struct ieee80211_header
{
    unsigned short frame_control;
    unsigned short duration_id;
    unsigned char addr1[ETHER_ADDR_LEN];
    unsigned char addr2[ETHER_ADDR_LEN];
    unsigned char addr3[ETHER_ADDR_LEN];
    unsigned short seq_ctrl;
};

pcap_t *handle_global = NULL;

void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    struct radiotap_header *radiotap_hdr = (struct radiotap_header *)packet;
    struct ieee80211_header *wifi_hdr = (struct ieee80211_header *)(packet + radiotap_hdr->it_len);

    printf("Received packet:\n");
    printf("Frame Control: 0x%04x\n", ntohs(wifi_hdr->frame_control));
    printf("Duration ID: %d\n", ntohs(wifi_hdr->duration_id));
    printf("Address 1: %02x:%02x:%02x:%02x:%02x:%02x\n", wifi_hdr->addr1[0], wifi_hdr->addr1[1], wifi_hdr->addr1[2], wifi_hdr->addr1[3], wifi_hdr->addr1[4], wifi_hdr->addr1[5]);
    printf("Address 2: %02x:%02x:%02x:%02x:%02x:%02x\n", wifi_hdr->addr2[0], wifi_hdr->addr2[1], wifi_hdr->addr2[2], wifi_hdr->addr2[3], wifi_hdr->addr2[4], wifi_hdr->addr2[5]);
    printf("Address 3: %02x:%02x:%02x:%02x:%02x:%02x\n", wifi_hdr->addr3[0], wifi_hdr->addr3[1], wifi_hdr->addr3[2], wifi_hdr->addr3[3], wifi_hdr->addr3[4], wifi_hdr->addr3[5]);
    printf("Sequence Control: 0x%04x\n", ntohs(wifi_hdr->seq_ctrl));
    
    int payload_start = radiotap_hdr->it_len + sizeof(struct ieee80211_header);
    int payload_size = pkthdr->caplen - payload_start;
    printf("Payload start: %d\n", payload_start);
    printf("Payload size: %d\n", payload_size);
    printf("Packet size: %d\n", pkthdr->caplen);
}

void handle_sigint(int sig)
{
    if (handle_global != NULL)
    {
        printf("Stopping pcap_loop \n");
        pcap_breakloop(handle_global);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open device %s: %s\n", argv[1], errbuf);
        return 2;
    }

    handle_global = handle;

    struct bpf_program fp;
    char filter_exp[] = "ether src host 11:11:11:11:11:11 or ether dst host 11:11:11:11:11:11";
    bpf_u_int32 net;

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    printf("Listening on %s...\n", argv[1]);

    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = handle_sigint;
    sigaction(SIGINT, &act, NULL);

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}
