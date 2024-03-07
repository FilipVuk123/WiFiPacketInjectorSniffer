#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <signal.h>

static volatile int keep_running = 1;

void int_handler(int dummy) {
    keep_running = 0;
}


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
    unsigned char addr1[6];
    unsigned char addr2[6];
    unsigned char addr3[6];
    unsigned short seq_ctrl;
};

size_t bytes_received = 0;

void packet_handler(const unsigned char *packet, int packet_len)
{
    bytes_received += packet_len;
    struct radiotap_header *radiotap_hdr = (struct radiotap_header *)packet;
    struct ieee80211_header *wifi_hdr = (struct ieee80211_header *)(packet + radiotap_hdr->it_len);
    if (packet_len == 1516){
    printf("Packet size: %d\n", packet_len);

    printf("==============================================\n");
    printf("Received packet:\n");
    printf("Frame Control: 0x%04x\n", ntohs(wifi_hdr->frame_control));
    printf("Duration ID: %d\n", ntohs(wifi_hdr->duration_id));
    printf("Address 1: %02x:%02x:%02x:%02x:%02x:%02x\n", wifi_hdr->addr1[0], wifi_hdr->addr1[1], wifi_hdr->addr1[2], wifi_hdr->addr1[3], wifi_hdr->addr1[4], wifi_hdr->addr1[5]);
    printf("Address 2: %02x:%02x:%02x:%02x:%02x:%02x\n", wifi_hdr->addr2[0], wifi_hdr->addr2[1], wifi_hdr->addr2[2], wifi_hdr->addr2[3], wifi_hdr->addr2[4], wifi_hdr->addr2[5]);
    printf("Address 3: %02x:%02x:%02x:%02x:%02x:%02x\n", wifi_hdr->addr3[0], wifi_hdr->addr3[1], wifi_hdr->addr3[2], wifi_hdr->addr3[3], wifi_hdr->addr3[4], wifi_hdr->addr3[5]);
    printf("Sequence Control: 0x%04x\n", ntohs(wifi_hdr->seq_ctrl));
    printf("radiotap_hdr->it_len: %d\n", radiotap_hdr->it_len);
    printf("sizeof(struct ieee80211_header): %d\n", sizeof(struct ieee80211_header));
    int payload_start = radiotap_hdr->it_len + sizeof(struct ieee80211_header);
    int payload_size = packet_len - payload_start;
    
    printf("Payload start: %d\n", payload_start);
    printf("Payload size: %d\n", payload_size);
    
    printf("\n\n");
    printf("Payload at start: \n");
    for (int i = payload_start; i < payload_start + 20; i++){
        printf("%c", packet[i]);
    }

    printf("\n");
    printf("Payload at end: \n");
    for (int i = payload_size - 20; i < packet_len; i++){
        printf("%c", packet[i]);
    }

    printf("\n");
    printf("==============================================\n");
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    signal(SIGINT, int_handler);

    int sockfd;
    struct sockaddr_ll sll;
    char buffer[BUFSIZ];

    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0)
    {
        perror("socket");
        return 1;
    }

    // Bind socket to interface
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(argv[1]);

    if (sll.sll_ifindex == 0)
    {
        perror("if_nametoindex");
        return 1;
    }

    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        perror("bind");
        return 1;
    }

    printf("Listening on %s...\n", argv[1]);

    while (keep_running)
    {
        int recv_len = recv(sockfd, buffer, BUFSIZ, 0);
        if (recv_len < 0)
        {
            perror("recv");
            return 1;
        }

        packet_handler((unsigned char *)buffer, recv_len);
    }

    close(sockfd);

    printf("Total bytes received: %zu\n", bytes_received);

    return 0;
}
