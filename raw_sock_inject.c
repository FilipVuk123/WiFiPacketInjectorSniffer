#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <openssl/rand.h>

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

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    int sockfd;
    struct sockaddr_ll sll;
    char *interface = argv[1];

    // Create raw socket
    sockfd = socket(AF_PACKET, SOCK_RAW, 0); 
    if (sockfd < 0)
    {
        perror("socket");
        return 1;
    }

    // Retrieve interface index
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
    {
        perror("ioctl");
        return 1;
    }

    // Bind socket to interface
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_idx.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        perror("bind");
        return 1;
    }

    // Prepare packet headers
    struct radiotap_header radiotap_hdr;
    radiotap_hdr.it_version = 0;
    radiotap_hdr.it_pad = 0;
    radiotap_hdr.it_len = 0x08;
    radiotap_hdr.it_present = 0;

    struct ieee80211_header wifi_hdr;
    wifi_hdr.frame_control = htons(0x0800);
    wifi_hdr.duration_id = htons(0x0000);
    memset(wifi_hdr.addr1, 0xff, 6); // Destination address set to broadcast
    memset(wifi_hdr.addr2, 0x11, 6);
    memset(wifi_hdr.addr3, 0x11, 6);
    wifi_hdr.seq_ctrl = htons(0x0000);

    // Prepare packet data
    int buffer_size = 1450;
    char *bufferToSend = malloc(buffer_size);
    char *str_to_append = "TestingTestingTesting";
    int str_to_append_len = strlen(str_to_append);
    int packet_size = sizeof(struct radiotap_header) + sizeof(struct ieee80211_header) + buffer_size;
    unsigned char *complete_packet = (unsigned char *)malloc(packet_size);

    // Construct packet
    if (RAND_poll() != 1)
    {
        printf("RAND_poll");
        return 1;
    }
    if (RAND_bytes(bufferToSend, buffer_size) != 1)
    {
        printf("RAND_bytes");
        return 1;
    }
    strncpy(bufferToSend + (buffer_size - str_to_append_len), str_to_append, str_to_append_len);
    strncpy(bufferToSend, str_to_append, str_to_append_len);

    memcpy(complete_packet, &radiotap_hdr, sizeof(struct radiotap_header));
    memcpy(complete_packet + sizeof(struct radiotap_header), &wifi_hdr, sizeof(struct ieee80211_header));
    memcpy(complete_packet + sizeof(struct radiotap_header) + sizeof(struct ieee80211_header), bufferToSend, buffer_size);

    // Send packet
    int ret = write(sockfd, complete_packet, packet_size);
    if (ret < 0)
    {
        perror("write");
        return 1;
    }
    
    printf("Packet sent successfully\n");

    // Cleanup
    free(complete_packet);
    free(bufferToSend);
    close(sockfd);

    return 0;
}
