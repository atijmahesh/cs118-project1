#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <cstdlib>
#include <ctime>
#include "consts.h"

using namespace std;

// Main function of transport layer; never quits
void listen_loop(int sockfd, struct sockaddr_in* addr, int type, ssize_t (*input_p)(uint8_t*, size_t), void (*output_p)(uint8_t*, size_t)) {
    uint8_t buffer[BUF_SIZE] = {0};
    packet* pkt = reinterpret_cast<packet*>(buffer);
    socklen_t addr_len = sizeof(struct sockaddr_in);
    size_t payload_size = 0;

    if (type == CLIENT) {
        // step 1: client sends SYN packet
        uint16_t client_seq = (rand() % 1000) + 1;
        pkt->seq = htons(client_seq);
        pkt->ack = 0;

        // read payload data (if available)
        payload_size = input_p(pkt->payload, MAX_PAYLOAD); // `input_io` populates `payload` field
        pkt->length = htons(payload_size);

        pkt->win = htons(MIN_WINDOW);
        pkt->flags = SYN | set_parity(pkt);
        pkt->unused = 0;

        // send SYN packet to server (client is blocked until it receives SYN-ACK)
        sendto(sockfd, pkt, sizeof(packet) + payload_size, 0, (struct sockaddr*) addr, addr_len);
        print_diag(pkt, SEND);

    } else if (type == SERVER) {

    }
    while (true) {

    }
}
