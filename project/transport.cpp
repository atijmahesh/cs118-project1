#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <unordered_map>
#include <map>
#include <set>
#include "consts.h"

using namespace std;

// Main function of transport layer; never quits
void listen_loop(int sockfd, struct sockaddr_in* addr, int type, ssize_t (*input_p)(uint8_t*, size_t), void (*output_p)(uint8_t*, size_t)) {
    uint8_t buffer[BUF_SIZE] = {0};
    packet* pkt = reinterpret_cast<packet*>(buffer);
    socklen_t addr_len = sizeof(struct sockaddr_in);
    size_t payload_size = 0;
    uint16_t client_seq = 0, server_seq = 0;

    if (type == CLIENT) {
        // step 1: client sends SYN packet to server to initiate handshake
        client_seq = (rand() % 1000) + 1;
        pkt->seq = htons(client_seq);
        pkt->ack = 0;

        // read payload data (if available)
        payload_size = input_p(pkt->payload, MAX_PAYLOAD); // `input_io` populates `payload` field
        pkt->length = htons(payload_size);

        pkt->win = htons(MIN_WINDOW);
        pkt->flags = SYN;
        pkt->unused = 0;
        pkt->flags |= set_parity(pkt);

        // send SYN packet to server (client is now blocked until it receives SYN-ACK)
        sendto(sockfd, pkt, sizeof(packet) + payload_size, 0, (struct sockaddr*) addr, addr_len);
        print_diag(pkt, SEND);

        // step 4: client receives SYN-ACK from server (client now unblocked)
        recvfrom(sockfd, pkt, BUF_SIZE, 0, (struct sockaddr*) addr, &addr_len);
        print_diag(pkt, RECV);
        if (!(pkt->flags & SYN) || !(pkt->flags & ACK)) {
            print("Expected SYN-ACK packet. Dropping...\n");
            exit(1);
        }

        // step 5: client sends ACK to server to complete handshake
        server_seq = ntohs(pkt->seq);
        pkt->seq = htons(client_seq + 1);
        pkt->ack = htons(server_seq + 1);

        // read payload data (if available)
        payload_size = input_p(pkt->payload, MAX_PAYLOAD);
        pkt->length = htons(payload_size);

        pkt->win = htons(MIN_WINDOW);
        pkt->flags = ACK;
        pkt->unused = 0;
        pkt->flags |= set_parity(pkt);

        // send final ACK packet to server (handshake complete)
        sendto(sockfd, pkt, sizeof(packet) + payload_size, 0, (struct sockaddr*) addr, addr_len);
        print_diag(pkt, SEND);
    } else if (type == SERVER) {
        // step 2: server receives SYN packet from client

        // server is blocked until it receives SYN from client
        recvfrom(sockfd, pkt, BUF_SIZE, 0, (struct sockaddr*) addr, &addr_len);
        print_diag(pkt, RECV);
        if (!(pkt->flags & SYN)) {
            print("Expected SYN packet. Dropping...\n");
            exit(1);
        }
        
        // step 3: server sends SYN-ACK to client
        client_seq = ntohs(pkt->seq);
        server_seq = (rand() % 1000) + 1;
        pkt->seq = htons(server_seq);
        pkt->ack = htons(client_seq + 1); // ACK = client_seq + 1

        // read payload data (if available)
        payload_size = input_p(pkt->payload, MAX_PAYLOAD); // `input_io` populates `payload` field
        pkt->length = htons(payload_size);
        
        pkt->win = htons(MIN_WINDOW);
        pkt->flags = SYN | ACK;
        pkt->unused = 0;
        pkt->flags |= set_parity(pkt);

        // send SYN-ACK packet to client (server is now blocked until it receives ACK)
        sendto(sockfd, pkt, sizeof(packet) + payload_size, 0, (struct sockaddr*) addr, addr_len);
        print_diag(pkt, SEND);
    }

    // make socket nonblocking after handshake is completed
    init_fd(sockfd);
    uint16_t seq_num, ack_num;
    if (type == CLIENT) {
        seq_num = client_seq + 1;
        ack_num = server_seq + 1;
    } else {
        seq_num = server_seq + 1;
        ack_num = client_seq + 1;
    }

    unordered_map<uint16_t, packet> send_buf; // stores unACKed packets
    map<uint16_t, packet> recv_buf; // stores out-of-order packets
    uint16_t window_size = MIN_WINDOW; // window size, static for now (TODO: implement flow control)
    
    while (true) {
        // receive packet from sender
        int bytes_recvd = recvfrom(sockfd, pkt, BUF_SIZE, 0, (struct sockaddr*) addr, &addr_len);
        if (bytes_recvd < 0) continue;
        
        print_diag(pkt, RECV);
        
        if (calc_pbit(pkt) != 0) { // parity check
            print("Corrupt packet detected. Dropping...\n");
            continue;
        }
    }
}
