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

        // if received packet is an ACK, remove all packets from send buffer up to (but not including) ACK number
        if (pkt->flags & ACK) {
            uint16_t pkt_ack = ntohs(pkt->ack);
            auto it = send_buf.begin();
            while (it != send_buf.end()) {
                if (it->first < pkt_ack)
                    it = send_buf.erase(it);
                else
                    it++;
            }
        }

        uint16_t pkt_seq = ntohs(pkt->seq);
        uint16_t pkt_len = ntohs(pkt->length);
        window_size = ntohs(pkt->win);
        
        // process in-order packets
        if (pkt_seq == ack_num) {
            output_p(pkt->payload, pkt_len);
            ++ack_num; // expected seq # moves forward
            // process buffered out-of-order packets that might now be in-order
            while (recv_buf.find(ack_num) != recv_buf.end()) {
                output_p(recv_buf[ack_num].payload, ntohs(recv_buf[ack_num].length));
                recv_buf.erase(ack_num);
                ++ack_num;
            }
        }
        // buffer out-of-order packets
        else if (pkt_seq > ack_num)
            recv_buf[pkt_seq] = *pkt;

        // send new data if window is not full
        if (send_buf.size() < window_size / MAX_PAYLOAD) {
            packet new_pkt = {};
            new_pkt.seq = htons(seq_num);
            new_pkt.ack = htons(ack_num);
            
            // read from stdin into payload
            payload_size = input_p(new_pkt.payload, MAX_PAYLOAD);
            if (payload_size == 0) continue; // no more data to send

            new_pkt.length = htons(payload_size);
            new_pkt.win = htons(window_size);
            new_pkt.flags = set_parity(&new_pkt);

             // store packet in send buffer then send it
            send_buf[seq_num] = new_pkt;
            sendto(sockfd, &new_pkt, sizeof(packet) + payload_size, 0, (struct sockaddr*) addr, addr_len);
            print_diag(&new_pkt, SEND);
        }
    }
}
