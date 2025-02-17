#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <unordered_map>
#include <map>
#include <set>
#include <cstring>
#include <sys/time.h>
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
        if (ntohs(pkt->length) > 0)
            output_p(pkt->payload, ntohs(pkt->length));

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
        if (ntohs(pkt->length) > 0)
            output_p(pkt->payload, ntohs(pkt->length));
        
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
    int flags = fcntl(sockfd, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(sockfd, F_SETFL, flags);

    uint16_t seq_num, ack_num;
    if (type == CLIENT) {
        seq_num = client_seq + 2;
        ack_num = server_seq + 1;
    } else {
        seq_num = server_seq + 1;
        ack_num = client_seq + 1;
    }

    unordered_map<uint16_t, packet> send_buf; // stores unACKed packets
    map<uint16_t, packet> recv_buf; // stores out-of-order packets
    uint16_t window_size = MIN_WINDOW; // window size, static for now (TODO: implement flow control)
    
    struct timeval last_ack_timestamp, cur_time; // start timers
    gettimeofday(&last_ack_timestamp, nullptr); // updated on each ACK received
    gettimeofday(&cur_time, nullptr); // updated on each iteration of loop

    uint16_t last_ack = ack_num; // start at whatever ACK is after handshake
    uint16_t dup_acks = 0;

    while (true) {
        // receive packet from sender
        int bytes_recvd = recvfrom(sockfd, pkt, BUF_SIZE, 0, (struct sockaddr*) addr, &addr_len);
        if (bytes_recvd > 0) {
            print_diag(pkt, RECV);
            if (calc_pbit(pkt) == 0) {
                uint16_t pkt_ack = ntohs(pkt->ack);
                // if packet is ACK from other side
                if (pkt->flags & ACK) {
                    // check if ACK advances `last_ack`
                    if (pkt_ack > last_ack) {
                        // brand new ACK that moves forward
                        last_ack = pkt_ack;
                        dup_acks = 0;
                        gettimeofday(&last_ack_timestamp, nullptr); // reset RTO timer
                    } else if (pkt_ack == last_ack) {
                        // duplicate ACK
                        ++dup_acks;
                        if (dup_acks == DUP_ACKS) {
                            // fast retransmit
                            if (!send_buf.empty()) {
                                uint16_t lowest_seq = send_buf.begin()->first;
                                for (auto &kv : send_buf)
                                    if (kv.first < lowest_seq)
                                        lowest_seq = kv.first;
                                packet &lowest_pkt = send_buf[lowest_seq];
                                sendto(sockfd, &lowest_pkt, sizeof(packet) + ntohs(lowest_pkt.length), 0, (struct sockaddr*) addr, addr_len);
                                // no resetting RTO timer for dup ACKs
                                print_diag(&lowest_pkt, DUPS);
                            }
                        }
                    }
                    // remove ACKed packets from send buffer
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

                if (pkt_len > 0) {
                    if (pkt_seq == ack_num) {
                        // handle in-order data immediately
                        output_p(pkt->payload, pkt_len);
                        ++ack_num;
                        while (recv_buf.find(ack_num) != recv_buf.end()) {
                            packet &buf_pkt = recv_buf[ack_num];
                            uint16_t buf_len = ntohs(buf_pkt.length);
                            output_p(buf_pkt.payload, buf_len);
                            recv_buf.erase(ack_num);
                            ++ack_num;
                        }
                        // send back an ACK
                        packet ack_pkt = {};
                        ack_pkt.seq = 0; // empty ACK packets can't have a SEQ #
                        ack_pkt.ack = htons(ack_num);
                        ack_pkt.length = 0;
                        ack_pkt.win = htons(window_size);
                        ack_pkt.flags = ACK;
                        ack_pkt.flags |= set_parity(&ack_pkt);
                        sendto(sockfd, &ack_pkt, sizeof(packet), 0, (struct sockaddr*) addr, addr_len);
                        print_diag(&ack_pkt, SEND);
                    }
                    else if (pkt_seq > ack_num)
                        // buffer out-of-order packet into recv buffer
                        recv_buf[pkt_seq] = *pkt;
                }
            }
        }
        
        if (send_buf.size() < (window_size / MAX_PAYLOAD)) {
            uint8_t buffer[BUF_SIZE] = {0};
            packet* p = reinterpret_cast<packet*>(buffer);
            uint16_t n = input_p(p->payload, MAX_PAYLOAD);
            if (n > 0) {
                p->seq = htons(seq_num);
                p->ack = htons(ack_num);
                p->length = htons(n);
                p->win = htons(window_size);
                p->flags = 0;
                p->flags |= set_parity(p);
                send_buf[seq_num] = *p;
                sendto(sockfd, p, sizeof(packet) + n, 0, (struct sockaddr*) addr, addr_len);
                print_diag(p, SEND);
                ++seq_num;
            }
        }

        // check if RTO timer has expired
        gettimeofday(&cur_time, nullptr);
        long diff_usec = TV_DIFF(cur_time, last_ack_timestamp);
        if (diff_usec >= RTO) {
            if (!send_buf.empty()) {
                uint16_t lowest_seq = send_buf.begin()->first;
                for (auto &kv : send_buf)
                    if (kv.first < lowest_seq)
                        lowest_seq = kv.first;
                packet &lowest_pkt = send_buf[lowest_seq];
                sendto(sockfd, &lowest_pkt, sizeof(packet) + ntohs(lowest_pkt.length), 0, (struct sockaddr*) addr, addr_len);
                print_diag(&lowest_pkt, RTOS);
            }
        }
    }
}
