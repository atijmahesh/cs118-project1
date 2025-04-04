#include "consts.h"
#include "io.h"
#include "transport.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <cstdlib>
#include <ctime>

using namespace std;

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: client <hostname> <port> \n");
        exit(1);
    }

    srand(time(nullptr)); // pass in a constant param to `srand` for determinism (debugging)
                        // use IPv4  use UDP
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Construct server address */
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET; // use IPv4
    // Only supports localhost as a hostname, but that's all we'll test on
    const char* addr = strcmp(argv[1], "localhost") == 0 ? "127.0.0.1" : argv[1];
    server_addr.sin_addr.s_addr = inet_addr(addr);
    // Set sending port
    int PORT = atoi(argv[2]);
    server_addr.sin_port = htons(PORT); // Big endian
    
    init_io();
    listen_loop(sockfd, &server_addr, CLIENT, input_io, output_io);

    return 0;
}
