#include "consts.h"
#include "io.h"
#include "transport.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <cstdlib>
#include <ctime>

using namespace std;

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: server <port>\n");
        exit(1);
    }

    srand(time(nullptr)); // pass in a constant param to `srand` for determinism (debugging)
                        // use IPv4  use UDP
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    /* Construct our address */
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET; // use IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY;   // accept all connections. same as inet_addr("0.0.0.0")
    // Set receiving port
    int PORT = atoi(argv[1]);
    server_addr.sin_port = htons(PORT); // Big endian

    /* Let operating system know about our config */
    ::bind(sockfd, (struct sockaddr*) &server_addr, sizeof(server_addr));

    struct sockaddr_in client_addr; // Same information, but about client
    socklen_t s = sizeof(struct sockaddr_in);
    char buffer;

    // Wait for client connection
    recvfrom(sockfd, &buffer, sizeof(buffer), MSG_PEEK, (struct sockaddr*) &client_addr, &s);
    init_io();
    listen_loop(sockfd, &client_addr, SERVER, input_io, output_io);

    return 0;
}
