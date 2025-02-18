# CS 118 Winter 25 Project 1
### Takbir Rahman, Atij Mahesh, Brandon Lo

## 1. Design Choices
- We used the given packet struct with SEQ #, ACK #, payload length, dynamic window size, flags, and the payload data itself
- We developed in C++ because we disagree with Omar's take that C++ is cringe. It's much easier to develop in C++ with library abstractions
- We used a `std::unordered_map` for our send buffer, mapping our sent (but not yet ACKed) packets
- We used a `std::map` for our recv buffer, holding onto any out-of-order packets
- We developed all within `transport.cpp` since client and server become ambiguous after the handshake is established

## 2. Problems Encountered
- The most significant problem encountered early on was having a huge percent difference in bytes sent/received

- We don't have a 100% solution, and are still encountering errors 
    - Server data loss: In `test_server_drop`, the server only receives a small fraction of the expected bytes when the reference client sends data
    - Client partial reception: In `test_client_drop`, the client receives only around 40% of the expected data, indicating packet loss or incomplete retransmissions
    - Large file reliability issues: In `test_server_drop` with a 500KB file, the server loses around 15% of the data, suggesting issues with handling dropped or reordered packets at scale


## 3. Solutions to Problems
- The primary reason for the 1st problem was that, if the client was calling `listen_loop`, we didn't set the starting SEQ # properly
    - Initially set `seq_num` to 1 plus the client's SEQ, but we fixed it by adding 2 to the client's SEQ since `listen_loop` starts after the handshake, so we needed to correctly account for SYN and ACK sent during handshake

- Couldn't resolve the latter few issues