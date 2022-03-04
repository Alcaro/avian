# avian

A chat program over DNS

Designed for censorship circumvention, not convenience

## Limitations

- Server installation requires significant technical expertise.
- Unix-likes only. Tested on Linux and WSL; does not work natively on Windows (PRs welcome).
- There are no channels, usernames, banhammers, online status, file upload, or any other modern conveniences. Give access to trusted people only.
- It's slow. You can read 8 bytes and send 4 bytes per roundtrip to the server, no more; this is usually around 16 bytes per second.

## Installation

- Create the_key.h, containing
```
#define THE_SERVER "avian.example.com"
#define THE_SERVER_DNS "\5avian\7example\3com"
#define THE_KEY { 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04 }
```
- Compile with `g++ -xc++ main.cpp -xc aes.c -o avian` (works on Linux and WSL; does not work natively on Windows)
- Run `./avian --server` somewhere on the open internet
- Assign a NS record to avian.example.com, pointing to the IP or normal domain name of your server
- Run `./avian` on a computer with restricted internet access (and on one on the open internet, so your restricted friends can communicate)

## Protocol

The avian protocol consists of 16 byte messages.

A query consists of a 32 bit counter (Unix timestamp - avian is not designed for operation beyond 2038), 32 bits expected chat history size (avian does not support chat history bigger than four gigabytes), 4 bytes data to append (padded with 00s if nothing to send), and 32 bits of 00 00 00 00 as a checksum. If expected chat history size does not match actual, the data will not be appended.

The counter+histsize field may not be reused, but as long as either is bigger than last time, the other may remain unchanged.

These 16 bytes will be encrypted with AES-128 in ECB mode, hex encoded using the alphabet abcdefghijklmnop, appended with the server name, and queried over DNS.

The resulting AAAA response will be xor'd with the query's plaintext, then decrypted with the same AES key.

The response plaintext consists of a 32 bit actual chat history size, 8 bytes chat data (or 00s if nothing), and 32 bits of 11 11 11 11.

This means receiving a message can only be done at 8 bytes per query (but can be parallelized), and sending is 4 bytes per trip (which can not be parallelized - the server will reject unordered writes).

## Logo

[![Eurasian blue tit](https://upload.wikimedia.org/wikipedia/commons/thumb/8/86/Eurasian_blue_tit_Lancashire.jpg/320px-Eurasian_blue_tit_Lancashire.jpg)](https://en.wikipedia.org/wiki/File:Eurasian_blue_tit_Lancashire.jpg)

Any other Ukraine-colored bird is also acceptable as logo.

## What's with the name?

It's named after [another censorship-resistant and inconvenient communication protocol](https://en.wikipedia.org/wiki/IP_over_Avian_Carriers).

## Okay but all of your tools have weird names

All the normal names were taken, boring, or both
