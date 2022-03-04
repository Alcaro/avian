#define VERBOSE 0

#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include "the_key.h"
extern "C" {
#include "aes.h"
}

static AES_ctx aesctx;

// chat protocol:
// client->server - u32 timestamp, u32 file pos, u8[4] append, u32 zeroes
// server->client - u32 file size, u8[8] data, u32 0x11111111

static void printdebug(const char * prefix, const uint8_t * in, size_t len = 16)
{
#if VERBOSE
	if (prefix) printf("%s ", prefix);
	for (size_t i=0;i<len;i++)
		printf("%.2X", in[i]);
	puts("");
#endif
}

static bool process_chat_query(uint8_t* ret, const uint8_t * in, int chatlog_fd)
{
printdebug("recv", in);
	if (in[12] != 0x00 || in[13] != 0x00 || in[14] != 0x00 || in[15] != 0x00)
		return false;
	// ignore timestamp, it's mostly a cache buster
	uint32_t rd_pos = (in[4]<<24) | (in[5]<<16) | (in[6]<<8) | (in[7]<<0);
	size_t wr_amt = (!!in[8] + !!in[9] + !!in[10] + !!in[11]); // can screw up if there's a nul before a not nul - assumed to not happen
	
	size_t filesz = lseek(chatlog_fd, 0, SEEK_END);
	ret[0] = filesz>>24; ret[1] = filesz>>16; ret[2] = filesz>>8; ret[3] = filesz>>0;
	
	if (filesz == rd_pos)
	{
		if (wr_amt)
			write(chatlog_fd, in+8, wr_amt);
		filesz += wr_amt;
	}
	
	memset(ret+4, 0, 8);
	if (rd_pos < filesz)
		pread(chatlog_fd, ret+4, 8, rd_pos);
	ret[12] = 0x11; ret[13] = 0x11; ret[14] = 0x11; ret[15] = 0x11;
	
printdebug("send", ret);
	return true;
}

static uint8_t to_send[4];
static time_t last_msg;

static void make_chat_query(uint8_t* query, int chatlog_fd)
{
	time_t t = time(NULL);
	if (!last_msg) last_msg = t;
	query[0] = t>>24; query[1]=t>>16; query[2]=t>>8; query[3]=t;
	
	if (!to_send[0])
		read(0, to_send, 4);
	
	size_t filesz = lseek(chatlog_fd, 0, SEEK_END);
	query[4] = filesz>>24; query[5] = filesz>>16; query[6] = filesz>>8; query[7] = filesz>>0;
	memcpy(query+8, to_send, 4);
	
	memset(query+12, 0, 4);
printdebug("send", query);
}
static void process_chat_response(const uint8_t * in, int chatlog_fd)
{
printdebug("recv", in);
	if (in[12] != 0x11 || in[13] != 0x11 || in[14] != 0x11 || in[15] != 0x11)
	{
		puts("someone's tampering with your communications!!!1");
		usleep(1000000);
		return;
	}
	uint32_t rd_pos = (in[0]<<24) | (in[1]<<16) | (in[2]<<8) | (in[3]<<0);
	
	int i;
	for (i=0;i<4;i++)
	{
		if (to_send[i] != in[i+4]) break;
	}
	memmove(to_send, to_send+i, i);
	memset(to_send+i, 0, 4-i);
	
	size_t wr_amt = (!!in[4] + !!in[5] + !!in[6] + !!in[7] + !!in[8] + !!in[9] + !!in[10] + !!in[11]);
	if (wr_amt)
	{
		write(chatlog_fd, in+4, wr_amt);
		write(1, in+4, wr_amt);
	}
	else
	{
		time_t delay = (time(NULL)-last_msg)*1000000.0/60;
		if (delay < 1000000) delay = 1000000;
		if (delay > 60000000) delay = 60000000;
		usleep(delay);
	}
}

static bool decode_label_hex(uint8_t * out, const uint8_t * in)
{
	for (int i=0;i<16;i++)
	{
		char c1 = tolower(in[i*2]);
		char c2 = tolower(in[i*2+1]);
		if (c1 < 'a' || c1 >= 'a'+16) return false;
		if (c2 < 'a' || c2 >= 'a'+16) return false;
		out[i] = (c1-'a')*16 + (c2-'a');
	}
	return true;
}

static void encode_label_hex(uint8_t * out, const uint8_t * in)
{
	for (int i=0;i<16;i++)
	{
		out[i*2] = (in[i]/16)+'a';
		out[i*2+1] = (in[i]%16)+'a';
	}
}

namespace {
static int setsockopt(int socket, int level, int option_name, const void * option_value, socklen_t option_len)
{
	return ::setsockopt(socket, level, option_name, (char*)/*lol windows*/option_value, option_len);
}

static int setsockopt(int socket, int level, int option_name, int option_value)
{
	return setsockopt(socket, level, option_name, &option_value, sizeof(option_value));
}

static int mksocket()
{
	const char* hostname=0; /* wildcard */
	const char* portname="53";
	struct addrinfo hints;
	memset(&hints,0,sizeof(hints));
	hints.ai_family=AF_INET6;
	hints.ai_socktype=SOCK_DGRAM;
	hints.ai_protocol=0;
	hints.ai_flags=AI_PASSIVE|AI_ADDRCONFIG;
	struct addrinfo* res=0;
	int err=getaddrinfo(hostname,portname,&hints,&res);
	if (err != 0) exit(1);
	int fd=socket(res->ai_family,res->ai_socktype|SOCK_CLOEXEC,res->ai_protocol);
	if (fd == -1) exit(1);
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, false) < 0) exit(1);
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, true) < 0) exit(1);
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, true) < 0) exit(1);
	if (bind(fd,res->ai_addr,res->ai_addrlen) == -1) exit(1);
	freeaddrinfo(res);
	return fd;
}
}

static size_t process_packet(uint8_t* ret, const uint8_t * in, size_t inlen, int chatlog_fd)
{
	if (inlen < 12) return 0;
	memcpy(ret, in, inlen);
	
	static const char servname_dns[] = THE_SERVER_DNS;
	static const size_t QD = 12; // start of first QD
	static const size_t QDsz = 1+32+sizeof(servname_dns) + 2 + 2; // QNAME, QTYPE, QCLASS
	static const size_t AN = QD + QDsz;
	static const size_t ANsz = 2+2+2+4+2+16; // NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA
	
	ret[2] = (ret[2]&0x79)|0x80; // FLAGS (set QR, copy OPCODE, set AA, copy RD, clear others)
	ret[3] &= 0x70;
	
	if (false)
	{
		//FORMERR:  ret[3] |= 1; return inlen;
		//SERVFAIL: ret[3] |= 2; return inlen;
		NXDOMAIN: ret[3] |= 3; return inlen;
		//NOTIMP:   ret[3] |= 4; return inlen;
		REFUSED:  ret[3] |= 5; return inlen;
	}
	
	if ((in[2]&~0x01) != 0x00 || (in[3]&~0x70) != 0x00) goto REFUSED; // FLAGS (ignore RD and Z, others should be zero)
	if (in[4] != 0 || in[5] != 1) goto REFUSED; // QDCOUNT
	if (in[6] != 0 || in[7] != 0) goto REFUSED; // ANCOUNT
	if (in[8] != 0 || in[9] != 0) goto REFUSED; // NSCOUNT
	if (in[10] == 0 && in[11] == 1 && inlen >= QD+QDsz+11)
	{
		ret[11] = 0; // discard extra OPT type additional record, per RFC 6891
		inlen = QD+QDsz;
	}
	else if (in[10] != 0 || in[11] != 0) goto REFUSED; // ARCOUNT
	
	if (in[QD] != 32) goto NXDOMAIN;
	if (inlen != QD+QDsz) goto NXDOMAIN; // header, QNAME, QTYPE, QCLASS
	if (memcmp(in+QD+1+32, servname_dns, sizeof(servname_dns)) != 0) goto NXDOMAIN;
	
	uint8_t chat_q[16];
	if (!decode_label_hex(chat_q, in+QD+1))
		goto NXDOMAIN;
	
	AES_ECB_decrypt(&aesctx, chat_q);
	
	ret[AN+0] = 0xC0+0; ret[AN+1] = QD; // NAME
	ret[AN+2] = 0; ret[AN+3] = 28; // TYPE = AAAA
	ret[AN+4] = 0; ret[AN+5] = 1; // CLASS = IN
	ret[AN+6] = 0x00; ret[AN+7] = 0x00; ret[AN+8] = 3600/256; ret[AN+9] = 3600%256; // TTL
	ret[AN+10] = 0; ret[AN+11] = 16; // RDLENGTH
	
	uint8_t* chat_ret = ret+AN+12; // RDATA
	if (!process_chat_query(chat_ret, chat_q, chatlog_fd)) goto NXDOMAIN;
	
	AES_ECB_encrypt(&aesctx, chat_ret);
	for (int i=0;i<16;i++)
		chat_ret[i] ^= chat_q[i];
	
	ret[2] |= 0x04; // FLAGS.AA
	ret[7] = 1; // ANCOUNT
	
	return AN+ANsz;
}

static void do_server()
{
	int fd = mksocket();
	if (fd < 0) exit(1);
	int chatlog_fd = open("chat.txt", O_RDWR|O_CREAT, 0644);
	if (chatlog_fd < 0) exit(1);
	
	if (getuid() == 0) {
		/* process is running as root, drop privileges */
		if (setgid(65534) != 0)
			exit(1);
		if (setuid(65534) != 0)
			exit(1);
	}
	puts("Ready");
	
	while (true)
	{
		uint8_t buffer[65536];
		uint8_t buf2[65536];
		struct sockaddr_storage src_addr;
		socklen_t src_addr_len=sizeof(src_addr);
		ssize_t count=recvfrom(fd,buffer,sizeof(buffer),0,(struct sockaddr*)&src_addr,&src_addr_len);
		if (count==-1) {
			exit(1);
		} else if (count==sizeof(buffer)) {
			continue;
		}
		
#if VERBOSE >= 2
		printdebug("recvraw", buffer, count);
#endif
		size_t retlen = process_packet(buf2, buffer, count, chatlog_fd);
#if VERBOSE >= 2
		printdebug("sendraw", buf2, retlen);
#endif
		if (retlen != 0)
			sendto(fd, buf2, retlen, 0, (struct sockaddr*)&src_addr, src_addr_len);
#if VERBOSE >= 1
		fflush(stdout);
#endif
	}
}

static void do_client(const char * fn)
{
	int chat_fd = open(fn, O_RDWR|O_CREAT, 0644);
	fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK);
	
	char domain[] = "abcdabcdabcdabcdabcdabcdabcdabcd." THE_SERVER;
	while (true)
	{
		uint8_t query[16];
		uint8_t query_orig[16];
		make_chat_query(query, chat_fd);
		memcpy(query_orig, query, 16);
		
		AES_ECB_encrypt(&aesctx, query);
		encode_label_hex((uint8_t*)domain, query);
		
		bool ok = false;
		uint8_t ret[16];
#if VERBOSE >= 2
		printf("lookup %s\n", domain);
#endif
		
		struct addrinfo hints;
		struct addrinfo * result;
		
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = 0;
		
		if (getaddrinfo(domain, NULL, &hints, &result) == 0)
		{
			memcpy(ret, &((struct sockaddr_in6*)result->ai_addr)->sin6_addr, 16);
			freeaddrinfo(result);
			ok = true;
		}
#ifdef VERBOSE
		else puts("lookup failure");
#endif
		
		if (ok)
		{
			for (int i=0;i<16;i++)
				ret[i] ^= query_orig[i];
			AES_ECB_decrypt(&aesctx, ret);
			process_chat_response(ret, chat_fd);
		}
		else
			usleep(1000000);
	}
}

int main(int argc, char** argv)
{
	static const uint8_t key[] = THE_KEY;
	static_assert(sizeof(key) == 16, "the key must be exactly 16 bytes");
	AES_init_ctx(&aesctx, key);
	
	if (argc >= 2 && !strncmp(argv[1], "--server", strlen("--server")))
		do_server();
	else
		do_client(argv[1] ? argv[1] : "chatlocal.txt");
	return 0;
}
