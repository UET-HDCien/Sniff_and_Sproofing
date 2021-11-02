#include "decode-ipv4.h"
#include "decode-tcp.h"

typedef struct pseudo_tcp_ {
	unsigned saddr , daddr ;
	unsigned char mbz ;
	unsigned char ptcl ;
	unsigned short tcpl ;
	tcpheader tcp ;
	char payload[1500] ;
} pseudo_tcp;

unsigned short calculate_tcp_checksum (ipheader *);

