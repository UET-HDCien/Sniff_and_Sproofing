#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "checksum.h"


unsigned short in_cksum (unsigned short *buf , int length)
{
	unsigned short *w = buf;
	int nLeft = length ;
	int sum = 0;
	unsigned short temp = 0;

	while (nLeft > 1) {
		sum += *w++;
		nLeft -= 2 ;
	}

	if (nLeft == 1 ) {
		*(u_char *)( &temp ) = *(u_char *) w ;
		sum += temp ;
	}

	sum= (sum >> 16) + (sum & 0xffff);
	sum+= (sum>> 16);
	// add carry
	return (unsigned short ) (~sum ) ;
}

unsigned short calculate_tcp_checksum (ipheader *ip) {
	int IP_HEADER_LEN = ip -> iph_ihl * 4;
	tcpheader *tcp = (tcpheader * ) ((u_char *)ip + IP_HEADER_LEN);
	int tcp_len = ntohs(ip->iph_len) - IP_HEADER_LEN;
	pseudo_tcp p_tcp;
	memset(&p_tcp, 0x00, sizeof(pseudo_tcp));
	p_tcp.saddr = ip->iph_srcip.s_addr;
	p_tcp.daddr = ip->iph_dstip.s_addr ;
	p_tcp.mbz = 0;
	p_tcp.ptcl = IPPROTO_TCP;
	p_tcp.tcpl = htons(tcp_len);
	memcpy(&p_tcp.tcp, tcp, tcp_len); 
	return (unsigned short ) in_cksum (( unsigned short *)&p_tcp ,tcp_len + 12);
}

