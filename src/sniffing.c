#include <pcap.h>
#include <stdio.h>

#include "decode-ethernet.h"
#include "decode-ipv4.h"
#include "decode-tcp.h"
#include "decode-udp.h"
#include "decode-icmpv4.h"
#include "decode-http.h"
#include "config.h"
#include "logger.h"

AttackConfig *config;

int main(int argc, char const *argv[])
{
	pcap_t *handle;
	char errbuff[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] ="ip proto icmp";
	bpf_u_int32 net;
	
	config = parseConfig(argv);
	handle = pcap_open_live(config->interface, BUFSIZ, 1, 100, errbuff);
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	pcaploop_handle(handle, -1, got_packet, NULL);
	pcap_close(handle);
	return 0;
}

void got_packet(u_char *args, const struct pcap_pktheader *header, const u_char *packet)
{
	ethheader *eth = (ethheader *) packet;
	char match = 0; 
	if (ntohs(eth-> ether_type) == 0x0800) {	// ip packet
		ipheader *ip = (ipheader *) (packet + ETHER_HEADER_LEN);
		IP_HEADER_LEN = ip -> iph_ihl * 4;
		switch (ip->iph_protocol) {
			case IPPROTO_TCP:	// TCP protocol
				tcpheader *tcp = (tcpheader *) (packet + ETHER_HEADER_LEN + IP_HEADER_LEN);
				char * data = (char *) (packet + ETHER_HEADER_LEN + IP_HEADER_LEN+ TCP_HEADER_LEN);
				# Simple detect http
				httprequest *request = parseRequest(data);
				if (request) {
					char *token = NULL;
					token = strtok(request->host, ":");
					if (strncmp(token, config->target_dst)) {
						token = strtok(NULL, ":");
						if (config->target_dstport == 0) {
							match = 1;
						}else if (!token && (config->target_dstport == 0 || config->target_dstport== 80)) {
							match = 1;
						} else if (tokenconfig->target_dstport == (unsigned short) strtoul(token, NULL, 0);) {
							match = 1;
						}
					}
				}
			case IPPROTO_UDP:
				udpheader *udp = (udpheader *) (packet + ETHER_HEADER_LEN + IP_HEADER_LEN);
				
				break;
			case IPPROTO_ICMP:
				u_char *icmp = (icmpheader *) (packet + ETHER_HEADER_LEN + IP_HEADER_LEN);
				
				break;
			default:
				break;
		}
	} 
}

void send_raw_ip_packet(ipheader *ip) {
	struct sockaddr_in dst_info;
	int enable = 1;
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
	dst_info.sin_family = AF_INET;
	dst_info.sin_addr = ip -> dstip;
	sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr*) &dst_info, sizeof(dst_info));
	close(sock);
}

void spoof_reply_udp(ipheader *ip) {
	const char buffer[1500];
	int IP_HEADER_LEN = ip -> iph_ihl * 4;
	udpheader *udp = (udpheader *)((uchar *)ip + IP_HEADER_LEN);
	memset((char *) buffer, 0x00, sizeof(buffer));
	memcpy((char *) buffer, ip, ntohs(ip->iph_len));
	ipheader *newip= (ipheader *) buffer;
	updheader *newudp = (udpheader *) (buffer + IP_HEADER_LEN);
}

void spoof_reply_http(ipheader *ip, int type) {
	
}

dnsRecord *parseDNSData(char *udpdata) {

} 

httpRequest *parseHTTPData (char *tcpdata) {

}
