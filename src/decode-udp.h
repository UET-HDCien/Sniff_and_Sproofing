#define UDP_HEADER_LEN         8

typedef struct udpheader_
{
	uint16_t uh_sport;  /* source port */
	uint16_t uh_dport;  /* destination port */
	uint16_t uh_len;    /* length */
	uint16_t uh_sum;    /* checksum */
} udpheader;
