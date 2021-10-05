#define ETHERNET_HEADER_LEN           14

typedef struct ethheader_ {
	u_char ether_dhost[6];
	u_char ether_shost[6];
	u_short ether_type;
} ethheader;

