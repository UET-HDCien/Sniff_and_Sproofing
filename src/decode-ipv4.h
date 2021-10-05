typedef struct ipheader_ {
	unsigned char iph_ihl:4;
	unsigned char iph_ver:4;
	unsigned char iph_tos;
	unsigned short int iph_len;
	unsigned short int iph_ident;
	unsigned short int iph_flag:3;
	unsigned short int iph_offset:13;
	unsigned char iph_ttl;
	unsigned char iph_proto;
	unsigned short int iph_chksum;
	struct in_addr iph_srcip;
	struct in_addr iph_dstip;
} ipheader;


