#define TCP_HEADER_LEN                       20

typedef struct tcpheader_
{
    uint16_t th_sport;  /**< source port */
    uint16_t th_dport;  /**< destination port */
    uint32_t th_seq;    /**< sequence number */
    uint32_t th_ack;    /**< acknowledgement number */
    uint8_t th_offx2;   /**< offset and reserved */
    uint8_t th_flags;   /**< pkt flags */
    uint16_t th_win;    /**< pkt window */
    uint16_t th_sum;    /**< checksum */
    uint16_t th_urp;    /**< urgent pointer */
} tcpheader;

typedef struct pseudo_tcp_ {
	unsigned saddr, daddr;
	unsigned char mbz;
	unsigned char ptcl;
	unsigned short tcpl;
	tcpheader tcp;
	char payload[1500];
} pseudo_tcp;
