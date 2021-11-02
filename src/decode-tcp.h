#define TCP_HEADER_LEN                       20

typedef struct tcpheader_
{
    uint16_t th_sport;  
    uint16_t th_dport;  
    uint32_t th_seq;    
    uint32_t th_ack;    
    uint8_t th_offx2;   
    uint8_t th_flags;   
    uint16_t th_win;    /**< pkt window */
    uint16_t th_sum;    /**< checksum */
    uint16_t th_urp;    /**< urgent pointer */
} tcpheader;

