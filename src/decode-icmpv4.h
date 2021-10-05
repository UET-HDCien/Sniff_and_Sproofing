#define ICMP_HEADER_LEN       8

typedef struct icmpheader_
{
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
} icmpheader;

