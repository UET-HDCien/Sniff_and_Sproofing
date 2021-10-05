
typedef struct AttackConfig_ {
	char target_src[256];
	unsigned short target_srcport;
	char target_dst[256];
	unsigned short target_dstport;
	char interface[64];
} AttackConfig;

AttackConfig *parseConfig(char const *argv[]);
