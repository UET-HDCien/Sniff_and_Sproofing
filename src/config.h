#define MAX_HOST_LEN 256
typedef struct AttackConfig_ {
	char dst[256];
	unsigned short dport;
	char host[MAX_HOST_LEN];
	char interface[64];
} AttackConfig;

AttackConfig *parseConfig(int argc, char const *argv[]);
