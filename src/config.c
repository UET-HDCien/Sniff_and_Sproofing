#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include "string.h"

void printConfig() {
	printf("================================================ \n");
	printf("Usage: kien -i interface <option> <parameter> \n");
	printf("--dst: Destination IP to capture packet and sproof \n");
	printf("--dport: Destination port to capture packet and sproof \n");
	printf("--host: Destination host (in HTTP Request) to capture packet and sproof \n");
	printf("Example: kien -i eth0 --host abc.xyz\n");
}

AttackConfig *parseConfig(int argc, char const *argv[]) {
	AttackConfig *config = (AttackConfig *) malloc(sizeof(AttackConfig));
	memset(config, 0x00, sizeof(AttackConfig));
	int i = 1;
	while (i < argc-1) {
		if (!strcmp(argv[i],"--dst")) {
			strncpy(config->dst, argv[i+1], sizeof(config->dst));
		} else if (!strcmp(argv[i],"--dport")) {
			config->dport = (unsigned short) strtoul(argv[i+1], NULL, 0);
		} else if (!strcmp(argv[i],"-i")) {
			strncpy(config->interface, argv[i+1], sizeof(config->interface));
		} else if (!strcmp(argv[i],"--host")) {
			strncpy(config->host, argv[i+1], sizeof(config->host));
		} else if (!strcmp(argv[i],"--help")) {
			printConfig();
			i += 1;
			continue;
		} else {
			printf("Invalid option %s\n", argv[i]);
			printConfig();
			return NULL;
		}
		
		i += 2;
	}
	if (i == argc-1 && strncmp(argv[argc-1],"-h", strlen(argv[argc-1])) ) {
		printf("Option \"%s\" invalid or need a parameter!\n", argv[argc-1]);
		printConfig();
		return NULL;
	}

	return config;

}

