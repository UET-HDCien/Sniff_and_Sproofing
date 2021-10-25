#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include "string.h"

void printConfig() {
	printf("================================================ \n");
	printf("Usage: kien -i interface <optional parameter> \n");
	printf("--dst: Destination IP to capture packet and sproof \n");
	printf("--dst-port: Destination port to capture packet and sproof \n");
	printf("--host: Destination host (in HTTP Request) to capture packet and sproof \n");
	printf("--src: Source IP to capture request and sproof respond\n");
}

AttackConfig *parseConfig(int argc, char const *argv[]) {
	AttackConfig *config = (AttackConfig *) malloc(sizeof(AttackConfig));
	memset(config, 0x00, sizeof(AttackConfig));
	int i = 1;
	while (i < argc-1) {
		if (!strncmp(argv[i],"--dst", strlen(argv[i]))) {
			strncpy(config->target_dst, argv[i+1], sizeof(config->target_dst));
		} else if (!strncmp(argv[i],"--src", strlen(argv[i]))) {
			strncpy(config->target_src,argv[i+1],sizeof(config->target_src));
		} else if (!strncmp(argv[i],"--dst-port", strlen(argv[i]))) {
			config->target_dstport = (unsigned short) strtoul(argv[i+1], NULL, 0);
		} else if (!strncmp(argv[i],"--src-port", strlen(argv[i]))) {
			config->target_srcport = (unsigned short) strtoul(argv[i+1], NULL, 0);
		} else if (!strncmp(argv[i],"-i", strlen(argv[i]))) {
			strncpy(config->interface, argv[i+1], sizeof(config->interface));
		} else if (!strncmp(argv[i],"--host", strlen(argv[i]))) {
			strncpy(config->target_dst, argv[i+1], sizeof(config->target_dst));
		} else if (!strncmp(argv[i],"-h", strlen(argv[i]))) {
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

