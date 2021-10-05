#include "config.h"
#include <stdlib.h>
#include "string.h"

AttackConfig *parseConfig(char const *argv[]) {
	AttackConfig *config = 	(AttackConfig *) malloc(sizeof(AttackConfig));
	memset(config, 0x00, sizeof(config));
	int i = 1;
	
	while (1) {
		
		if (!argv[i]) break;
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
		}
		
		i += 2;
	}

}
