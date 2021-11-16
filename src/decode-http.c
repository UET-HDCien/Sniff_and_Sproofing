#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "decode-http.h"


httprequest *parseRequest(char *requestText) {
	if (requestText == NULL || requestText[0]=='\0') return NULL;
	//printf("len %ld\n",strlen(requestText));
	char key[256];
	char val[1024];
	char tmp[2048];
	strncpy(tmp, requestText, sizeof(tmp));
	char *token = NULL;
	token = strtok(tmp," ");
	char valid = 0;
	
	if (!strcmp(token,"GET") || !strcmp(token,"POST") || !strcmp(token,"PUT") || !strcmp(token,"DELETE"))   {
		valid = 1;
	}
	if (!valid) return NULL; 
	
	httprequest *request;
	request = (httprequest*) malloc (sizeof(httprequest));
	memset(request, 0x00, sizeof(httprequest));
	strncpy(request->method, token, strlen(token));
	token = strtok(NULL, "\n");
	
	while (token) {
		memset(key, 0x00, sizeof(key));
		memset(val, 0x00, sizeof(val));
		token = strtok(NULL, ":");
		if (!token) break;
		strncpy(key, token, strlen(token));
		token = strtok(NULL,"\r\n");
		if (!token) break;
		strncpy(val, token+1, strlen(token)-1);	// Skip space after :
		if (!strncmp(key,"Host",strlen(token))) {
			strncpy(request->host, val, strlen(val));	// skip space character
			break;
		}
	}
	return request;
}
