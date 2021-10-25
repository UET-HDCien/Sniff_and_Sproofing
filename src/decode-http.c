#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "decode-http.h"


httprequest *parseRequest(u_char *requestText) {
	char key[256];
	char val[1024];
	if (requestText == NULL || requestText[0]=='\0') return NULL;
	
	char tmp[2048];
	strncpy(tmp, requestText, strlen(requestText));
	char *token = NULL;
	token = strtok(tmp," ");
	char valid = 0;
	
	if (!strncmp(token,"GET",strlen(token)) || !strncmp(token,"POST",strlen(token)) || !strncmp(token,"PUT",strlen(token)) || !strncmp(token,"DELETE",strlen(token)))   {
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
