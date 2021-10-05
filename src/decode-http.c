#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "decode-http.h"


httprequest *parseRequest(char *requestText) {
	char *token = NULL;
	token = strtok(requestText, " ");
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
	if (token) {
		token = strtok(NULL, ":");
	}
	
	while (token) {
		if (!strncmp(token,"Host",strlen(token))) {
			token = strtok(NULL,"\n");
			strncpy(request->host, token, strlen(token));
			//printf("%d", strlen(token));
		}
		token = strtok(NULL,":");
	}
	return request;
}

int main() {
	char requestText[] = "GETS / HTTP/1.1\nHost:google.com\n";
	httprequest *request = parseRequest(requestText);
	if (!request) {
		printf("Invalid request!");
	}
	else printf("method:%s\nhost:%s",request->method, request->host);
}
