#define MAX_HOST_LEN 256
#define MAX_PATH_LEN 512


typedef struct httprequest_ {
	char host[MAX_HOST_LEN];
	char scheme[20];	//http or https
	char path[MAX_PATH_LEN];
	char method[20];
} httprequest;

typedef struct httprespond_ {
	int statusCode;
} httprespond;

httprequest * parseRequest(char *requestText);
