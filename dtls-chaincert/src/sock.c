#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <netinet/ip.h> 
#include <error.h>
#include <errno.h>
#include <string.h>

void SetInetAddr(struct sockaddr_in *addr, int port){
	int SOCK_LEN;
	SOCK_LEN = sizeof(addr);
	bzero((char *)addr,SOCK_LEN);
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = INADDR_ANY;
	addr->sin_port = htons(port);
}

int BindSocket(int type, int port)
{
	int    sd, SOCK_LEN;
	struct sockaddr_in  addr;
    
	if ( (sd = socket(AF_INET,type,0)) < 0 ) {
		printf( "[BindSocket] socket fail (port=%d) : %s\n",
					port,
					strerror(errno));
	}
	
	SetInetAddr(&addr, port);

	SOCK_LEN = sizeof(addr);
	if ( bind(sd,(struct sockaddr *)&addr,SOCK_LEN) < 0 ) {
		printf("[BindSocket] bind fail (port=%d) : %s\n",
					port,
					strerror(errno));
	}
    struct timeval read_timeout;
    read_timeout.tv_sec = 0;
    read_timeout.tv_usec = 10;
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof read_timeout);

	return sd;
}