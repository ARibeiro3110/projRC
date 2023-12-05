#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include "common.h"

int is_port_no(char* ASport) {
    return 0 < atoi(ASport) && atoi(ASport) <= 99999;
}