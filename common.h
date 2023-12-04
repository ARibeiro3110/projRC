#ifndef __COMMON_H__
#define __COMMON_H__

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

#define DEFAULT_IP                   "localhost"
#define DEFAULT_PORT                 "58046"   // 58000 + 46 (group number)

#define LIN_LOU_UNR_MESSAGE_SIZE     21
#define RLI_RLO_RUR_MESSAGE_SIZE     9
#define STATUS_SIZE                  4
#define AID_SIZE                     4
#define OPA_MESSAGE_SIZE             78
#define BUFFER_DEFAULT               128
#define CLS_MESSAGE_SIZE             25
#define STATE_SIZE                   2
#define LMA_LMB_MESSAGE_SIZE         12
#define LST_MESSAGE_SIZE             5
#define SAS_MESSAGE_SIZE             9
#define RSA_PREFIX_SIZE              8
#define BID_MESSAGE_SIZE             32
#define RBD_MESSAGE_SIZE             8
#define UID_SIZE                     7
#define VALUE_SIZE                   7
#define DATE_SIZE                    11
#define TIME_SIZE                    9
#define SEC_SIZE                     6
#define SRC_MESSAGE_SIZE             9
#define SRC_BUFFER_SIZE              2213
#define NAME_SIZE                    11
#define FILENAME_SIZE                25
#define BID_INFO_SIZE                2102
#define CLOSED_INFO_SIZE             28
#define MAX_BUFFER_MA_MB_L           6008
#define MAX_AUCTION_LIST             6001
#define COMMAND_SIZE                 12
#define MAX_ARGS                     54
#define PASSWORD_SIZE                9
#define ASIP_SIZE                    16
#define ASPORT_SIZE                  6

/* Returns 1 if the string is a valid port number and 0 otherwise */
int is_port_no(char* ASport);

#endif