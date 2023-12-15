#ifndef __COMMON_H__
#define __COMMON_H__

#define DEFAULT_IP                   "localhost"
#define DEFAULT_PORT                 "58046"   // 58000 + 46 (group number)

#define LIN_LOU_UNR_MESSAGE_SIZE     21
#define RLI_RLO_RUR_MESSAGE_SIZE     9
#define MESSAGE_TYPE_SIZE            4
#define STATUS_SIZE                  4
#define AID_SIZE                     4
#define OPA_MESSAGE_SIZE             78
#define BUFFER_DEFAULT               4096
#define CLS_MESSAGE_SIZE             25
#define STATE_SIZE                   2
#define LMA_LMB_MESSAGE_SIZE         12
#define LST_MESSAGE_SIZE             5
#define SAS_MESSAGE_SIZE             9
#define RSA_PREFIX_SIZE              40
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
#define FILESIZE_SIZE                8
#define BID_INFO_SIZE                2102
#define CLOSED_INFO_SIZE             28
#define MAX_BUFFER_MA_MB_L           6008
#define MAX_AUCTION_LIST             6001
#define COMMAND_SIZE                 12
#define MAX_ARGS                     54
#define PASSWORD_SIZE                9
#define ASIP_SIZE                    16
#define ASPORT_SIZE                  6

void exit_error(int fd, struct addrinfo *res);

/* Returns 1 if the string is a valid port number and 0 otherwise */
int is_port_no(char* ASport);

/* Returns 1 if the string is only composed of digits and 0 otherwise */
int is_numeric(char *word);

/* Returns 1 if the string is only composed of alphanumeric characters and 0 otherwise */
int is_alphanumeric(char* word);

/* Returns 1 if the string is an auction name and 0 otherwise */
int is_auction_name(char *word);

/* Returns 1 if the string represents a filename and 0 otherwise */
int is_filename(char *word);

/* Returns 1 if the string represents a date and 0 otherwise */
int is_date(char *word);

/* Returns 1 if the string represents a time and 0 otherwise */
int is_time(char *word);

/* Copies data from a socket to a given file (fp) */
int copy_from_socket_to_file(int size, int fd, struct addrinfo *res, FILE *fp);

/* Sends asset through the socket */
void send_asset(FILE *file_fd, int fd);

/* Calculates the order of magnitude of a number */
int OoM(long number);

#endif