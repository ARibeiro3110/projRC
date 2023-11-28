#ifndef __USER_H__
#define __USER_H__

/* Returns 1 if the string is only composed of digits and 0 otherwise */
int is_numeric(char *word);

/* Returns 1 if the string is only composed of alphanumeric characters and 0 otherwise */
int is_alphanumeric(char* word);

/* Assigns ASIP and ASport values according to the given input */
void handle_arguments(int argc, char **argv, char *ASIP, char *ASport);

/* Registers the user into the system or logs him in */
int login(char *uid, char *password, int fd, struct addrinfo *res, struct sockaddr_in addr);

/* Logs the user of the current session out */
void logout(char *uid, char *password, int fd, struct addrinfo *res, struct sockaddr_in addr);

void unregister(char *uid, char *password, int fd, struct addrinfo *res, struct sockaddr_in addr);

void open_auction(char *uid, char *password, char *name, char *asset_fname, char *start_value, char *timeactive, int fd, struct addrinfo *res, struct sockaddr_in addr);

void close_auction(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void myauctions(char *uid, int fd, struct addrinfo *res, struct sockaddr_in addr);

void mybids(char *uid, int fd, struct addrinfo *res, struct sockaddr_in addr);

void list(int fd, struct addrinfo *res, struct sockaddr_in addr);

void show_asset(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void bid(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void show_record(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void exit_user(int exit_status, int fd, struct addrinfo *res);

#endif