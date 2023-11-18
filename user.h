#ifndef __USER_H__
#define __USER_H__

/* Calculates the order of magnitude of a number (number of digits) */
int order_of_magnitude(int number);

/* Returns 1 if the string is only composed of alphanumeric characters and 0 otherwise */
int is_alphanumeric(char* word);

/* Assigns ASIP and ASport values according to the given input */
void handle_arguments(int argc, char **argv, char *ASIP, char *ASport);

/* Registers the user into the system or logs him in */
void login(int uid, char *password, int fd, struct addrinfo *res, struct sockaddr_in addr);

/* Logs the user of the current session out */
void logout(int uid, char *password, int fd, struct addrinfo *res, struct sockaddr_in addr);

void unregister(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void open_auction(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void close_auction(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void myauctions(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void mybids(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void list(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void show_asset(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void bid(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void show_record(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

void exit_user(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr);

#endif