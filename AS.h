#ifndef __AS_H__
#define __AS_H__

/* Tries to lock the semaphore, exiting if failed */
void sem_wait_(sem_t *sem);

/* Tries to unlock the semaphore, exiting if failed */
void sem_post_(sem_t *sem);

/* Sets up the ASDIR, AUCTIONS AND USERS directories if they do not exist*/
void setup_environment();

/* Assigns ASport and verbose values according to the given input */
void handle_main_arguments(int argc, char **argv, char *ASport, int *verbose);

/* Handles udp client requests and forwards request to the adequate handler */
void handle_udp_request(int fd_udp, struct sockaddr_in addr_udp, int verbose);

/* Handles login requests */
void handle_login_request(char *uid, char *user_password, int fd,
                          struct sockaddr_in addr, int verbose);

/* Handles logout requests */
void handle_logout_request(char *uid, char *user_password, int fd,
                           struct sockaddr_in addr, int verbose);

/* Handles unregister requests */
void handle_unregister_request(char *uid, char *user_password, int fd,
                               struct sockaddr_in addr, int verbose);

/* Handles myauctions requests */
void handle_myauctions_request(char *uid, int fd, struct sockaddr_in addr,
                               int verbose);

/* Handles mybids requests */
void handle_mybids_request(char *uid, int fd, struct sockaddr_in addr,
                           int verbose);

/* Handles list requests */
void handle_list_request(int fd, struct sockaddr_in addr, int verbose);

/* Handles show_record requests */
void handle_show_record_request(char *aid, int fd, struct sockaddr_in addr,
                                int verbose);

/* Handles tcp client requests and forwards request to the adequate handler */
void handle_tcp_request(int fd_tcp, struct sockaddr_in addr_tcp, int verbose);

/* Handles open_auction requests */
void handle_open_auction_request(int newfd, char *uid, char *password,
                                 char *name, char *start_value, char *timeactive,
                                 char *asset_fname, long f_size, int verbose);

/* Handles close_auction requests */
void handle_close_auction_request(int newfd, char *uid, char *user_password,
                                  char *aid, int verbose);

/* Handles show_asset requests */
void handle_show_asset_request(int newfd, char *aid, int verbose);

/* Handles bid requests */
void handle_bid_request(int newfd, char *uid, char *user_password,
                        char *aid, char *value, int verbose);

/* Sends ERR message to udp client */
void send_udp_ERR(int fd, struct sockaddr_in addr, int verbose);

/* Sends ERR message to udp client according to a given prefix */
void send_udp_response_ERR(char *prefix, int fd, struct sockaddr_in addr,
                           int verbose);

/* Sends udp response to client request */
void send_udp_response(char *response, int fd, struct sockaddr_in addr);

/* Sends tcp response to client request */
void send_tcp_response(char *response, int fd);

/* Sends ERR message to tcp client */
void send_tcp_ERR(int fd, int verbose);

/* Sends ERR message to tcp client according to a given prefix */
void send_tcp_response_ERR(char *prefix, int fd, int verbose);

/* Returns 1 if file exists and 0 otherwise */
int exists_file(char *path);

/* Returns 1 if directory exists and 0 otherwise */
int exists_dir(char *path);

/* Creates _pass.txt file */
void create_password(char *uid, char *password);

/* Creates _login.txt file */
void create_login(char *uid);

/* Creates START_X.txt file */
void create_start(int aid, char *uid, char *name, char *asset_fname,
                  char *start_value, char *timeactive);

/* Receives asset through the socket and stores it locally */
int store_asset(int fd, int aid, char *asset_fname, long f_size);

/* Creates auction file in hosted section of the database */
void create_hosted(char *uid, int aid);

/* Creates END_X.txt file */
int create_close(char *end_file_path, char *start_file_path);

/* Returns 1 if auction duration has expired and 0 otherwise */
int auction_duration_has_expired(char *aid, char *start_file_path);

/* Appends auctions to response string for my_auctions and my_bids functions */
void append_auctions(char *response, struct dirent **filelist, int n_entries);

/* Appends auctions to response string for list function */
void append_auctions_list(char *response, struct dirent **filelist,
                          int n_entries);

/* Gets bid history for show_record function and writes it to bid_info */
int get_bid_list(char *bid_info, char *aid);

/* Gets closure information for show_record function and writes it to closed_info */
int get_closed_info(char *closed_info, char *aid);

/* Calculates the size of an asset */
long asset_fsize(char *fname);

/* Reads and sends asset through the socket to the client */
void send_asset(FILE *file_fd, int fd);

/* Creates bid file in bids section of the database */
void create_bid(int highest_bid, char *aid, char *uid);

/* Creates bid file in bidded section of the database */
void create_bidded(char *uid, char *aid);

/* Attempts to bid on an existing auction */
void attempt_bid(char *aid, char *uid, char *value, char *response, int verbose);

#endif