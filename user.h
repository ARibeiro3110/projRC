#ifndef __USER_H__
#define __USER_H__

/* Returns 1 if the string is a valid IPv4 address and 0 otherwise */
int is_ipv4(char *ASIP);

/* Assigns ASIP and ASport values according to the given input */
void handle_main_arguments(int argc, char **argv, char *ASIP, char *ASport);

/* Opens a udp socket, sends the provided message and writes the server answer onto the buffer */
void sendrec_udp_socket(char *message, char *buffer, int buffer_size, char *ASIP, char *ASport);

/* Handles login server responses */
int handle_login_response(char *status, char *buffer);

/* Registers the user into the system or logs him in */
int login(int logged_in, char *uid, char *password, char *ASIP, char *ASport);

/* Handles logout server responses */
int handle_logout_response(char *status, char *buffer);

/* Logs the user of the current session out */
int logout(char *uid, char *password, char *ASIP, char *ASport);

/* Handles unregister server responses */
int handle_unregister_response(char *status, char *buffer);

/* Unregisters the user from the service */
int unregister(char *uid, char *password, char *ASIP, char *ASport);

/* Handles open_auction server responses */
void handle_open_auction_response(char *status, char *aid, char *buffer);

/* Connects to the server through tcp and sends the provided message */
void connsend_tcp_socket(char *message, int fd, struct addrinfo *res, char *ASIP, char *ASport);

/* Transfers data from file to socket */
void write_from_file_to_socket(int file_fd, char *buffer, int fd, struct addrinfo *res);

/* Opens an auction */
void open_auction(char *uid, char *password, char *name, char *asset_fname, 
                  char *start_value, char *timeactive, char *ASIP, char *ASport);

/* Handles close_auction server responses */
void handle_close_auction_response(char *status, char *aid, char *uid, char *buffer);

/* Closes an opened auction */
void close_auction(char *uid, char *password, char *aid, char *ASIP, char *ASport);

/* Handles and prints responses with aid and state pairs (myauctions, mybids, list) */
void print_aid_state(char *auction_list);

/* Handles myauctions server responses */
void handle_myauctions_response(char *status, char *buffer, char *auction_list);

/* Shows the auctions created by the currently logged in user */
void myauctions(char *uid, char *ASIP, char *ASport);

/* Handles mybids server responses */
void handle_mybids_reponse(char *status, char *buffer, char *auction_list);

/* Shows the bids made by the currently logged in user */
void mybids(char *uid, char *ASIP, char *ASport);

/* Handles list server responses */
void handle_list_response(char *status, char *buffer, char *auction_list);

/* Lists all auctions in the system */
void list(char *ASIP, char *ASport);

/* Handles show_asset server responses */
void handle_show_asset_response(char *status, char *fname, char *fsize, int fd, struct addrinfo *res);

/* Transfers the asset of the auction to the local computer */
void show_asset(char *aid, char *ASIP, char *ASport);

/* Handles show_asset server responses */
void handle_bid_response(char *status, char *aid , char *response);

/* Makes a bid on auction number aid*/
void bid(char *uid, char *password, char *aid, char *value, char *ASIP, char *ASport);

/* Verifies if the terminator exists in show_record server response */
int verify_terminator(int bid, int closed, char *buffer, long auction_info_size, long bid_info_size, long closed_info_size);

/* Handles and prints bids */
int handle_bids(char *bid_info);

/* Handles and prints closure information */
int handle_closed(char *closed_info);

/* Shows the record of auction number aid */
void show_record(char *args, char *ASIP, char *ASport);

/* Exits the program closing the socket and freeing res */
void exit_error(int fd, struct addrinfo *res);

#endif