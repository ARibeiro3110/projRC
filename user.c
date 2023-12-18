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
#include <errno.h>
#include <signal.h>

#include "common.h"
#include "user.h"

// GLOBAL VARIABLE: used to prevent the user from shutting the app without logging out
int logged_in = 0;

void sigint_detected(int sig) {
    // In some systems, after the handler call the signal gets reverted
    // to SIG_DFL (the default action associated with the signal).
    // So we set the signal handler back to our function after each trap.

    if (sig == SIGINT) {
        if (signal(SIGINT, sigint_detected) != SIG_ERR) {
            if (logged_in)
                write(0, "\nWARNING: Please log out before exiting.\n> ", 44);
            else {
                printf("\nSIGINT DETECTED, SHUTTING DOWN...\n");
                exit(0);
            }
        }
        return;
    }
}

void handle_main_arguments(int argc, char **argv, char *ASIP, char *ASport) {
    switch (argc) {
    case 1:          // all arguments are omitted
        strcpy(ASIP, DEFAULT_IP);
        strcpy(ASport, DEFAULT_PORT);
        break;

    case 3:          // one of the arguments is omitted
        if (!strcmp(argv[1], "-n")) {
            strcpy(ASIP, argv[2]);
            strcpy(ASport, DEFAULT_PORT);
        }

        else if (!strcmp(argv[1], "-p")) {
            if (!is_port_no(argv[2])) {
                fprintf(stderr, "usage: ASport needs to be a valid port number\n");
                exit(1);
            }

            strcpy(ASport, argv[2]);
            strcpy(ASIP, DEFAULT_IP);
        }

        else {
            fprintf(stderr, "usage: user [-n ASIP] [-p ASport]\n");
            exit(1);
        }

        break;

    case 5:          // all arguments are present
        if (!strcmp(argv[1], "-n") && !strcmp(argv[3], "-p")) {
            if (!is_port_no(argv[4])) {
                fprintf(stderr, "usage: ASport needs to be a valid port number\n");
                exit(1);
            }

            strcpy(ASIP, argv[2]);
            strcpy(ASport, argv[4]);
        }

        else if (!strcmp(argv[1], "-p") && !strcmp(argv[3], "-n")) {
            if (!is_port_no(argv[2])) {
                fprintf(stderr, "usage: ASport needs to be a valid port number\n");
                exit(1);
            }

            strcpy(ASport, argv[2]);
            strcpy(ASIP, argv[4]);
        }

        else {
            fprintf(stderr, "usage: user [-n ASIP] [-p ASport]\n");
            exit(1);
        }
        break;

    default:
        fprintf(stderr, "usage: user [-n ASIP] [-p ASport]\n");
        exit(1);
    }
}

int sendrec_udp_socket(char *message, char *buffer, int buffer_size, char *ASIP, char *ASport) {
    int fd, errcode;
    struct addrinfo hints, *res;
    struct sockaddr_in addr;

    // open UDP socket
    fd = socket(AF_INET, SOCK_DGRAM, 0); // UDP socket
    if (fd == -1) {  /*error*/
        fprintf(stderr, "ERROR: socket creation was not sucessful\n");
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket

    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 seconds timeout
    timeout.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        fprintf(stderr, "ERROR: socket timeout creation was not sucessful\n");
        close(fd);
        exit(1);
    }

    errcode = getaddrinfo(ASIP, ASport, &hints, &res);
    if (errcode != 0) {  /*error*/
        fprintf(stderr, "ERROR: server not found\n");
        exit_error(fd, res);
    }

    // Send message
    ssize_t n = sendto(fd, message, strlen(message), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/
        fprintf(stderr, "ERROR: UDP request failed\n");
        exit_error(fd, res);
    }

    // Receive response
    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, buffer_size, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            printf("Peer took too long to respond. Please try again later\n");
            return -1;
        }

        fprintf(stderr, "ERROR: UDP response failed\n");
        exit_error(fd, res);
    }

    freeaddrinfo(res);
    close(fd);

    return 1;
}

void read_user_input(char *args) {
    char c;
    int space_previous = 0, i = 0;
    while ((c = getchar()) != '\n') {
        if (space_previous && c != ' ') {
            space_previous = 0;
            if (i != 0)
                args[i++] = ' ';
            args[i++] = c;
        }

        else if (c == ' ')
            space_previous = 1;

        else
            args[i++] = c;
    }
    args[i] = '\0';
}

int handle_login_response(char *status, char *buffer) {
    int status_size = strlen(status);

    if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("Password is incorrect. Log in failed. Please try again.\n");

    else if (!strcmp(status, "REG") && buffer[7] == '\n') {
        printf("New user sucessfully created and logged in.\n");
        return 1;
    }

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (buffer[3] != ' ' || buffer[4 + status_size] != '\n'
             || strlen(buffer) - status_size != 5
             || buffer[5 + status_size] != '\0') {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (!strcmp(status, "OK") && buffer[6] == '\n') {
        printf("User logged in.\n");
        return 1;
    }

    else {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    return 0;
}

int login(int logged_in, char *uid, char *password, char *ASIP, char *ASport) {
    char args[17] = "";

    if (getchar() != ' ') {
        fprintf(stderr, "usage: login <UID: 6 digits> <password: 8 alphanumeric chars>\n");
        return 0;
    }

    read_user_input(args);

    if (args[6] != ' ') {
        fprintf(stderr, "usage: login <UID: 6 digits> <password: 8 alphanumeric chars>\n");
        return 0;
    }

    sscanf(args, "%6s %8s", uid, password);
    long length_password = strlen(password), length_uid = strlen(uid);

    if (length_uid != 6 || length_password != 8 || !is_alphanumeric(password)
        || !is_numeric(uid)) {
        fprintf(stderr, "usage: login <UID: 6 digits> <password: 8 alphanumeric chars>\n");
        return 0;
    }

    if (logged_in) {
        printf("WARNING: A user is already logged in. Please logout before logging in into another account.\n");
        return 0;
    }
    // LIN message always has 21 chars (3 for LIN, 6 for UID, 8 for password, 2
    // for spaces, 1 for \n and 1 for \0). Status message has at most 4 chars
    // (3 letters and one \0).
    char message[LIN_LOU_UNR_MESSAGE_SIZE] = "",
         buffer[RLI_RLO_RUR_MESSAGE_SIZE] = "", status[STATUS_SIZE] = "";
    sprintf(message, "LIN %s %s\n", uid, password);

    if (sendrec_udp_socket(message, buffer, RLI_RLO_RUR_MESSAGE_SIZE, ASIP, ASport) == -1)
        return 0;

    sscanf(buffer, "RLI %s\n", status);

    return handle_login_response(status, buffer);
}

int handle_logout_response(char *status, char *buffer) {
    int status_size = strlen(status);

    if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("User was not logged in. Logout failed.\n");

    else if (!strcmp(status, "UNR") && buffer[7] == '\n')
        printf("User is not registered.\n");

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (buffer[3] != ' ' || buffer[4 + status_size] != '\n'
             || strlen(buffer) - status_size != 5
             || buffer[5 + status_size] != '\0') {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (!strcmp(status, "OK") && buffer[6] == '\n') {
        printf("User logged out.\n");
        return 1;
    }

    else {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    return 0;
}

int logout(char *uid, char *password, char *ASIP, char *ASport) {
    // verifications are not necessary since the values for uid and password
    // were previously verified

    // LOU message always has 21 chars (3 for LIN, 6 for UID, 8 for password, 2
    // for spaces, 1 for \n and 1 for \0). Status message has at most 4 chars
    // (3 letters and one \0).
    char message[LIN_LOU_UNR_MESSAGE_SIZE] = "",
         buffer[RLI_RLO_RUR_MESSAGE_SIZE] = "", status[STATUS_SIZE] = "";
    sprintf(message, "LOU %s %s\n", uid, password);

    if (sendrec_udp_socket(message, buffer, RLI_RLO_RUR_MESSAGE_SIZE, ASIP, ASport) == -1)
        return 0;

    sscanf(buffer, "RLO %s\n", status);

    return handle_logout_response(status, buffer);
}

int handle_unregister_response(char *status, char *buffer) {
    int status_size = strlen(status);

    if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("User was not logged in. Unregistered failed.\n");

    else if (!strcmp(status, "UNR") && buffer[7] == '\n')
        printf("User is not registered.\n");

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (buffer[3] != ' ' || buffer[4 + status_size] != '\n'
             || strlen(buffer) - status_size != 5
             || buffer[5 + status_size] != '\0') {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (!strcmp(status, "OK") && buffer[6] == '\n') {
        printf("User unregistered.\n");
        return 1;
    }

    else {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    return 0;
}

int unregister(char *uid, char *password, char *ASIP, char *ASport) {
    // verifications are not necessary since the values for uid and password
    // were previously verified

    // UNR message always has 21 chars (3 for LIN, 6 for UID, 8 for password, 2
    // for spaces, 1 for \n and 1 for \0). Status message has at most 4 chars
    // (3 letters and one \0).
    char message[LIN_LOU_UNR_MESSAGE_SIZE] = "",
         buffer[RLI_RLO_RUR_MESSAGE_SIZE] = "", status[STATUS_SIZE] = "";
    sprintf(message, "UNR %s %s\n", uid, password);

    if (sendrec_udp_socket(message, buffer, RLI_RLO_RUR_MESSAGE_SIZE, ASIP, ASport) == -1)
        return 0;

    sscanf(buffer, "RUR %s\n", status);

    return handle_unregister_response(status, buffer);
}

void handle_open_auction_response(char *status, char *aid, char *buffer) {
    int status_size = strlen(status);

    if (!strcmp(buffer, "ERR\n")) {
        printf("Unexpected protocol message.\n");
        return;
    }

    else if (!strcmp(status, "ERR") && buffer[7] == '\n') {
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");
        return;
    }

    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("Auction could not be started or password was incorrect.\n");

    else if (!strcmp(status, "NLG") && buffer[7] == '\n')
        printf("User is not logged in.\n");

    else if (buffer[3] != ' ' || buffer[4 + status_size] != ' '
             || buffer[8 + status_size] != '\n'
             || strlen(buffer) - (3 + status_size) != 6) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (!strcmp(status, "OK") && (strlen(aid) != 3 || !is_numeric(aid))) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (!strcmp(status, "OK") && buffer[10] == '\n')
        printf("Auction %s was started.\n", aid);

    else {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }
}

void connsend_tcp_socket(char *message, int fd, struct addrinfo *res, char *ASIP, char *ASport) {
    int n = connect(fd, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/
        fprintf(stderr, "ERROR: connect to server failed\n");
        exit_error(fd, res);
    }

    int bytes_written = 0;
    while ((n = write(fd, &message[bytes_written], strlen(&message[bytes_written]))) != 0) {
        if (n == -1) { /*error*/
            fprintf(stderr, "ERROR: message write failed\n");
            exit_error(fd, res);
        }
        bytes_written += n;
    }
}

void open_auction(char *uid, char *password, char *name, char *asset_fname,
                  char *start_value, char *timeactive, char *ASIP, char *ASport) {
    // verifications are not necessary for uid and password fields since the
    // values for uid and password were previously verified

    if (strlen(name) > 10 || !is_auction_name(name) || !is_filename(asset_fname)
        || strlen(start_value) > 6 || !is_numeric(start_value)
        || strlen(timeactive) > 5 || !is_numeric(timeactive)) {
        fprintf(stderr, "usage: open <name: up to 10 alphanumeric chars> <asset_fname: up to 24 alphanumeric chars (plus '-','_', '.') with file extension> <start_value: up to 6 digits> <timeactive: up to 5 digits>\n");
        return;
    }

    // open tcp socket
    int fd = socket(AF_INET, SOCK_STREAM, 0); //TCP socket
    if (fd == -1) { //error
        fprintf(stderr, "ERROR: socket creation was not sucessful\n");
        exit(1);
    }

    struct addrinfo *res, hints;

    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 seconds timeout
    timeout.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        fprintf(stderr, "ERROR: socket timeout creation was not sucessful\n");
        close(fd);
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_STREAM; //TCP socket

    int errcode = getaddrinfo(ASIP, ASport, &hints, &res);
    if (errcode != 0) {  /*error*/
        fprintf(stderr, "ERROR: server not found\n");
        close(fd);
        exit(1);
    }

    char message[OPA_MESSAGE_SIZE] = "", buffer[BUFFER_DEFAULT] = "";

    FILE *file_fd = fopen(asset_fname, "r");

    if (file_fd == NULL && errno == 2) {
        printf("WARNING: File %s does not exist.\n", asset_fname);
        return;
    }

    long f_size = 0;

    // calculate the file size
    f_size = lseek(fileno(file_fd), 0, SEEK_END);
    lseek(fileno(file_fd), 0, SEEK_SET);   // reset pointer to beginning

    if (f_size == 0)
        printf("WARNING: %s file has no content\n", asset_fname);

    else {
        sprintf(message, "OPA %s %s %s %s %s %s %ld ", uid, password, name, start_value, timeactive, asset_fname, f_size);

        connsend_tcp_socket(message, fd, res, ASIP, ASport);
        send_asset(file_fd, fd);
        read_tcp_socket(fd, res, buffer, 12);

        char status[STATUS_SIZE], aid[AID_SIZE];
        sscanf(buffer, "ROA %3s %s\n", status, aid);

        handle_open_auction_response(status, aid, buffer);
    }

    fclose(file_fd);
    freeaddrinfo(res);
    close(fd);
}

void handle_close_auction_response(char *status, char *aid, char *uid, char *buffer) {
    int status_size = strlen(status);

    if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else if (!strcmp(status, "EAU") && buffer[7] == '\n')
        printf("Auction %s could not be found.\n", aid);

    else if (!strcmp(status, "NLG") && buffer[7] == '\n')
        printf("User is not logged in.\n");

    else if (!strcmp(status, "EOW") && buffer[7] == '\n')
        printf("Auction %s is not owned by %s.\n", aid, uid);

    else if (!strcmp(status, "END") && buffer[7] == '\n')
        printf("Auction %s has already finished.\n", aid);

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (buffer[3] != ' ' || buffer[4 + status_size] != '\n'
             || strlen(buffer) - status_size != 5) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (!strcmp(status, "OK") && buffer[6] == '\n')
        printf("Auction %s was closed.\n", aid);

    else {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }
}

void close_auction(char *uid, char *password, char *aid, char *ASIP, char *ASport) {
    if (strlen(aid) != 3 || !is_numeric(aid)) {
        fprintf(stderr, "usage: close <AID: 3 digits>\n");
        return;
    }

    // open tcp socket
    int fd = socket(AF_INET, SOCK_STREAM, 0); //TCP socket
    if (fd == -1) { //error
        fprintf(stderr, "ERROR: socket creation was not sucessful\n");
        exit(1);
    }

    struct addrinfo *res, hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_STREAM; //TCP socket

    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 seconds timeout
    timeout.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        fprintf(stderr, "ERROR: socket timeout creation was not sucessful\n");
        close(fd);
        exit(1);
    }

    int errcode = getaddrinfo(ASIP, ASport, &hints, &res);
    if (errcode != 0) {  /*error*/
        fprintf(stderr, "ERROR: server not found\n");
        exit_error(fd, res);
    }

    char message[CLS_MESSAGE_SIZE] = "", buffer[BUFFER_DEFAULT] = "";
    sprintf(message, "CLS %s %s %s\n", uid, password, aid);

    connsend_tcp_socket(message, fd, res, ASIP, ASport);
    read_tcp_socket(fd, res, buffer, 9);

    char status[STATUS_SIZE];
    sscanf(buffer, "RCL %s\n", status);

    handle_close_auction_response(status, aid, uid, buffer);

    freeaddrinfo(res);
    close(fd);
}

void print_aid_state(char *auction_list) {
    char aid[AID_SIZE], state[STATE_SIZE];

    // Each AID state pair has 6 chars (3 for AID, 1 for state and 1 for
    // space). While the string is not finished, we traverse the string 6 by
    // 6, extract the AID and the state from that section and print the section.
    for (int i = 0; auction_list[6*i] == ' '; i++) {
        sscanf(&auction_list[6*i + 1], "%3s %s", aid, state);
        if (auction_list[6*i + 4] != ' ') {
            fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
            exit(1);
        }

        if (strlen(aid) != 3 || !is_numeric(aid)) {
            fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
            exit(1);
        }

        if (!strcmp(state, "1"))
            printf("\"%s\" - active; ", aid);
        else if (!strcmp(state, "0"))
            printf("\"%s\" - closed; ", aid);
        else {
            fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
            exit(1);
        }
    }
}

void handle_myauctions_response(char *status, char *buffer, char *auction_list) {
    int status_size = strlen(status), auction_list_size = strlen(auction_list);

    if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else if (buffer[3] != ' ' || (auction_list_size != 0 && auction_list[0] != ' ')
             || strlen(buffer) - (status_size + auction_list_size) != 5
             || buffer[4 + status_size + auction_list_size] != '\n'
             || buffer[5 + status_size + auction_list_size] != '\0') {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("User has no ungoing auctions. Auctions listing failed.\n");

    else if (!strcmp(status, "NLG") && buffer[7] == '\n')
        printf("User is not logged in.\n");

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (!strcmp(status, "OK") && buffer[6 + auction_list_size] == '\n') {
        printf("List of user's auctions: ");
        print_aid_state(auction_list);
        printf("\n");
    }

    else {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }
}

void myauctions(char *uid, char *ASIP, char *ASport) {
    // verifications are not necessary since the value for uid and was
    // previously verified

    // LMA message always has 12 chars (3 for LMA, 6 for UID, 1 for spaces, 1
    // for \n and 1 for \0). Status message has at most 4 chars (3 letters and
    // one \0). Auction_list has at most 6001 chars (6 chars per auction * 1000
    // maximum auctions + 1 for for \0). Buffer has variable size, but at most
    // 6008 chars (3 for RMA + 1 for space + 2 for status + 6 chars per
    // auction * 1000 maximum auctions + 1 for \n + 1 for for \0)

    char message[LMA_LMB_MESSAGE_SIZE] = "", buffer[MAX_BUFFER_MA_MB_L] = "", status[STATUS_SIZE] = "",
        auction_list[MAX_AUCTION_LIST] = "";

    sprintf(message, "LMA %s\n", uid);

    if (sendrec_udp_socket(message, buffer, MAX_BUFFER_MA_MB_L, ASIP, ASport) == -1)
        return;

    // reads everything into auction_list until \n character
    sscanf(buffer, "RMA %3s%[^\n]", status, auction_list);

    if (strlen(auction_list) > 6000) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    handle_myauctions_response(status, buffer, auction_list);
}

void handle_mybids_reponse(char *status, char *buffer, char *auction_list) {
    int status_size = strlen(status), auction_list_size = strlen(auction_list);

    if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("User has no bids.\n");

    else if (!strcmp(status, "NLG") && buffer[7] == '\n')
        printf("User is not logged in.\n");

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (buffer[3] != ' ' || (auction_list_size != 0 && auction_list[0] != ' ')
             || strlen(buffer) - (status_size + auction_list_size) != 5
             || buffer[4 + status_size + auction_list_size] != '\n'
             || buffer[5 + status_size + auction_list_size] != '\0') {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (!strcmp(status, "OK") && buffer[6 + strlen(auction_list)] == '\n') {
        printf("List of user's bids: ");
        print_aid_state(auction_list);
        printf("\n");
    }

    else {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }
}

void mybids(char *uid, char *ASIP, char *ASport) {
    // verifications are not necessary since the value for uid and was
    // previously verified

    // LMB message always has 12 chars (3 for LMA, 6 for UID, 1 for spaces, 1
    // for \n and 1 for \0). Status message has at most 4 chars (3 letters and
    // one \0). Auction_list has at most 6001 chars (6 chars per auction * 1000
    // maximum auctions + 1 for for \0). Buffer has variable size, but at most
    // 6008 chars (3 for RMA + 1 for space + 2 for status + 6 chars per
    // auction * 1000 maximum auctions + 1 for \n + 1 for for \0)

    char message[LMA_LMB_MESSAGE_SIZE] = "", buffer[MAX_BUFFER_MA_MB_L] = "", status[STATUS_SIZE] = "",
         auction_list[MAX_AUCTION_LIST] = "";

    sprintf(message, "LMB %s\n", uid);

    if (sendrec_udp_socket(message, buffer, MAX_BUFFER_MA_MB_L, ASIP, ASport) == -1)
        return;

    // reads everything into auction_list until \n character
    sscanf(buffer, "RMB %3s%[^\n]", status, auction_list);

    if (strlen(auction_list) > 6000) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    handle_mybids_reponse(status, buffer, auction_list);
}

void handle_list_response(char *status, char *buffer, char *auction_list) {
    int status_size = strlen(status), auction_list_size = strlen(auction_list);

    if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("No auction was yet started.\n");

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (buffer[3] != ' ' || (auction_list_size != 0 && auction_list[0] != ' ')
             || strlen(buffer) - (status_size + auction_list_size) != 5
             || buffer[4 + status_size + auction_list_size] != '\n'
             || buffer[5 + status_size + auction_list_size] != '\0') {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (!strcmp(status, "OK") && buffer[6 + strlen(auction_list)] == '\n') {
        if (!strlen(auction_list)) {
            printf("No auctions are currently active.\n");
            return;
        }

        printf("List of the currently active auctions: ");
        print_aid_state(auction_list);
        printf("\n");
    }

    else {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }
}

void list(char *ASIP, char *ASport) {
    // LST message always has 5 chars. Status message has at most 4 chars (3
    // letters and one \0). Auction_list has at most 6002 chars (6 chars per
    // auction * 1000 maximum auctions + 1 for \n + 1 for for \0). Buffer has
    // variable size, but at most 6008 chars (3 for RLS + 1 for space + 2 for
    // status + 6 chars per auction * 1000 maximum auctions + 1 for \n + 1 for \0)

    char message[LST_MESSAGE_SIZE] = "LST\n", buffer[MAX_BUFFER_MA_MB_L] = "", status[STATUS_SIZE] = "",
         auction_list[MAX_AUCTION_LIST] = "";

    if (sendrec_udp_socket(message, buffer, MAX_BUFFER_MA_MB_L, ASIP, ASport) == -1)
        return;

    // reads everything into auction_list until \n character
    sscanf(buffer, "RLS %3s%[^\n]", status, auction_list);

    if (strlen(auction_list) > 6000) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    handle_list_response(status, buffer, auction_list);
}

void handle_show_asset_response(char *status, char *fname, char *fsize, int fd, struct addrinfo *res) {
    if (!strcmp(status, "OK")) {
        FILE *fp = fopen(fname, "w");
        if (fp == NULL) {
            fprintf(stderr, "ERROR: could not open file. ERRCODE %d\n", errno);
            return;
        }

        long size = atol(fsize);
        if (copy_from_socket_to_file(size, fd, res, fp) == -1) {
            fclose(fp);
            unlink(fname);
            return;
        }

        fclose(fp);

        printf("File %s of size %s was sucessfully created on your computer.\n", fname, fsize);
    }

    else if (!strcmp(status, "NOK"))
        printf("There is no file to be sent, or some problem occured.\n");

    else if (!strcmp(status, "ERR"))
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }
}

void show_asset(char *aid, char *ASIP, char *ASport) {
    if (strlen(aid) != 3 || !is_numeric(aid)) {
        fprintf(stderr, "usage: show_asset <AID: 3 digits>\n\t\bor sa <AID: 3 digits>\n");
        return;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0); //TCP socket
    if (fd == -1) { //error
        fprintf(stderr, "ERROR: socket creation was not sucessful\n");
        exit(1);
    }

    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 seconds timeout
    timeout.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        fprintf(stderr, "ERROR: socket timeout creation was not sucessful\n");
        close(fd);
        exit(1);
    }

    struct addrinfo *res, hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_STREAM; //TCP socket

    int errcode = getaddrinfo(ASIP, ASport, &hints, &res);
    if (errcode != 0) {  /*error*/
        fprintf(stderr, "ERROR: server not found\n");
        exit_error(fd, res);
    }

    char message[SAS_MESSAGE_SIZE] = "";
    sprintf(message, "SAS %s\n", aid);
    connsend_tcp_socket(message, fd, res, ASIP, ASport);

    int n, spaces = 0, bytes_read = 0;
    char prefix[RSA_PREFIX_SIZE], status[STATUS_SIZE], fname[FILENAME_SIZE] = "", fsize[FILESIZE_SIZE] = "";

    for (int i = 0; i < RSA_PREFIX_SIZE; i++) {
        n = read(fd, &prefix[i], 1);
        if (n == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                printf("Peer took too long to respond. Please try again later\n");
                return;
            }

            fprintf(stderr, "ERROR: show_asset read failed\n");
            return;
        }

        if (!strcmp(prefix, "ERR\n")) {
            printf("Unexpected protocol message.\n");
            return;
        }

        if (prefix[i] == ' ')
            spaces++;

        if (spaces == 4)
            break;

        bytes_read += n;
    }
    prefix[bytes_read + 1] = '\0';

    sscanf(prefix, "RSA %s %s %s ", status, fname, fsize);
    long status_size = strlen(status), fname_size = strlen(fname), fsize_size = strlen(fsize);

    if (prefix[3] != ' ' || prefix[4 + status_size] != ' '
        || prefix[5 + status_size + fname_size] != ' '
        || prefix[6 + status_size + fname_size + fsize_size] != ' ') {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    if (!is_filename(fname) || strlen(fsize) > 7 || !is_numeric(fsize)) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    handle_show_asset_response(status, fname, fsize, fd, res);
    close(fd);
}

void handle_bid_response(char *status, char *aid , char *response) {
    int status_size = strlen(status);

    if (!strcmp(response, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else if (!strcmp(status, "REF"))
        printf("Your bid was refused as a larger bid has already been placed.\n");

    else if (!strcmp(status, "ILG"))
        printf("You cannot bid on an auction you are hosting.\n");

    else if (!strcmp(status, "NOK"))
        printf("Auction %s is not active or user password is incorrect.\n", aid);

    else if (!strcmp(status, "NLG"))
        printf("User is not logged in.\n");

    else if (!strcmp(status, "ERR"))
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (response[3] != ' ' || response[4 + status_size] != '\n'
             || strlen(response) - status_size != 5) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (!strcmp(status, "ACC"))
        printf("Your bid was accepted.\n");

    else {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }
}

void bid(char *uid, char *password, char *aid, char *value, char *ASIP, char *ASport) {
    if (strlen(aid) != 3 || !is_numeric(aid) || strlen(value) > 6 || !is_numeric(value)) {
        fprintf(stderr, "usage: bid <AID: 3 digits> <value: up to 6 digits>\n");
        return;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0); //TCP socket
    if (fd == -1) { //error
        fprintf(stderr, "ERROR: socket creation was not sucessful\n");
        exit(1);
    }

    struct timeval timeout;
    timeout.tv_sec = 5;  // 5 seconds timeout
    timeout.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        fprintf(stderr, "ERROR: socket timeout creation was not sucessful\n");
        close(fd);
        exit(1);
    }

    struct addrinfo *res, hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; //IPv4
    hints.ai_socktype = SOCK_STREAM; //TCP socket

    int errcode = getaddrinfo(ASIP, ASport, &hints, &res);
    if (errcode != 0) {  /*error*/
        fprintf(stderr, "ERROR: server not found\n");
        exit_error(fd, res);
    }

    char message[BID_MESSAGE_SIZE] = "";
    sprintf(message, "BID %s %s %s %s\n", uid, password, aid, value);

    connsend_tcp_socket(message, fd, res, ASIP, ASport);

    char response[RBD_MESSAGE_SIZE] = "", status[STATUS_SIZE] = "";
    read_tcp_socket(fd, NULL, response, 9);

    sscanf(response, "RBD %3s", status);
    handle_bid_response(status, aid, response);

    freeaddrinfo(res);
    close(fd);
}

int verify_terminator(int bid, int closed, char *buffer, long auction_info_size, long bid_info_size, long closed_info_size) {
    if (bid == 1 && closed == 1 && (buffer[auction_info_size + bid_info_size + closed_info_size] != '\n'
        || buffer[auction_info_size + bid_info_size + closed_info_size + 1] != '\0')) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (bid == 0 && closed == 1 && (buffer[auction_info_size + 1 + closed_info_size] != '\n'
             || buffer[auction_info_size + 2 + closed_info_size] != '\0')) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (bid == 1 && closed == 0 && (buffer[auction_info_size + bid_info_size - 1] != '\n'
             || buffer[auction_info_size + bid_info_size] != '\0')) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (bid == 0 && closed == 0 && (buffer[auction_info_size] != '\n'
             || buffer[auction_info_size + 1] != '\0')) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }
    return 1;
}

int handle_bids(char *bid_info) {
    char bidder_uid[UID_SIZE] = "", bid_value[VALUE_SIZE] = "", bid_date[DATE_SIZE] = "",
         bid_time[TIME_SIZE] = "", bid_sec_time[SEC_SIZE] = "";
    int bid_info_length;

    if (bid_info[0] != ' ') {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    for (int i = 0; bid_info[i] == ' ' && strlen(&bid_info[i]) != 1; i += bid_info_length) {
        sscanf(&bid_info[i + 1], "B %6s %6s %10s %8s %s", bidder_uid, bid_value, bid_date, bid_time, bid_sec_time);

        long bid_value_size = strlen(bid_value);

        if (bid_info[i + 2] != ' ' || bid_info[i + 9] != ' ' || bid_info[i + 10 + bid_value_size] != ' '
            || bid_info[i + 21 + bid_value_size] != ' ' || bid_info[i + 30 + bid_value_size] != ' ') {
            fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
            exit(1);
        }

        if (strlen(bidder_uid) != 6 || !is_numeric(bidder_uid)
            || bid_value_size > 6 || !is_numeric(bid_value)
            || !is_date(bid_date) || !is_time(bid_time)
            || strlen(bid_sec_time) > 5 || !is_numeric(bid_sec_time)) {
            fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
            exit(1);
        }

        // 7 is for the 'B' and the spaces
        bid_info_length = 7 + strlen(bidder_uid) + strlen(bid_value) + strlen(bid_date) + strlen(bid_time) + strlen(bid_sec_time);
        printf("\t\bbid: user: %s, value=%s, %s %s, %s\n", bidder_uid, bid_value, bid_date, bid_time, bid_sec_time);
    }
    return 1;
}

int handle_closed(char *closed_info) {
    char end_date[DATE_SIZE] = "", end_time[TIME_SIZE] = "", end_sec_time[SEC_SIZE] = "";
    sscanf(closed_info, "E %10s %8s %s\n", end_date, end_time, end_sec_time);

    if (closed_info[1] != ' ' || closed_info[12] != ' ' || closed_info[21] != ' ' ) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    if (!is_date(end_date) || !is_time(end_time)
        || strlen(end_sec_time) > 5 || !is_numeric(end_sec_time)) {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    printf("closed: %s %s, %s\n", end_date, end_time, end_sec_time);

    return 1;
}

void show_record(char *aid, char *ASIP, char *ASport) {
    if (strlen(aid) != 3 || !is_numeric(aid)) {
        fprintf(stderr, "usage: show_record <AID: 3 digits>\n\t\bor sr <AID: 3 digits>\n");
        return;
    }

    // SRC message always has 9 chars (3 for SRC, 3 for AID, 1 for spaces, 1
    // for \n and 1 for \0). Status message has at most 4 chars (3 letters and
    // one \0). bid_info has at most 2102 chars ((1+1+6+1+6+1+10+1+8+1+5)*50 for
    // the bids + 1 for initial \n + 1 for \0). closed_info has at most 28 chars
    // (27 for info + 1 for \0). buffer has at most 2213 chars (3 for RRC + 2
    // for status + 6 for host_uid + 10 for auction_name + 24 for asset_fname +
    // 6 for start_value + 10 for start_date + 8 for start_time + 5 for timeactive
    // + 2102 from bid_info + 28 chars).

    char message[SRC_MESSAGE_SIZE] = "", buffer[SRC_BUFFER_SIZE] = "",
         status[STATUS_SIZE] = "", host_uid[UID_SIZE] = "",
         auction_name[NAME_SIZE] = "", asset_fname[FILENAME_SIZE] = "",
         start_value[VALUE_SIZE] = "", start_date[DATE_SIZE] = "",
         start_time[TIME_SIZE] = "", timeactive[SEC_SIZE] = "",
         bid_info[BID_INFO_SIZE] = "", closed_info[CLOSED_INFO_SIZE] = "";
    sprintf(message, "SRC %s\n", aid);

    if (sendrec_udp_socket(message, buffer, SRC_BUFFER_SIZE, ASIP, ASport) == -1)
        return;

    // Using this format, bid_info will always have a \n at the beginning. If
    // no bids were specified and if we used another format which matched the \n
    // at the end of the owner info, the %[^E] part of the string would read
    // nothing. In turn, this would prevent the closed_info to read any
    // information. On the contrary, if we keep the \n unmatched, %[^E] will
    // always match at least with one character (\n), which allows closed_info
    // to read the rest of the string.
    sscanf(buffer, "RRC %3s %6s %10s %24s %6s %10s %8s %5s%2101[^E]%[^\n]",
            status, host_uid, auction_name, asset_fname, start_value,
            start_date, start_time, timeactive, bid_info, closed_info);

    if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("Auction with AID %s does not exist.\n", aid);

    else if (buffer[3] != ' ') {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }

    else if (!strcmp(status, "OK")) {
        long auction_name_size = strlen(auction_name), asset_fname_size = strlen(asset_fname),
             start_value_size = strlen(start_value), timeactive_size = strlen(timeactive);

        if (strlen(host_uid) != 6 || !is_numeric(host_uid) || auction_name_size > 10
            || !is_auction_name(auction_name) || !is_filename(asset_fname)
            || start_value_size > 6 || !is_numeric(start_value)
            || !is_date(start_date) || !is_time(start_time) || strlen(timeactive) > 5
            || !is_numeric(timeactive) || strlen(closed_info) > 27) {
            fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
            exit(1);
        }

        // when there is closure information, \n is not part of the strings so to
        // make the calculations work, we have to add 1
        int tmp = strlen(closed_info);
        if (tmp)
            tmp += 1;

        if (strlen(buffer) - (26 + auction_name_size + asset_fname_size
            + start_value_size + timeactive_size + strlen(bid_info) + tmp) != 11){
            fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
            exit(1);
        }

        int bid = strlen(bid_info) - 1 != 0, closed = strlen(closed_info) != 0;
        long auction_info_size = 37 + strlen(auction_name) + strlen(asset_fname) + strlen(start_value) + strlen(timeactive);
        long bid_info_size = strlen(bid_info);
        long closed_info_size = strlen(closed_info);
        if (!verify_terminator(bid, closed, buffer, auction_info_size, bid_info_size, closed_info_size))
            return;

        if (buffer[6] != ' ' || buffer[13] != ' ' || buffer[14 + auction_name_size] != ' '
            || buffer[15 + auction_name_size + asset_fname_size] != ' '
            || buffer[16 + auction_name_size + asset_fname_size + start_value_size] != ' '
            || buffer[27 + auction_name_size + asset_fname_size + start_value_size] != ' '
            || buffer[36 + auction_name_size + asset_fname_size + start_value_size] != ' ') {
            fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
            exit(1);
        }

        printf("owner: %s, %s, %s, value=%s, %s %s, timeactive: %s\n", host_uid,
               auction_name, asset_fname, start_value, start_date, start_time,
               timeactive);

        if (bid)
            if (!handle_bids(bid_info))
                return;

        if (closed)
            if (!handle_closed(closed_info))
                return;
    }

    else {
        fprintf(stderr, "ERROR: server sent wrong protocol message.\n");
        exit(1);
    }
}

int main(int argc, char **argv) {
    char ASIP[ASIP_SIZE] = "", ASport[ASPORT_SIZE] = "";
    handle_main_arguments(argc, argv, ASIP, ASport);

    char command[COMMAND_SIZE] = "", args[MAX_ARGS] = "", uid[UID_SIZE] = "", password[PASSWORD_SIZE] = "", aid[AID_SIZE + 1] = "";

    signal(SIGINT, sigint_detected);

    printf("Input your command:\n");

    while (1) {
        printf("> ");
        scanf("%s", command);

        if (!strcmp(command, "login")) {
            if (login(logged_in, uid, password, ASIP, ASport))
                logged_in = 1;
        }

        else if (!strcmp(command, "logout")) {
            if (logged_in) {
                if (logout(uid, password, ASIP, ASport))
                    logged_in = 0;
            }

            else
                printf("WARNING: No user is logged in. Please log in before logging out.\n");
        }

        else if (!strcmp(command, "unregister")) {
            if (logged_in) {
                if (unregister(uid, password, ASIP, ASport))
                    logged_in = 0;
            }

            else
                printf("WARNING: No user is logged in. Please log in before unregistering.\n");
        }

        else if (!strcmp(command, "open")) {
            if (getchar() != ' ') {
                fprintf(stderr, "usage: open <name: up to 10 alphanumeric chars> <asset_fname: up to 24 alphanumeric chars (plus '-','_', '.') with file extension> <start_value: up to 6 digits> <timeactive: up to 5 digits>\n");
            }

            else {
                char name[NAME_SIZE] = "", asset_fname[FILENAME_SIZE] = "", start_value[VALUE_SIZE] = "",
                     timeactive[SEC_SIZE] = "";
                read_user_input(args);
                sscanf(args, "%s %s %s %s\n", name, asset_fname, start_value, timeactive);

                if (logged_in)
                    open_auction(uid, password, name, asset_fname, start_value, timeactive, ASIP, ASport);

                else
                    printf("WARNING: No user is logged in. Please log in before requesting auction opening.\n");
            }
        }

        else if (!strcmp(command, "close")) {
            if (getchar() != ' ') {
                fprintf(stderr, "usage: close <AID: 3 digits>\n");
            }

            else {
                read_user_input(aid);

                if (logged_in)
                    close_auction(uid, password, aid, ASIP, ASport);

                else
                    printf("WARNING: No user is logged in. Please log in before requesting auction closure.\n");
            }
        }

        else if (!strcmp(command, "myauctions") || !strcmp(command, "ma")) {
            if (logged_in)
                myauctions(uid, ASIP, ASport);

            else
                printf("WARNING: No user is logged in. Please log in before requesting auction listing.\n");
        }

        else if (!strcmp(command, "mybids") || !strcmp(command, "mb"))
            if (logged_in)
                mybids(uid, ASIP, ASport);

            else
                printf("WARNING: No user is logged in. Please log in before requesting bid listing.\n");

        else if (!strcmp(command, "list") || !strcmp(command, "l"))
            list(ASIP, ASport);

        else if (!strcmp(command, "show_asset") || !strcmp(command, "sa")) {
            if (getchar() != ' ') {
                fprintf(stderr, "usage: show_asset <AID: 3 digits>\n\t\bor sa <AID: 3 digits>\n");
            }

            else {
                read_user_input(aid);
                show_asset(aid, ASIP, ASport);
            }
        }

        else if (!strcmp(command, "bid") || !strcmp(command, "b"))
            if (logged_in) {
                if (getchar() != ' ') {
                    fprintf(stderr, "usage: bid <AID: 3 digits> <value: up to 6 digits>\n");
                }

                else {
                    char value[VALUE_SIZE];
                    read_user_input(args);
                    sscanf(args, "%3s %s\n", aid, value);
                    bid(uid, password, aid, value, ASIP, ASport);
                }
            }

            else
                printf("WARNING: No user is logged in. Please log in before requesting bid.\n");

        else if (!strcmp(command, "show_record") || !strcmp(command, "sr")) {
            if (getchar() != ' ') {
                fprintf(stderr, "usage: show_record <AID: 3 digits>\n\t\bor sr <AID: 3 digits>\n");
            }

            else {
                read_user_input(aid);
                show_record(aid, ASIP, ASport);
            }
        }

        else if (!strcmp(command, "exit")) {
            if (logged_in)
                printf("WARNING: Please log out before exiting.\n");
            else
                exit(0);
        }

        else {
            printf("Command not found. Please try again\n");
            while (getchar() != '\n');  // flushes the rest of the input
        }
    }

    return 0;
}