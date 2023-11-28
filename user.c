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

#include "user.h"

#define DEFAULT_IP "localhost"
#define DEFAULT_PORT "58046"   // 58000 + 46 (group number)

#define MAX_BUFFER_MA_MB_L   6008
#define MAX_AUCTION_LIST     6001

int is_numeric(char *word) {
    int l = strlen(word);
    for (int i = 0; i < l; i++)
        if ('0' > word[i] || word[i] > '9')
            return 0;
    return 1;
}

int is_alphanumeric(char *word) {
    int l = strlen(word);
    for (int i = 0; i < l; i++)
        if (!('0' <= word[i] <= '9' || 'A' <= word[i] <= 'Z' || 'a' <= word[i] <= 'z'))
            return 0;
    return 1;
}

int is_filename(char *word) {
    int l = strlen(word);

    if (l > 24)
        return 0;

    for (int i = 0; i < l; i++) {
        if (!('0' <= word[i] <= '9' || 'A' <= word[i] <= 'Z' 
              || 'a' <= word[i] <= 'z' || word[i] == '-' 
              || word[i] == '_' || word[i] == '.'))
            return 0;
        
        if (i == l - 4 && word[i] != '.')
            return 0;
        
        if (i > l - 4 && ('a' > word[i] || word[i] > 'z' || '0' > word[i] || word[i] > '9'))
            return 0;
    }
    return 1;
}

int is_date(char *word) {
    int l = strlen(word);

    if (l != 10)
        return 0;

    for (int i = 0; i < l; i++) {   // YYYY-MM-DD
        if ((i == 4 || i == 7) && word[i] != '-')
            return 0;
        else if (i != 4 && i != 7 && ('0' > word[i] || word[i] > '9'))
            return 0;
    }

    int year, month, day;
    sscanf(word, "%4d-%2d-%2d", &year, &month, &day);

    if (year >= 0) 
        if (1 <= month <=12) {
            if ((1 <= day <= 31) && (month == 1 || month == 3 || month == 5 || month == 7 || month == 8 || month == 10 || month == 12))
                return 1;
            else if ((1 <= day <= 30) && (month == 4 || month == 6 || month == 9 || month == 11))
                return 1;
            else if ((1 <= day <= 28) && month == 2)
                return 1;
            else if (day == 29 && month == 2 && (year % 400 == 0 ||(year % 4 == 0 && year % 100 != 0)))
                return 1;
            else
                return 0;
        }
        else
            return 0;
    else
        return 0;
    return 1;
}

int is_time(char *word) {
    int l = strlen(word);

    if (l != 8)
        return 0;

    for (int i = 0; i < l; i++) {
        if ((i == 2 || i == 5) && word[i] != ':')
            return 0;
        else if (i != 2 && i != 5 && ('0' > word[i] || word[i] > '9'))
            return 0;
    }

    int hours, minutes, seconds;
    sscanf(word, "%2d:%2d:%2d", &hours, &minutes, &seconds);

    if (0 > hours || hours > 24)
        return 0;
    if (0 > minutes || minutes > 60)
        return 0;
    if (0 > seconds || seconds > 60)
        return 0;

    return 1;
}

int is_ipv4(char *ASIP) {
    int ip_numbers[4];

    sscanf(ASIP, "%d.%d.%d.%d", &ip_numbers[0], &ip_numbers[1], &ip_numbers[2], &ip_numbers[3]);

    for (int i = 0; i < 4; i++)
        if (0 > ip_numbers[i] || ip_numbers[i] > 255)
            return 0;
    return 1;
}

int is_port_no(char* ASport) {
    return 0 < atoi(ASport) && atoi(ASport) <= 99999;
}

void handle_arguments(int argc, char **argv, char *ASIP, char *ASport) {
    switch (argc) {
    case 1:          // all arguments are omitted
        strcpy(ASIP, DEFAULT_IP); 
        strcpy(ASport, DEFAULT_PORT);
        break;

    case 3:          // one of the arguments is omitted
        if (!strcmp(argv[1], "-n")) {
            if (!is_ipv4(argv[2])) {
                fprintf(stderr, "usage: ASIP needs to follow the IPv4 format\n");
                exit(1);
            }

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
            if (!is_ipv4(argv[2])) {
                fprintf(stderr, "usage: ASIP needs to follow the IPv4 format\n");
                exit(1);
            }

            if (!is_port_no(argv[4])) {
                fprintf(stderr, "usage: ASport needs to be a valid port number\n");
                exit(1);
            }

            strcpy(ASIP, argv[2]);
            strcpy(ASport, argv[4]);
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

int login(char *uid, char *password, int fd, struct addrinfo *res, struct sockaddr_in addr) {     
    long length_password = strlen(password), length_uid = strlen(uid);
    
    if (length_uid != 6 || length_password != 8 || !is_alphanumeric(password) || !is_numeric(uid)) {
        fprintf(stderr, "usage: login <UID: 6 digits> <password: 8 alphanumeric chars>\n");
        if (length_uid > 6 || length_password > 8)
            while (getchar() != '\n');  // flushes the rest of the input
        return 0;
    }

    // LIN message always has 21 chars (3 for LIN, 6 for UID, 8 for password, 2 
    // for spaces, 1 for \n and 1 for \0). Status message has at most 4 chars 
    // (3 letters and one \0).
    char message[21], buffer[9], status[4];
    sprintf(message, "LIN %s %s\n", uid, password);

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: login request failed\n");
        exit_user(1, fd, res);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, 9, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: login response failed\n");
        exit_user(1, fd, res);
    }

    sscanf(buffer, "RLI %s\n", status);

    if (!strcmp(status, "OK") && buffer[6] == '\n') {
        printf("User logged in.\n");
        return 1;
    }
    
    else if (!strcmp(status, "NOK") && buffer[7] == '\n') {
        printf("Password is incorrect. Log in failed. Please try again.\n");
        return 0;
    }
    
    else if (!strcmp(status, "REG") && buffer[7] == '\n') {
        printf("New user sucessfully created and logged in.\n");
        return 1;
    }

    else if (!strcmp(status, "ERR") && buffer[7] == '\n') {
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");
        return 0;
    }
    
    else if (!strcmp(buffer, "ERR\n")) {
        printf("Unexpected protocol message.\n");
        return 0;
    }

    else {
        fprintf(stderr, "ERROR: Server sent unknown message.\n");
        return 0;
    }
}

void logout(char *uid, char *password, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    // verifications are not necessary since the values for uid and password 
    // were previously verified
    
    // LOU message always has 21 chars (3 for LIN, 6 for UID, 8 for password, 2 
    // for spaces, 1 for \n and 1 for \0). Status message has at most 4 chars 
    // (3 letters and one \0).
    char message[21], buffer[9], status[4];
    sprintf(message, "LOU %s %s\n", uid, password);

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: logout request failed\n");
        exit_user(1, fd, res);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, 9, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: logout response failed\n");
        exit_user(1, fd, res);
    }

    sscanf(buffer, "RLO %s\n", status);

    if (!strcmp(status, "OK") && buffer[6] == '\n')
        printf("User logged out.\n");
    
    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("User was not logged in. Logout failed.\n");
    
    else if (!strcmp(status, "UNR") && buffer[7] == '\n')
        printf("User is not registered.\n");

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else 
        fprintf(stderr, "ERROR: Server sent unknown message.\n");
}

void unregister(char *uid, char *password, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    // verifications are not necessary since the values for uid and password 
    // were previously verified
    
    // UNR message always has 21 chars (3 for LIN, 6 for UID, 8 for password, 2 
    // for spaces, 1 for \n and 1 for \0). Status message has at most 4 chars 
    // (3 letters and one \0). 
    char message[21], buffer[9], status[4];
    sprintf(message, "UNR %s %s\n", uid, password);

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: unregister request failed\n");
        exit_user(1, fd, res);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, 9, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: unregister response failed\n");
        exit_user(1, fd, res);
    }

    sscanf(buffer, "RUR %s\n", status);

    if (!strcmp(status, "OK") && buffer[6] == '\n')
        printf("User unregistered.\n");
    
    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("User was not logged in. Unregistered failed.\n");
    
    else if (!strcmp(status, "UNR") && buffer[7] == '\n')
        printf("User is not registered.\n");

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else 
        fprintf(stderr, "ERROR: Server sent unknown message.\n");
}

void open_auction(char *uid, char *password, char *name, char *asset_fname, 
                  char *start_value, char *timeactive, int fd, 
                  struct addrinfo *res, struct sockaddr_in addr) {
    if (strlen(name) > 10 || is_alphanumeric(name) || !is_filename(asset_fname) 
        || strlen(start_value) > 6 || !is_numeric(start_value) 
        || strlen(timeactive) > 5 || !is_numeric(timeactive)) {
        fprintf(stderr, "usage: open <name: up to 10 alphanumeric chars> <asset_fname: up to 24 alphanumeric chars (plus '-','_', '.') with file extension> <start_value: up to 6 digits> <timeactive: up to 5 digits>\n");
        return;
    }
    
    char message[21], buffer[128]; //TODO

    int file_fd = open("ABCDE.txt", O_RDONLY);
    long f_size = 0;

    // calculate the file size
    f_size = lseek(file_fd, 0, SEEK_END);
    lseek(file_fd, 0, SEEK_SET);   // reset pointer to beginning

    sprintf(message, "OPA %s %s %s %s %s %s %ld ", uid, password, name, start_value, timeactive, asset_fname, f_size);
    int n = write(fd, message, strlen(message));
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: open_auction information write failed\n");
        exit_user(1, fd, res);
    }

    printf("---> ;%s", message);

    int bytes_read = 0;
    while ((bytes_read = read(file_fd, buffer, 128)) != 0) {
        buffer[bytes_read] = '\0';
        n = write(fd, buffer, bytes_read);
        if (n == -1) { /*error*/ 
            fprintf(stderr, "ERROR: open_auction data write failed\n");
            exit_user(1, fd, res);
        }
        printf("%s", buffer);
    }

    printf(";");

    // write terminator (\n)
    n = write(fd, "\n", 1);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: open_auction terminator write failed\n");
        exit_user(1, fd, res);
    }
    
    char status[4], aid[4];
    n = read(fd, buffer, 12);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: open_auction read failed\n");
        exit_user(1, fd, res);
    }
    buffer[n] = '\0';

    sscanf(buffer, "ROA %3s %s\n", status, aid);

    if (!strcmp(status, "OK") && (strlen(aid) != 3 || !is_numeric(aid))) {
        fprintf(stderr, "ERROR: server sent message in wrong format\n");
        return;
    }

    if (!strcmp(status, "OK") && buffer[10] == '\n')
        printf("Auction %s was started.\n", aid);
    
    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("Auction could not be started.\n");
    
    else if (!strcmp(status, "NLG") && buffer[7] == '\n')
        printf("User is not logged in.\n");

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else 
        fprintf(stderr, "ERROR: Server sent unknown message.\n");
}

void close_auction(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void myauctions(char *uid, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    // verifications are not necessary since the value for uid and was 
    // previously verified
    
    // LMA message always has 12 chars (3 for LMA, 6 for UID, 1 for spaces, 1 
    // for \n and 1 for \0). Status message has at most 4 chars (3 letters and 
    // one \0). Auction_list has at most 6001 chars (6 chars per auction * 1000 
    // maximum auctions + 1 for for \0). Buffer has variable size, but at most 
    // 6008 chars (3 for RMA + 1 for space + 2 for status + 6 chars per 
    // auction * 1000 maximum auctions + 1 for \n + 1 for for \0)

    char message[12], buffer[MAX_BUFFER_MA_MB_L], status[4], auction_list[MAX_AUCTION_LIST];
    sprintf(message, "LMA %s\n", uid);

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: myauctions request failed\n");
        exit_user(1, fd, res);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, MAX_BUFFER_MA_MB_L, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: myauctions response failed\n");
        exit_user(1, fd, res);
    }

    // reads everything into auction_list until \n character
    sscanf(buffer, "RMA %3s%[^\n]", status, auction_list);

    if (strlen(auction_list) > 6000) {
        fprintf(stderr, "ERROR: Server sent auction list with wrong format.\n");
        return;
    }

    if (!strcmp(status, "OK") && buffer[7 + strlen(auction_list)] == '\n') {
        printf("List of user's auctions: ");
    
        char aid[4], state[2];

        // Each AID state pair has 6 chars (3 for AID, 1 for state and 1 for
        // space). While the string is not finished, we traverse the string 6 by 
        // 6, extract the AID and the state from that section and print the section.
        for (int i = 0; auction_list[6*i] == ' '; i++) {
            sscanf(&auction_list[6*i + 1], "%3s %s", aid, state);
            if (strlen(aid) != 3 || !is_numeric(aid)) {
                fprintf(stderr, "ERROR: Server sent unvalid AID %s.\n", aid);
                return;
            }

            if (!strcmp(state, "1"))
                printf("\"%s\" - active; ", aid);
            else if (!strcmp(state, "0"))
                printf("\"%s\" - closed; ", aid);
            else {
                fprintf(stderr, "ERROR: Server sent unvalid state %s.\n", state);
                return;
            }
        }
        printf("\n");
    }

    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("User has no ungoing auctions. Auctions listing failed.\n");
    
    else if (!strcmp(status, "NLG") && buffer[7] == '\n')
        printf("User is not logged in.\n");

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else 
        fprintf(stderr, "ERROR: Server sent unknown message.\n");
}

void mybids(char *uid, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    // verifications are not necessary since the value for uid and was 
    // previously verified

    // LMB message always has 12 chars (3 for LMA, 6 for UID, 1 for spaces, 1 
    // for \n and 1 for \0). Status message has at most 4 chars (3 letters and 
    // one \0). Auction_list has at most 6001 chars (6 chars per auction * 1000 
    // maximum auctions + 1 for for \0). Buffer has variable size, but at most 
    // 6008 chars (3 for RMA + 1 for space + 2 for status + 6 chars per 
    // auction * 1000 maximum auctions + 1 for \n + 1 for for \0)

    char message[12], buffer[MAX_BUFFER_MA_MB_L], status[4], auction_list[MAX_AUCTION_LIST];
    sprintf(message, "LMB %s\n", uid);

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: mybids request failed\n");
        exit_user(1, fd, res);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, MAX_BUFFER_MA_MB_L, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: mybids response failed\n");
        exit_user(1, fd, res);
    }

    // reads everything into auction_list until \n character
    sscanf(buffer, "RMB %3s%[^\n]", status, auction_list);

    if (strlen(auction_list) > 6000) {
        fprintf(stderr, "ERROR: Server sent auction list with wrong format.\n");
        return;
    }

    if (!strcmp(status, "OK") && buffer[7 + strlen(auction_list)] == '\n') {
        printf("List of user's bids: ");
    
        char aid[4], state[2];

        // Each AID state pair has 6 chars (3 for AID, 1 for state and 1 for
        // space). While the string is not finished, we traverse the string 6 by 
        // 6, extract the AID and the state from that section and print the section.
        for (int i = 0; auction_list[6*i] == ' '; i++) {
            sscanf(&auction_list[6*i + 1], "%3s %s", aid, state);
            if (strlen(aid) != 3 || !is_numeric(aid)) {
                fprintf(stderr, "ERROR: AID %s is not valid.\n", aid);
                return;
            }

            if (!strcmp(state, "1"))
                printf("\"%s\" - active; ", aid);
            else if (!strcmp(state, "0"))
                printf("\"%s\" - closed; ", aid);
            else {
                fprintf(stderr, "ERROR: state %s is not valid.\n", state);
                return;
            }
        }
        printf("\n");
    }

    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("User has no ongoing bids. Bid listing failed.\n");
    
    else if (!strcmp(status, "NLG") && buffer[7] == '\n')
        printf("User is not logged in.\n");

    else if (!strcmp(status, "ERR") && buffer[7] == '\n')
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else 
        fprintf(stderr, "ERROR: Server sent unknown message.\n");
}

void list(int fd, struct addrinfo *res, struct sockaddr_in addr) {
    // LST message always has 5 chars. Status message has at most 4 chars (3
    // letters and one \0). Auction_list has at most 6002 chars (6 chars per
    // auction * 1000 maximum auctions + 1 for \n + 1 for for \0). Buffer has
    // variable size, but at most 6008 chars (3 for RLS + 1 for space + 2 for
    // status + 6 chars per auction * 1000 maximum auctions + 1 for \n + 1 for \0)

    char message[5] = "LST\n";
    char buffer[MAX_BUFFER_MA_MB_L], status[4], auction_list[MAX_AUCTION_LIST];

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/
        fprintf(stderr, "ERROR: list request failed\n");
        exit_user(1, fd, res);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, MAX_BUFFER_MA_MB_L, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/
        fprintf(stderr, "ERROR: list response failed\n");
        exit_user(1, fd, res);
    }

    // reads everything into auction_list until \n character
    sscanf(buffer, "RLS %3s%[^\n]", status, auction_list);

    if (strlen(auction_list) > 6000) {
        fprintf(stderr, "ERROR: Server sent auction list with wrong format.\n");
        return;
    }

    if (!strcmp(status, "OK") && buffer[7 + strlen(auction_list)] == '\n') {
        if (!strlen(auction_list)) {
            printf("No auctions are currently active.\n");
            return;
        }

        printf("List of the currently active auctions: ");
    
        char aid[4], state[2];

        // Each AID state pair has 6 chars (3 for AID, 1 for state and 1 for
        // space). While the string is not finished, we traverse the string 6 by 
        // 6, extract the AID and the state from that section and print the section.
        for (int i = 0; auction_list[6*i] == ' '; i++) {
            sscanf(&auction_list[6*i + 1], "%3s %s", aid, state);
            if (strlen(aid) != 3 || !is_numeric(aid)) {
                fprintf(stderr, "ERROR: AID %s is not valid.\n", aid);
                return;
            }

            if (!strcmp(state, "1"))
                printf("\"%s\" - active; ", aid);
            else if (!strcmp(state, "0"))
                printf("\"%s\" - closed; ", aid);
            else {
                fprintf(stderr, "ERROR: state %s is not valid.\n", state);
                return;
            }
        }
        printf("\n");
    }

    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("No auction was yet started.\n");

    else if (!strcmp(status, "ERR") && buffer[7] == '\n') 
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");
    
    else if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else 
        fprintf(stderr, "ERROR: Server sent unknown message.\n");
}

void show_asset(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void bid(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void show_record(char *aid, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    if (aid[3] == '\n')
        aid[3] = '\0';
    else {
        fprintf(stderr, "usage: show_record <AID: 3 digits>\n\t\bor sr <AID: 3 digits>\n");
        if (strlen(aid) > 3)
            while (getchar() != '\n');  // flushes the rest of the input
        return;
    }

    if (strlen(aid) != 3 || !is_numeric(aid)) {
        fprintf(stderr, "usage: show_record <AID: 3 digits>\n\t\bor sr <AID: 3 digits>\n");
        return;
    }
    
    // SRC message always has 9 chars (3 for SRC, 3 for AID, 1 for spaces, 1
    // for \n and 1 for \0). Status message has at most 4 chars (3 letters and
    // one \0).
    
    // TODO: Auction_list has at most 6002 chars (6 chars per auction * 1000 
    // maximum auctions + 1 for \n + 1 for for \0). Buffer has variable size, 
    // but at most 6008 chars (3 for RMB + 1 for space + 2 for status + 6 chars 
    // per auction * 1000 maximum auctions + 1 for \n + 1 for for \0)

    char message[9], buffer[2213], status[4], host_uid[7], auction_name[11], 
         asset_fname[25], start_value[7], start_date[11], start_time[9], timeactive[6],
         bid_info[2102], closed_info[28]; // TODO
    sprintf(message, "SRC %s\n", aid);

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: show_record request failed\n");
        exit_user(1, fd, res);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, 2213, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/
        fprintf(stderr, "ERROR: show_record response failed\n");
        exit_user(1, fd, res);
    }

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

    if (strlen(host_uid) != 6 || !is_numeric(host_uid) || strlen(auction_name) > 10 
        || !is_alphanumeric(auction_name) || !is_filename(asset_fname) 
        || strlen(start_value) > 6 || !is_numeric(start_value) 
        || !is_date(start_date) || !is_time(start_time) || strlen(timeactive) > 5 
        || !is_numeric(timeactive) || strlen(closed_info) > 27) {
        fprintf(stderr, "ERROR: server sent message in wrong format\n");
        return;
    }

    if (!strcmp(status, "OK")) {
        // check for terminator
        int bid = strlen(bid_info) - 1 != 0, closed = strlen(closed_info) != 0;

        if (bid == 1 && closed == 1 && buffer[83 + strlen(bid_info) + strlen(closed_info)] != '\n') {
            fprintf(stderr, "ERROR: server sent message in wrong format\n");
            return;
        }

        else if (bid == 0 && closed == 1 && buffer[83 + 1 + strlen(closed_info)] != '\n') {
            fprintf(stderr, "ERROR: server sent message in wrong format\n");
            return;
        }

        else if (bid == 1 && closed == 0 && buffer[83 + strlen(bid_info)] != '\n') {
            fprintf(stderr, "ERROR: server sent message in wrong format\n");
            return;
        }

        else if (bid == 0 && closed == 0 && buffer[83] != '\n') {
            fprintf(stderr, "ERROR: server sent message in wrong format\n");
            return;
        }
        
        printf("owner: %s, %s, %s, value=%s, %s %s, timeactive: %s\n", host_uid, 
               auction_name, asset_fname, start_value, start_date, start_time, 
               timeactive);

        if (bid) {
            char bidder_uid[7], bid_value[7], bid_date[11], bid_time[9], 
                 bid_sec_time[6]; 
            int bid_info_length;
            for (int i = 0; bid_info[i] == ' ' && strlen(&bid_info[i]) != 1; i += bid_info_length) {
                sscanf(&bid_info[i + 1], "B %6s %6s %10s %8s %s", bidder_uid, bid_value, bid_date, bid_time, bid_sec_time);

                if (strlen(bidder_uid) != 6 || !is_numeric(bidder_uid) 
                    || strlen(bid_value) > 6 || !is_numeric(bid_value) 
                    || !is_date(bid_date) || !is_time(bid_time) 
                    || strlen(bid_sec_time) > 5 || !is_numeric(bid_sec_time)) {
                    fprintf(stderr, "ERROR: server sent message in wrong format\n");
                    return;
                }

                // 7 is for the 'B' and the spaces
                bid_info_length = 7 + strlen(bidder_uid) + strlen(bid_value) + strlen(bid_date) + strlen(bid_time) + strlen(bid_sec_time);
                printf("\t\bbid: user: %s, value=%s, %s %s, %s\n", bidder_uid, bid_value, bid_date, bid_time, bid_sec_time);
            }
        }
        
        if (closed) {
            char end_date[11], end_time[9], end_sec_time[7];
            sscanf(closed_info, "E %10s %8s %s\n", end_date, end_time, end_sec_time);

            if (!is_date(end_date) || !is_time(end_time) 
                || strlen(end_sec_time) > 5 || !is_numeric(end_sec_time)) {
                    fprintf(stderr, "ERROR: server sent message in wrong format\n");
                    return;
                }

            printf("closed: %s %s, %s\n", end_date, end_time, end_sec_time);
        }
    }

    else if (!strcmp(status, "ERR") && buffer[7] == '\n') 
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (!strcmp(status, "NOK") && buffer[7] == '\n')
        printf("Auction with AID %s does not exist.\n", aid);
    
    else if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else 
        fprintf(stderr, "ERROR: Server sent unknown message.\n");
}

void exit_user(int exit_status, int fd, struct addrinfo *res) {
    freeaddrinfo(res);
    close(fd); 
    exit(exit_status);
}

int main(int argc, char **argv) {
    char ASIP[16], ASport[6];
    handle_arguments(argc, argv, ASIP, ASport);

    int fd_udp, fd_tcp, errcode;
    struct addrinfo hints_udp, hints_tcp, *res_udp, *res_tcp;
    struct sockaddr_in addr;
    char command[12], args[54];

    // open UDP socket
    fd_udp = socket(AF_INET, SOCK_DGRAM, 0); // UDP socket
    if (fd_udp == -1) {  /*error*/ 
        fprintf(stderr, "ERROR: Socket creation was not sucessful\n");
        close(fd_udp);
        exit(1);
    }
    
    memset(&hints_udp, 0, sizeof hints_udp);
    hints_udp.ai_family = AF_INET; // IPv4
    hints_udp.ai_socktype = SOCK_DGRAM; // UDP socket

    errcode = getaddrinfo(ASIP, ASport, &hints_udp, &res_udp);
    if (errcode != 0) {  /*error*/ 
        fprintf(stderr, "ERROR: Server not found\n");
        exit_user(1, fd_udp, res_udp);
    }

    // open TCP socket
    fd_tcp = socket(AF_INET, SOCK_STREAM, 0); //TCP socket
    if (fd_tcp == -1) exit(1); //error

    memset(&hints_tcp, 0, sizeof hints_tcp);
    hints_tcp.ai_family = AF_INET; //IPv4
    hints_tcp.ai_socktype = SOCK_STREAM; //TCP socket

    errcode = getaddrinfo(ASIP, ASport, &hints_tcp, &res_tcp);
    if (errcode != 0) {  /*error*/ 
        fprintf(stderr, "ERROR: Server not found\n");
        exit_user(1, fd_tcp, res_tcp);
    }

    int n = connect(fd_tcp, res_tcp->ai_addr, res_tcp->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: Connect to server failed\n");
        exit_user(1, fd_tcp, res_tcp);
    }
    
    int logged_in = 0;
    char uid[7], password[9], aid[5];

    printf("Input your command:\n");

    while (1) {
        printf("> ");
        scanf("%s", command);

        if (!strcmp(command, "login")) {
            getchar();      // consumes the space
            // read or flush the rest of the input if already logged in
            fgets(args, 17, stdin);

            if (logged_in)
                printf("WARNING: A user is already logged in. Please logout before logging in into another account.\n");

            else {
                sscanf(args, " %6s %s", uid, password);
            
                if (login(uid, password, fd_udp, res_udp, addr))
                    logged_in = 1;                         // mark flag as logged in if login sucessful
            }
        }

        else if (!strcmp(command, "logout")) {
            if (logged_in) {
                logout(uid, password, fd_udp, res_udp, addr);
                logged_in = 0;
            }
            
            else
                printf("WARNING: No user is logged in. Please log in before logging out.\n");
        }

        else if (!strcmp(command, "unregister")) {
            if (logged_in) {
                unregister(uid, password, fd_udp, res_udp, addr);
                logged_in = 0;
            }

            else
                printf("WARNING: No user is logged in. Please log in before unregistering.\n");
        }

        else if (!strcmp(command, "open")) {
            char name[11], asset_fname[25], start_value[7], timeactive[6];
            
            getchar();      // consumes the space
            // read or flush the rest of the input if already logged in
            fgets(args, 54, stdin);
            sscanf(args, "%s %s %s %s\n", name, asset_fname, start_value, timeactive);

            if (logged_in)
                open_auction(uid, password, name, asset_fname, start_value, timeactive, fd_tcp, res_tcp, addr);

            else
                printf("WARNING: No user is logged in. Please log in before requesting auction opening.\n");   
        }

        else if (!strcmp(command, "close"))
            close_auction(args, fd_udp, res_udp, addr);

        else if (!strcmp(command, "myauctions") || !strcmp(command, "ma")) {
            if (logged_in)
                myauctions(uid, fd_udp, res_udp, addr);

            else
                printf("WARNING: No user is logged in. Please log in before requesting auction listing.\n");            
        }

        else if (!strcmp(command, "mybids") || !strcmp(command, "mb"))
            if (logged_in)
                mybids(uid, fd_udp, res_udp, addr);

            else
                printf("WARNING: No user is logged in. Please log in before requesting bid listing.\n"); 

        else if (!strcmp(command, "list") || !strcmp(command, "l"))
            list(fd_udp, res_udp, addr);

        else if (!strcmp(command, "show_asset") || !strcmp(command, "sa"))
            show_asset(args, fd_tcp, res_tcp, addr);

        else if (!strcmp(command, "bid") || !strcmp(command, "b"))
            bid(args, fd_tcp, res_tcp, addr);

        else if (!strcmp(command, "show_record") || !strcmp(command, "sr")) {
            getchar();               // consumes the space
            fgets(aid, 5, stdin);
            show_record(aid, fd_udp, res_udp, addr);
        }

        else if (!strcmp(command, "exit")) {
            if (logged_in)
                printf("WARNING: Please log out before exiting.\n");
            else {
                freeaddrinfo(res_tcp);
                close(fd_tcp); 
                exit_user(0, fd_udp, res_udp);
            }
        }

        else {
            printf("Command not found. Please try again\n");
            while (getchar() != '\n');  // flushes the rest of the input
        }
    }
    
    return 0;
}