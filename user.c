#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#include "user.h"

#define DEFAULT_IP "localhost"
#define DEFAULT_PORT "58046"   // 58000 + 46 (group number)

#define MAX_BUFFER_MA_MB_L   6008
#define MAX_AUCTION_LIST     6002

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
    for (int i = 0; i < l; i++) {
        if (!('0' <= word[i] <= '9' || 'A' <= word[i] <= 'Z' 
              || 'a' <= word[i] <= 'z' || word[i] == '-' 
              || word[i] == '_' || word[i] == '.'))
            return 0;
        
        if (i == l - 4 && word[i] != '.')
            return 0;
        
        if (i > l - 4 && ('a' > word[i] || word[i] > 'z'))
            return 0;
    }
    return 1;
}

int is_date(char *word) {
    int l = strlen(word);
    for (int i = 0; i < l; i++) {   // YYYY-MM-DD
        if ((i == 4 || i == 7) && word[i] != '-')
            return 0;
        else if (i != 4 && i != 7 && ('0' > word[i] || word[i] > '9'))
            return 0;
    }

    int year, month, day;
    sscanf(word, "%d-%d-%d", &year, &month, &day);

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
    for (int i = 0; i < l; i++) {
        if ((i == 2 || i == 5) && word[i] != ':')
            return 0;
        else if (i != 2 && i != 5 && ('0' > word[i] || word[i] > '9'))
            return 0;
    }

    int hours, minutes, seconds;
    sscanf(word, "%d:%d:%d", &hours, &minutes, &seconds);

    if (0 > hours || hours > 24)
        return 0;
    if (0 > minutes || minutes > 60)
        return 0;
    if (0 > seconds || seconds > 60)
        return 0;

    return 1;
}

void handle_arguments(int argc, char **argv, char *ASIP, char *ASport) {
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
    if (strlen(uid) != 6 || strlen(password) != 8 || !is_alphanumeric(password) || !is_numeric(uid)) {
        fprintf(stderr, "usage: login <UID: 6 digits> <password: 8 alphanumeric chars>\n");
        return 0;
    }

    // LIN message always has 21 chars (3 for LIN, 6 for UID, 8 for password, 2 
    // for spaces, 1 for \n and 1 for \0). Status message has at most 4 chars 
    // (3 letters and one \0).
    char message[21], buffer[128], status[4];        // TODO
    sprintf(message, "LIN %s %s\n", uid, password);

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: login request failed\n");
        exit_user(1, fd, res, addr);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: login response failed\n");
        exit_user(1, fd, res, addr);
    }

    sscanf(buffer, "RLI %s\n", status);

    if (!strcmp(status, "OK")) {
        printf("User logged in.\n");
        return 1;
    }
    
    else if (!strcmp(status, "NOK")) {
        printf("Password is incorrect. Log in failed. Please try again.\n");
        return 0;
    }
    
    else if (!strcmp(status, "REG")) {
        printf("New user sucessfully created and logged in.\n");
        return 1;
    }

    else if (!strcmp(status, "ERR")) {
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
    char message[21], buffer[128], status[4];        // TODO
    sprintf(message, "LOU %s %s\n", uid, password);

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: logout request failed\n");
        exit_user(1, fd, res, addr);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: logout response failed\n");
        exit_user(1, fd, res, addr);
    }

    sscanf(buffer, "RLO %s\n", status);

    if (!strcmp(status, "OK"))
        printf("User logged out.\n");
    
    else if (!strcmp(status, "NOK"))
        printf("User was not logged in. Logout failed.\n");
    
    else if (!strcmp(status, "UNR"))
        printf("User is not registered.\n");

    else if (!strcmp(status, "ERR"))
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
    char message[21], buffer[128], status[4];        // TODO
    sprintf(message, "UNR %s %s\n", uid, password);

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: unregister request failed\n");
        exit_user(1, fd, res, addr);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: unregister response failed\n");
        exit_user(1, fd, res, addr);
    }

    sscanf(buffer, "RUR %s\n", status);

    if (!strcmp(status, "OK"))
        printf("User unregistered.\n");
    
    else if (!strcmp(status, "NOK"))
        printf("User was not logged in. Unregistered failed.\n");
    
    else if (!strcmp(status, "UNR"))
        printf("User is not registered.\n");

    else if (!strcmp(status, "ERR"))
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else 
        fprintf(stderr, "ERROR: Server sent unknown message.\n");
}

void open_auction(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void close_auction(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void myauctions(char *uid, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    // verifications are not necessary since the value for uid and was 
    // previously verified
    
    // LMA message always has 12 chars (3 for LMA, 6 for UID, 1 for spaces, 1 
    // for \n and 1 for \0). Status message has at most 4 chars (3 letters and 
    // one \0). Auction_list has at most 6002 chars (6 chars per auction * 1000 
    // maximum auctions + 1 for \n + 1 for for \0). Buffer has variable size, 
    // but at most 6008 chars (3 for RMA + 1 for space + 2 for status + 6 chars 
    // per auction * 1000 maximum auctions + 1 for \n + 1 for for \0)

    char message[12], buffer[MAX_BUFFER_MA_MB_L], status[4], auction_list[MAX_AUCTION_LIST];
    sprintf(message, "LMA %s\n", uid);

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: myauctions request failed\n");
        exit_user(1, fd, res, addr);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, MAX_BUFFER_MA_MB_L, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: myauctions response failed\n");
        exit_user(1, fd, res, addr);
    }

    // reads everything into auction_list until \n character
    sscanf(buffer, "RMA %s%[^\n]", status, auction_list);

    if (!strcmp(status, "OK")) {
        printf("List of user's auctions: ");
    
        char aid[4], state[2];

        // Each AID state pair has 6 chars (3 for AID, 1 for state and 1 for
        // space). While the string is not finished, we traverse the string 6 by 
        // 6, extract the AID and the state from that section and print the section.
        for (int i = 0; auction_list[6*i] == ' '; i++) {
            sscanf(&auction_list[6*i + 1], "%s %s", aid, state);
            if (strlen(aid) != 3) {
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

    else if (!strcmp(status, "NOK"))
        printf("User has no ungoing auctions. Auctions listing failed.\n");
    
    else if (!strcmp(status, "NLG"))
        printf("User is not logged in.\n");

    else if (!strcmp(status, "ERR"))
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else 
        fprintf(stderr, "ERROR: Server sent unknown message.\n");
}

void mybids(char *uid, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    // verifications are not necessary since the value for uid and was 
    // previously verified
    
    // LMB message always has 12 chars (3 for LMB, 6 for UID, 1 for spaces, 1
    // for \n and 1 for \0). Status message has at most 4 chars (3 letters and
    // one \0). Auction_list has at most 6002 chars (6 chars per auction * 1000 
    // maximum auctions + 1 for \n + 1 for for \0). Buffer has variable size, 
    // but at most 6008 chars (3 for RMB + 1 for space + 2 for status + 6 chars 
    // per auction * 1000 maximum auctions + 1 for \n + 1 for for \0)

    char message[12], buffer[MAX_BUFFER_MA_MB_L], status[4], auction_list[MAX_AUCTION_LIST];
    sprintf(message, "LMB %s\n", uid);

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: mybids request failed\n");
        exit_user(1, fd, res, addr);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, MAX_BUFFER_MA_MB_L, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: mybids response failed\n");
        exit_user(1, fd, res, addr);
    }

    // reads everything into auction_list until \n character
    sscanf(buffer, "RMB %s %[^\n]", status, auction_list);

    if (!strcmp(status, "OK")) {
        printf("List of user's bids: ");
    
        char aid[4], state[2];

        // Each AID state pair has 6 chars (3 for AID, 1 for state and 1 for
        // space). While the string is not finished, we traverse the string 6 by 
        // 6, extract the AID and the state from that section and print the section.
        for (int i = 0; auction_list[6*i] == ' '; i++) {
            sscanf(&auction_list[6*i + 1], "%s %s", aid, state);
            if (strlen(aid) != 3) {
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

    else if (!strcmp(status, "NOK"))
        printf("User has no ongoing bids. Bid listing failed.\n");
    
    else if (!strcmp(status, "NLG"))
        printf("User is not logged in.\n");

    else if (!strcmp(status, "ERR"))
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
        exit_user(1, fd, res, addr);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, MAX_BUFFER_MA_MB_L, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/
        fprintf(stderr, "ERROR: list response failed\n");
        exit_user(1, fd, res, addr);
    }

    // reads everything into auction_list until \n character
    sscanf(buffer, "RLS %s %[^\n]", status, auction_list);

    if (!strcmp(status, "OK")) {
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
            sscanf(&auction_list[6*i + 1], "%s %s", aid, state);
            if (strlen(aid) != 3) {
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

    else if (!strcmp(status, "NOK"))
        printf("No auction was yet started.\n");

    else if (!strcmp(status, "ERR")) 
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

    char message[9], buffer[10000], status[4], host_uid[7], auction_name[100], 
         asset_fname[25], start_value[100], start_date[11], start_time[9], timeactive[7],
         bid_info[100], closed_info[100]; // TODO
    sprintf(message, "SRC %s\n", aid);

    ssize_t n = sendto(fd, message, strlen(message) * sizeof(char), 0, res->ai_addr, res->ai_addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: mybids request failed\n");
        exit_user(1, fd, res, addr);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, 10000, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/
        fprintf(stderr, "ERROR: list response failed\n");
        exit_user(1, fd, res, addr);
    }

    // Using this format, bid_info will always have a \n at the beginning. If
    // no bids were specified and if we used another format which matched the \n 
    // at the end of the owner info, the %[^E] part of the string would read 
    // nothing. In turn, this would prevent the closed_info to read any 
    // information. On the contrary, if we keep the \n unmatched, %[^E] will 
    // always match at least with one character (\n), which allows closed_info
    // to read the rest of the string.
    sscanf(buffer, "RRC %s %s %s %s %s %s %s %s%[^E]%[^\n]", status, host_uid, 
            auction_name, asset_fname, start_value, start_date, start_time, 
            timeactive, bid_info, closed_info);

    if (strlen(host_uid) != 6 || !is_numeric(host_uid) || strlen(auction_name) > 10 
        || !is_alphanumeric(auction_name) || !is_filename(asset_fname) 
        || strlen(start_value) > 6 || !is_numeric(start_value) 
        || !is_date(start_date) || !is_time(start_time) || strlen(timeactive) > 5 
        || !is_numeric(timeactive)) {
        fprintf(stderr, "ERROR: server sent message in wrong format\n");
        return;
    }

    if (!strcmp(status, "OK")) {
        printf("owner: %s, %s, %s, value=%s, %s %s, timeactive: %s\n", host_uid, 
               auction_name, asset_fname, start_value, start_date, start_time, 
               timeactive);
        
        // taking into account the '\n'
        if (strlen(bid_info) - 1) {
            char bid_info_line[100], bidder_uid[7], bid_value[100], bid_date[11], bid_time[9], 
                 bid_sec_time[7]; // TODO
            
            int bid_info_length;
            for (int i = 0; bid_info[i] == ' ' && strlen(&bid_info[i]) != 1; i += bid_info_length) {
                sscanf(&bid_info[i + 1], "B %s %s %s %s %s", bidder_uid, bid_value, bid_date, bid_time, bid_sec_time);

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
        
        if (strlen(closed_info)) {
            char end_date[11], end_time[9], end_sec_time[7];
            sscanf(closed_info, "E %s %s %s\n", end_date, end_time, end_sec_time);

            if (!is_date(end_date) || !is_time(end_time) 
                || strlen(end_sec_time) > 5 || !is_numeric(end_sec_time)) {
                    fprintf(stderr, "ERROR: server sent message in wrong format\n");
                    return;
                }

            printf("closed: %s %s, %s\n", end_date, end_time, end_sec_time);
        }
    }

    else if (!strcmp(status, "ERR")) 
        printf("The syntax of the request message is incorrect or the parameters values are invalid.\n");

    else if (!strcmp(status, "NOK"))
        printf("Auction with AID %s does not exist.\n", aid);
    
    else if (!strcmp(buffer, "ERR\n"))
        printf("Unexpected protocol message.\n");

    else 
        fprintf(stderr, "ERROR: Server sent unknown message.\n");
}

void exit_user(int exit_status, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    freeaddrinfo(res);
    close(fd); 
    exit(exit_status);
}

int main(int argc, char **argv) {
    char ASIP[100], ASport[100];          // TODO
    handle_arguments(argc, argv, ASIP, ASport);

    int fd, errcode;
    struct addrinfo hints, *res;
    struct sockaddr_in addr;
    char command[100], args[100];         // TODO

    fd = socket(AF_INET, SOCK_DGRAM, 0); // UDP socket
    if (fd == -1) {  /*error*/ 
        fprintf(stderr, "ERROR: Socket creation was not sucessful\n");
        close(fd);
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket

    errcode = getaddrinfo(ASIP, ASport, &hints, &res);
    if (errcode != 0) {  /*error*/ 
        fprintf(stderr, "ERROR: Server not found\n");
        exit_user(1, fd, res, addr);
    }

    int logged_in = 0;
    char uid[7], password[9];

    printf("Input your command:\n");

    while (1) {
        printf("> ");
        scanf("%s", command);

        if (!strcmp(command, "login")) {
            // read or flush the rest of the input if already logged in
            fgets(args, 100, stdin);    // TODO

            if (logged_in)
                printf("WARNING: A user is already logged in. Please logout before logging in into another account.\n");

            else {
                sscanf(args, " %s %s\n", uid, password);   // save uid and password
                if (login(uid, password, fd, res, addr))
                    logged_in = 1;                         // mark flag as logged in if login sucessful
            }
        }

        else if (!strcmp(command, "logout")) {
            if (logged_in) {
                logout(uid, password, fd, res, addr);
                logged_in = 0;
            }
            
            else
                printf("WARNING: No user is logged in. Please log in before logging out.\n");
        }

        else if (!strcmp(command, "unregister")) {
            if (logged_in) {
                unregister(uid, password, fd, res, addr);
                logged_in = 0;
            }

            else
                printf("WARNING: No user is logged in. Please log in before unregistering.\n");
        }

        else if (!strcmp(command,  "open")) {
            open_auction(args, fd, res, addr);
        }

        else if (!strcmp(command, "close"))
            close_auction(args, fd, res, addr);

        else if (!strcmp(command, "myauctions") || !strcmp(command, "ma")) {
            if (logged_in)
                myauctions(uid, fd, res, addr);

            else
                printf("WARNING: No user is logged in. Please log in before requesting auction listing.\n");            
        }

        else if (!strcmp(command, "mybids") || !strcmp(command, "mb"))
            if (logged_in)
                mybids(uid, fd, res, addr);

            else
                printf("WARNING: No user is logged in. Please log in before requesting bid listing.\n"); 

        else if (!strcmp(command, "list") || !strcmp(command, "l"))
            list(fd, res, addr);

        else if (!strcmp(command, "show_asset") || !strcmp(command, "sa"))
            show_asset(args, fd, res, addr);

        else if (!strcmp(command, "bid") || !strcmp(command, "b"))
            bid(args, fd, res, addr);

        else if (!strcmp(command, "show_record") || !strcmp(command, "sr")) {
            char aid[4];
            getchar();               // consumes the space
            fgets(aid, 4, stdin);   // TODO
            show_record(aid, fd, res, addr);
        }

        else if (!strcmp(command, "exit")) {
            if (logged_in)
                printf("WARNING: Please log out before exiting.\n");
            else
                exit_user(0, fd, res, addr);
        }

        else {
            fgets(args, 100, stdin);    // flush the rest of the input 
            printf("Command not found. Please try again\n");
        }
    }
    
    return 0;
}