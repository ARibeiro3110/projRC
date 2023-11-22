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
        exit(1);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: login response failed\n");
        exit(1);
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
    
    else {
        fprintf(stderr, "ERROR: unexpected protocol message\n");
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
        exit(1);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: logout response failed\n");
        exit(1);
    }

    sscanf(buffer, "RLO %s\n", status);

    if (!strcmp(status, "OK"))
        printf("User logged out.\n");
    
    else if (!strcmp(status, "NOK"))
        printf("User was not logged in. Logout failed.\n");
    
    else if (!strcmp(status, "UNR"))
        printf("User is not registered.\n");

    else 
        fprintf(stderr, "ERROR: unexpected protocol message\n");
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
        exit(1);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, 128, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: unregister response failed\n");
        exit(1);
    }

    sscanf(buffer, "RUR %s\n", status);

    if (!strcmp(status, "OK"))
        printf("User unregistered.\n");
    
    else if (!strcmp(status, "NOK"))
        printf("User was not logged in. Unregistered failed.\n");
    
    else if (!strcmp(status, "UNR"))
        printf("User is not registered.\n");

    else 
        fprintf(stderr, "ERROR: unexpected protocol message\n");
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
        exit(1);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, MAX_BUFFER_MA_MB_L, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: myauctions response failed\n");
        exit(1);
    }

    // reads everything into auction_list until \n character
    memset(auction_list, 0, MAX_AUCTION_LIST);
    sscanf(buffer, "RMA %s %[^\n]", status, auction_list);

    if (!strcmp(status, "OK")) {
        printf("List of user's auctions: ");
    
        char AID[4], state[2];

        // Each AID state pair has 6 chars (3 for AID, 1 for state and 1 for
        // space). While the string is not finished, we traverse the string 6 by 
        // 6, extract the AID and the state from that section and print the section.
        for (int i = 0; sscanf(&auction_list[6*i], "%s %s ", AID, state) != EOF; i++) {
            if (!strcmp(state, "1"))
                printf("\"%s\" - active; ", AID);
            else
                printf("\"%s\" - closed; ", AID);
        }
        printf("\n");
    }

    else if (!strcmp(status, "NOK"))
        printf("User has no ungoing auctions. Auctions listing failed.\n");
    
    else if (!strcmp(status, "NLG"))
        printf("User is not logged in.\n");

    else 
        fprintf(stderr, "ERROR: unexpected protocol message\n");
}

void mybids(char *uid, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    // verifications are not necessary since the values for uid and password 
    // were previously verified
    
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
        exit(1);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, MAX_BUFFER_MA_MB_L, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: mybids response failed\n");
        exit(1);
    }

    // reads everything into auction_list until \n character
    memset(auction_list, 0, MAX_AUCTION_LIST);
    sscanf(buffer, "RMB %s %[^\n]", status, auction_list);

    if (!strcmp(status, "OK")) {
        printf("List of user's bids: ");
    
        char AID[4], state[2];

        // Each AID state pair has 6 chars (3 for AID, 1 for state and 1 for
        // space). While the string is not finished, we traverse the string 6 by 
        // 6, extract the AID and the state from that section and print the section.
        for (int i = 0; sscanf(&auction_list[6*i], "%s %s ", AID, state) != EOF; i++) {
            if (!strcmp(state, "1"))
                printf("\"%s\" - active; ", AID);
            else
                printf("\"%s\" - closed; ", AID);
        }
        printf("\n");
    }

    else if (!strcmp(status, "NOK"))
        printf("User has no ongoing bids. Bid listing failed.\n");
    
    else if (!strcmp(status, "NLG"))
        printf("User is not logged in.\n");

    else 
        fprintf(stderr, "ERROR: unexpected protocol message\n");
}

void list(int fd, struct addrinfo *res, struct sockaddr_in addr) {
    // verifications are not necessary since the values for uid and password
    // were previously verified
    
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
        exit(1);
    }

    socklen_t addrlen = sizeof(addr);
    n = recvfrom(fd, buffer, MAX_BUFFER_MA_MB_L, 0, (struct sockaddr*) &addr, &addrlen);
    if (n == -1) { /*error*/
        fprintf(stderr, "ERROR: list response failed\n");
        exit(1);
    }

    // reads everything into auction_list until \n character
    memset(auction_list, 0, MAX_AUCTION_LIST);
    sscanf(buffer, "RLS %s %[^\n]", status, auction_list);
    printf("\nPRINT1\n%s\n", buffer);

    if (!strcmp(status, "OK")) {
        printf("List of the currently active auctions: ");
    
        char AID[4], state[2];

        // Each AID state pair has 6 chars (3 for AID, 1 for state and 1 for
        // space). While the string is not finished, we traverse the string 6 by 
        // 6, extract the AID and the state from that section and print the section.
        for (int i = 0; sscanf(&auction_list[6*i], "%s %s ", AID, state) != EOF; i++)
            if (!strcmp(state, "1"))
                printf("\"%s\" - active; ", AID);
        // TODO no enunciado diz que são enviadas todas as auctions (assumo que
        // caiba ao user só dar print das que quer), mas no powerpoint *parece-me* que só envia as ativas
        printf("\n");
    }

    else if (!strcmp(status, "NOK"))
        printf("No auction was yet started.\n");
    
    else 
        fprintf(stderr, "ERROR: unexpected protocol message\n");
}

void show_asset(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void bid(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void show_record(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void exit_user(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    freeaddrinfo(res);
    close(fd); 
    exit(0);
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
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM; // UDP socket

    errcode = getaddrinfo(ASIP, ASport, &hints, &res);
    if (errcode != 0) {  /*error*/ 
        fprintf(stderr, "ERROR: Server not found\n");
        exit(1);
    }

    int logged_in = 0;
    char uid[7], password[9];

    printf("Input your command:\n"); // TODO

    // TODO
    // "For replies including the status field it takes the value ERR when the
    // syntax of the request message was incorrect or when the parameter values
    // take invalid values. If an unexpected protocol message is received, the reply is ERR."

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

        else if (!strcmp(command,  "show_record") || !strcmp(command,  "sr"))
            show_record(args, fd, res, addr);

        else if (!strcmp(command, "exit")) {
            if (logged_in)
                printf("WARNING: Please log out before exiting.\n");
            else
                exit_user(args, fd, res, addr);
        }

        else 
            printf("Command not found. Please try again\n");
    }
    
    return 0;
}