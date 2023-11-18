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

#define DEFAULT_IP ""          // TODO
#define DEFAULT_PORT "58046"   // 58000 + 46 (group number)

int order_of_magnitude(int number) {
    int oom = 0;

    while (number > 0) {
        oom++;
        number = number / 10;
    }
    return oom;
}

int is_alphanumeric(char* word) {
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

void login(int uid, char *password, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    if (order_of_magnitude(uid) != 6 || strlen(password) != 8 || !is_alphanumeric(password)) {
        fprintf(stderr, "usage: login <UID: 6 digits> <password: 8 alphanumeric chars>\n");
        return;
    }

    // LIN message always has 21 chars (3 for LIN, 6 for UID, 8 for password, 2 
    // for spaces, 1 for \n and 1 for \0). Status message has at most 4 chars 
    // (3 letters and one \0).
    char message[21], buffer[128], status[4];        // TODO
    sprintf(message, "LIN %d %s\n", uid, password);

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

    if (!strcmp(status, "OK"))
        printf("User logged in.\n");
    
    else if (!strcmp(status, "NOK"))
        printf("Password is incorrect. Log in failed. Please try again.\n");
    
    else if (!strcmp(status, "REG"))
        printf("New user sucessfully created and logged in.\n");
    
    else 
        fprintf(stderr, "ERROR: unexpected protocol message\n");
}

void logout(int uid, char *password, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    // verifications are not necessary since the values for uid and password 
    // were previously verified
    
    // LIN message always has 21 chars (3 for LIN, 6 for UID, 8 for password, 2 
    // for spaces, 1 for \n and 1 for \0). Status message has at most 4 chars 
    // (3 letters and one \0).
    char message[21], buffer[128], status[4];        // TODO
    sprintf(message, "LOU %d %s\n", uid, password);

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

void unregister(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void open_auction(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void close_auction(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void myauctions(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void mybids(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void list(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void show_asset(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void bid(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void show_record(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {

}

void exit_user(char *args, int fd, struct addrinfo *res, struct sockaddr_in addr) {
    // TODO
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

    int uid, logged_in = 0;
    char password[9];

    printf("Input your command:\n");

    while (1) {
        printf("> ");
        scanf("%s", command);

        if (!strcmp(command, "login")) {
            // read or flush the rest of the input if already logged in
            fgets(args, 100, stdin);    // TODO

            if (logged_in)
                printf("A user is already logged in. Please logout before logging in into another account.\n");

            else {
                sscanf(args, " %d %s\n", &uid, password);  // save uid and password
                login(uid, password, fd, res, addr);
                logged_in = 1;                             // mark flag as logged in
            }
        }

        else if (!strcmp(command, "logout")) {
            logout(uid, password, fd, res, addr);
            logged_in = 0;
        }

        else if (!strcmp(command, "unregister"))
            unregister(args, fd, res, addr);

        else if (!strcmp(command,  "open"))
            open_auction(args, fd, res, addr);

        else if (!strcmp(command, "close"))
            close_auction(args, fd, res, addr);

        else if (!strcmp(command, "myauctions") || !strcmp(command, "ma"))
            myauctions(args, fd, res, addr);

        else if (!strcmp(command, "mybids") || !strcmp(command, "mb"))
            mybids(args, fd, res, addr);

        else if (!strcmp(command, "list") || !strcmp(command, "l"))
            list(args, fd, res, addr);

        else if (!strcmp(command, "show_asset") || !strcmp(command, "sa"))
            show_asset(args, fd, res, addr);

        else if (!strcmp(command, "bid") || !strcmp(command, "b"))
            bid(args, fd, res, addr);

        else if (!strcmp(command,  "show_record") || !strcmp(command,  "sr"))
            show_record(args, fd, res, addr);

        else if (!strcmp(command,  "exit"))
            exit_user(args, fd, res, addr);

        else 
            printf("Command not found. Please try again\n");
    }
    
    return 0;
}