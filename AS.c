#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

#include "common.h"
#include "AS.h" 

void handle_main_arguments(int argc, char **argv, char *ASport, int *verbose) {
    switch (argc) {
    case 1:          // all arguments are omitted 
        strcpy(ASport, DEFAULT_PORT);
        break;
    
    case 2:
        if (!strcmp(argv[1], "-v")) {
            strcpy(ASport, DEFAULT_PORT);
            *verbose = 1;
        }

        else {
            fprintf(stderr, "usage: AS [-p ASport] [-v]\n");
            exit(1);
        }
        break;

    case 3:          // one of the arguments is omitted
        if (!strcmp(argv[1], "-p")) {
            if (!is_port_no(argv[2])) {
                fprintf(stderr, "usage: ASport needs to be a valid port number\n");
                exit(1);
            }

            strcpy(ASport, argv[2]);
        }

        else {
            fprintf(stderr, "usage: AS [-p ASport] [-v]\n");
            exit(1);
        }

        break;

    case 4:          // all arguments are present
        if (!strcmp(argv[1], "-p") && !strcmp(argv[3], "-v")) {
            if (!is_port_no(argv[2])) {
                fprintf(stderr, "usage: ASport needs to be a valid port number\n");
                exit(1);
            }

            strcpy(ASport, argv[2]);
            *verbose = 1;
        }

        else if (!strcmp(argv[1], "-v") && !strcmp(argv[2], "-p")) {
            if (!is_port_no(argv[3])) {
                fprintf(stderr, "usage: ASport needs to be a valid port number\n");
                exit(1);
            }

            strcpy(ASport, argv[3]);
            *verbose = 1;
        }

        else {
            fprintf(stderr, "usage: AS [-p ASport] [-v]\n");
            exit(1);
        }
        break;
    
    default:
        fprintf(stderr, "usage: AS [-p ASport] [-v]\n");
        exit(1);
    }
}

int create_password(char *uid, char *password) {
    char pass_file_path[36];
    FILE *fp;
    
    sprintf(pass_file_path, "ASDIR/USERS/%s/%s_pass.txt", uid, uid);
    fp = fopen(pass_file_path, "w");
    if (fp == NULL)
        return 0;
    
    fprintf(fp, "%s\n", password);
    fclose(fp);
    
    return 1;
}

int create_login(char *uid) {
    char login_name[37];
    FILE *fp;
    
    sprintf(login_name, "ASDIR/USERS/%s/%s_login.txt", uid, uid);
    fp = fopen(login_name, "w");
    if (fp == NULL)
        return 0;
    
    fprintf(fp, "Logged in\n");
    fclose(fp);
    
    return 1;
}

int exists_file(char *path) {
    struct stat filestat;
    int retstat;
    retstat = stat(path, &filestat);

    if (retstat == -1 && errno == 2) 
        return 0;

    else if (retstat == -1 && errno != 2) 
        return -1;  

    else 
        return 1;
}

void handle_login_request(char *uid, char *user_password, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    char response[9];

    if (strlen(uid) != 6 || !is_numeric(uid) || strlen(user_password) != 8 
        || !is_alphanumeric(user_password)) {
        sprintf(response, "RLI ERR\n");
        int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
        if (n == -1)  {
            fprintf(stderr, "ERROR: unable to send response.\n");
            exit(1);
        }
        return;
    }

    char path[19];
    int new_user = 0;

    sprintf(path, "ASDIR/USERS/%s", uid);
    DIR *dr = opendir(path); 
    struct dirent *de;

    if (dr == NULL && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1); 
    } 

    else if (dr == NULL && errno == 2) { // directory does not exist
        if (mkdir(path, 0700) == -1) {
            fprintf(stderr, "ERROR: unable to create password file.\n");
            exit(1);
        }
        
        if (!create_password(uid, user_password)) {
            fprintf(stderr, "ERROR: unable to create password file.\n");
            exit(1);
        }
        
        if (!create_login(uid)) {
            fprintf(stderr, "ERROR: unable to create login file.\n");
            exit(1);
        }

        sprintf(response, "RLI REG\n");
        new_user = 1;
    }

    closedir(dr);

    if (!new_user) {
        char pass_file_path[35], file_password[9];
        sprintf(pass_file_path, "ASDIR/USERS/%s/%s_pass.txt", uid, uid);

        if (exists_file(pass_file_path) == 1) {
            FILE *fp = fopen(pass_file_path, "r");
            if (fp == NULL) {
                fprintf(stderr, "ERROR: %d unable to open pass file.\n", errno);
                exit(1);
            }
            
            fread(file_password, sizeof(file_password), 1, fp);
            file_password[8] = '\0';
            fclose(fp);

            if (!strcmp(file_password, user_password)) {
                if (!create_login(uid)) {
                    fprintf(stderr, "ERROR: unable to create login file.\n");
                    exit(1);
                }

                sprintf(response, "RLI OK\n");
            }

            else
                sprintf(response, "RLI NOK\n");
        }

        else {
            if (!create_password(uid, user_password)) {
                fprintf(stderr, "ERROR: unable to create password file.\n");
                exit(1);
            }
            
            if (!create_login(uid)) {
                fprintf(stderr, "ERROR: unable to create login file.\n");
                exit(1);
            }

            sprintf(response, "RLI REG\n");
        }
    }

    int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
	if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit(1);
    }
}

void handle_logout_request(char *uid, char *user_password, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    char response[9];

    if (strlen(uid) != 6 || !is_numeric(uid) || strlen(user_password) != 8 
        || !is_alphanumeric(user_password)) {
        sprintf(response, "RLO ERR\n");
        int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
        if (n == -1)  {
            fprintf(stderr, "ERROR: unable to send response.\n");
            exit(1);
        }
        return;
    }

    char path[19];
    int found_pass = 0, found_login = 0, unregistered = 0;

    sprintf(path, "ASDIR/USERS/%s", uid);
    DIR *dr = opendir(path); 
    struct dirent *de;

    if (dr == NULL && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1); 
    } 

    else if (dr == NULL && errno == 2) { // directory does not exist
        sprintf(response, "RLO UNR\n");
        unregistered = 1;
    }

    closedir(dr);

    if (!unregistered) {
        char pass_file_path[35];
        sprintf(pass_file_path, "ASDIR/USERS/%s/%s_pass.txt", uid, uid);

        if (exists_file(pass_file_path) == 1)
            found_pass = 1;

        char login_file_path[36];
        sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

        if (exists_file(login_file_path) == 1)
            found_login = 1;

        if (!found_pass && !found_login)
            sprintf(response, "RLO UNR\n");

        else if (found_pass && !found_login)
            sprintf(response, "RLO NOK\n");

        else {
            unlink(login_file_path);
            sprintf(response, "RLO OK\n");
        }
    }

    int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
	if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit(1);
    }
}

void handle_unregister_request(char *uid, char *user_password, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    char response[9];

    if (strlen(uid) != 6 || !is_numeric(uid) || strlen(user_password) != 8 
        || !is_alphanumeric(user_password)) {
        sprintf(response, "RUR ERR\n");
        int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
        if (n == -1)  {
            fprintf(stderr, "ERROR: unable to send response.\n");
            exit(1);
        }
        return;
    }

    char path[19];
    int found_pass = 0, found_login = 0, unregistered = 0;

    sprintf(path, "ASDIR/USERS/%s", uid);
    DIR *dr = opendir(path); 
    struct dirent *de;

    if (dr == NULL && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1); 
    } 

    else if (dr == NULL && errno == 2) { // directory does not exist
        sprintf(response, "RUR UNR\n");
        unregistered = 1;
    }

    closedir(dr);

    if (!unregistered) {
        char pass_file_path[35];
        sprintf(pass_file_path, "ASDIR/USERS/%s/%s_pass.txt", uid, uid);

        if (exists_file(pass_file_path) == 1)
            found_pass = 1;

        char login_file_path[36];
        sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

        if (exists_file(login_file_path) == 1)
            found_login = 1;

        if (!found_pass && !found_login)
            sprintf(response, "RUR UNR\n");

        else if (found_pass && !found_login)
            sprintf(response, "RUR NOK\n");

        else {
            unlink(login_file_path);
            unlink(pass_file_path);
            sprintf(response, "RUR OK\n");
        }
    }

    int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
	if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit(1);
    }
}

void handle_myauctions_request(char *uid, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    char response[MAX_BUFFER_MA_MB_L];
    
    if (strlen(uid) != 6 || !is_numeric(uid)) {
        sprintf(response, "RMA ERR\n");
        int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
        if (n == -1)  {
            fprintf(stderr, "ERROR: unable to send response.\n");
            exit(1);
        }
        return;
    }

    char login_file_path[36];
    sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

    if (exists_file(login_file_path) == 0) {
        sprintf(response, "RMA NLG\n");
        int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
        if (n == -1)  {
            fprintf(stderr, "ERROR: unable to send response.\n");
            exit(1);
        }
        return;
    }
        
    char path[26];
    int no_auctions = 0;

    sprintf(path, "ASDIR/USERS/%s/HOSTED", uid);
    struct dirent **filelist;
    int n_entries;
    
    n_entries = scandir(path, &filelist, 0, alphasort);
    if (n_entries == 2 || (n_entries < 0 && errno == 2)) {
        sprintf(response, "RMA NOK\n");
        no_auctions = 1;
    }

    else if (n_entries <= 0 && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1); 
    }

    if (!no_auctions) {
        char aid[AID_SIZE], aid_state[7];
        int state = 1, i = 0;
        long len;

        sprintf(response, "RMA OK");

        while (i != n_entries) {
            if (filelist[i]->d_type == DT_REG) {
                len = strlen(filelist[i]->d_name);

                if (len == 7) {
                    state = 1;
                    sscanf(filelist[i]->d_name, "%[^.].txt", aid);

                    if (strlen(aid) != 3 || !is_numeric(aid)) {
                        fprintf(stderr, "ERROR: aid has wrong format.\n");
                        exit(1); 
                    }
                    
                    char start_file_path[33];
                    sprintf(start_file_path, "ASDIR/AUCTIONS/%s/START_%s.txt", aid, aid);
                    
                    if (exists_file(start_file_path) != 1) {
                        fprintf(stderr, "ERROR: start file for auction %s does not exist.\n", aid);
                        exit(1); 
                    }

                    char end_file_path[31];
                    sprintf(end_file_path, "ASDIR/AUCTIONS/%s/END_%s.txt", aid, aid);

                    if (exists_file(end_file_path) == 1)
                        state = 0;

                    sprintf(aid_state, " %s %d", aid, state);
                    strcat(response, aid_state);
                }

                free(filelist[i]);         
            }
            i++;
        }
        
        free(filelist);
        strcat(response, "\n");
    }

    int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
	if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit(1);
    }
}

void handle_mybids_request(char *uid, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    char response[MAX_BUFFER_MA_MB_L];
    
    if (strlen(uid) != 6 || !is_numeric(uid)) {
        sprintf(response, "RMB ERR\n");
        int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
        if (n == -1)  {
            fprintf(stderr, "ERROR: unable to send response.\n");
            exit(1);
        }
        return;
    }

    char login_file_path[36];
    sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

    if (exists_file(login_file_path) == 0) {
        sprintf(response, "RMB NLG\n");
        int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
        if (n == -1)  {
            fprintf(stderr, "ERROR: unable to send response.\n");
            exit(1);
        }
        return;
    }
        
    char path[26];
    int no_bids = 0;

    sprintf(path, "ASDIR/USERS/%s/BIDDED", uid);
    struct dirent **filelist;
    int n_entries;
    
    n_entries = scandir(path, &filelist, 0, alphasort);
    if (n_entries == 2 || (n_entries < 0 && errno == 2)) {
        sprintf(response, "RMB NOK\n");
        no_bids = 1;
    }

    else if (n_entries <= 0 && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1); 
    }

    if (!no_bids) {
        char aid[AID_SIZE], aid_state[7];
        int state = 1, i = 0;
        long len;

        sprintf(response, "RMB OK");

        while (i != n_entries) {
            if (filelist[i]->d_type == DT_REG) {
                len = strlen(filelist[i]->d_name);

                if (len == 7) {
                    state = 1;
                    sscanf(filelist[i]->d_name, "%[^.].txt", aid);

                    if (strlen(aid) != 3 || !is_numeric(aid)) {
                        fprintf(stderr, "ERROR: aid has wrong format.\n");
                        exit(1); 
                    }

                    char start_file_path[33];
                    sprintf(start_file_path, "ASDIR/AUCTIONS/%s/START_%s.txt", aid, aid);
                    
                    if (exists_file(start_file_path) != 1) {
                        fprintf(stderr, "ERROR: start file for auction %s does not exist.\n", aid);
                        exit(1); 
                    }

                    char end_file_path[31];
                    sprintf(end_file_path, "ASDIR/AUCTIONS/%s/END_%s.txt", aid, aid);
                    
                    if (exists_file(end_file_path) == 1)
                        state = 0;

                    sprintf(aid_state, " %s %d", aid, state);
                    strcat(response, aid_state);
                }

                free(filelist[i]);         
            }
            i++;
        }
        
        free(filelist);
        strcat(response, "\n");
    }

    int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
	if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit(1);
    }
}

void handle_list_request(int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    char response[MAX_BUFFER_MA_MB_L];
        
    char path[15] = "ASDIR/AUCTIONS";
    int no_auctions = 0;

    struct dirent **filelist;
    int n_entries;
    
    n_entries = scandir(path, &filelist, 0, alphasort);
    if (n_entries == 2 || (n_entries < 0 && errno == 2)) {
        sprintf(response, "RLS NOK\n");
        no_auctions = 1;
    }

    else if (n_entries <= 0 && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1); 
    }

    if (!no_auctions) {
        char aid[AID_SIZE], aid_state[7];
        int state = 1, i = 0;
        long len;

        sprintf(response, "RLS OK");

        while (i != n_entries) {
            if (filelist[i]->d_type == DT_DIR) {
                len = strlen(filelist[i]->d_name);

                if (len == 3) {
                    state = 1;
                    sscanf(filelist[i]->d_name, "%s", aid);

                    if (strlen(aid) != 3 || !is_numeric(aid)) {
                        fprintf(stderr, "ERROR: aid has wrong format.\n");
                        exit(1); 
                    }

                    char start_file_path[33];
                    sprintf(start_file_path, "ASDIR/AUCTIONS/%s/START_%s.txt", aid, aid);
                    
                    if (exists_file(start_file_path) != 1) {
                        fprintf(stderr, "ERROR: start file for auction %s does not exist.\n", aid);
                        exit(1); 
                    }

                    char end_file_path[31];
                    sprintf(end_file_path, "ASDIR/AUCTIONS/%s/END_%s.txt", aid, aid);
                    
                    if (exists_file(end_file_path) == 1)
                        state = 0;

                    sprintf(aid_state, " %s %d", aid, state);
                    strcat(response, aid_state);
                }

                free(filelist[i]);         
            }
            i++;
        }
        
        free(filelist);
        strcat(response, "\n");
    }

    int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
	if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit(1);
    }
}

void send_ERR(int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    
    char response[5];
    sprintf(response, "ERR\n");
    
    int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
	if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit(1);
    }
}

int main(int argc, char **argv) {
    int fd, errcode;
    ssize_t n;
    socklen_t addrlen;
    struct addrinfo hints, *res;
    struct sockaddr_in addr;
    
    char ASport[ASPORT_SIZE] = "", buffer[MAX_BUFFER_MA_MB_L] = "", 
         message_type[MESSAGE_TYPE_SIZE] = "";
    int verbose = 0;

    handle_main_arguments(argc, argv, ASport, &verbose);

	while (1) {
        fd = socket(AF_INET, SOCK_DGRAM, 0); //UDP socket
        if (fd == -1) /*error*/ exit(1);

        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET; // IPv4
        hints.ai_socktype = SOCK_DGRAM; // UDP socket
        hints.ai_flags = AI_PASSIVE;

        errcode = getaddrinfo("localhost", ASport, &hints, &res);
        if (errcode != 0) /*error*/ exit(1);

        n = bind(fd, res->ai_addr, res->ai_addrlen);
        if (n == -1) /*error*/ exit(1);

		addrlen = sizeof(addr);
		n = recvfrom(fd, buffer, MAX_BUFFER_MA_MB_L, 0, (struct sockaddr*) &addr, &addrlen);
        if (n == -1) /*error*/ exit(1);

        sscanf(buffer, "%3s", message_type);

        if (!strcmp(message_type, "LIN")) {
            char uid[UID_SIZE], password[PASSWORD_SIZE];
            sscanf(&buffer[4], "%s %s", uid, password);

            if (buffer[3] != ' ' || buffer[10] != ' ' || buffer[19] != '\n')
                send_ERR(fd, addr);

            else 
                handle_login_request(uid, password, fd, addr);
        }

        else if (!strcmp(message_type, "LOU")) {
            char uid[UID_SIZE], password[PASSWORD_SIZE];
            sscanf(&buffer[4], "%s %s", uid, password);

            if (buffer[3] != ' ' || buffer[10] != ' ' || buffer[19] != '\n')
                send_ERR(fd, addr);

            else 
                handle_logout_request(uid, password, fd, addr);
        }

        else if (!strcmp(message_type, "UNR")) {
            char uid[UID_SIZE], password[PASSWORD_SIZE];
            sscanf(&buffer[4], "%s %s", uid, password);

            if (buffer[3] != ' ' || buffer[10] != ' ' || buffer[19] != '\n')
                send_ERR(fd, addr);

            else 
                handle_unregister_request(uid, password, fd, addr);
        }

        else if (!strcmp(message_type, "LMA")) {
            char uid[UID_SIZE];
            sscanf(&buffer[4], "%s", uid);

            if (buffer[3] != ' ' || buffer[10] != '\n')
                send_ERR(fd, addr);

            else 
                handle_myauctions_request(uid, fd, addr);
        }

        else if (!strcmp(message_type, "LMB")) {
            char uid[UID_SIZE];
            sscanf(&buffer[4], "%s", uid);

            if (buffer[3] != ' ' || buffer[10] != '\n')
                send_ERR(fd, addr);

            else 
                handle_mybids_request(uid, fd, addr);
        }

        else if (!strcmp(message_type, "LST"))
            handle_list_request(fd, addr);

        else if (!strcmp(message_type, "SRC")) {

        }

        else if (!strcmp(message_type, "OPA")) {

        }

        else if (!strcmp(message_type, "CLS")) {

        }

        else if (!strcmp(message_type, "SAS")) {

        }

        else if (!strcmp(message_type, "BID")) {

        }

        else {}

        freeaddrinfo(res);
        close(fd);
	}

    return 0;
}