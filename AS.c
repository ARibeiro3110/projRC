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
#include <sys/time.h>

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

int exists_file(char *path) {
    struct stat filestat;
    int retstat;
    retstat = stat(path, &filestat);

    if ((filestat.st_mode & __S_IFMT) != __S_IFREG)
        return 0;

    if (retstat == -1 && errno == 2) 
        return 0;

    else if (retstat == -1 && errno != 2) 
        return -1;  

    else 
        return 1;
}

int exists_dir(char *path) {
    struct stat filestat;
    int retstat;
    retstat = stat(path, &filestat);

    if ((filestat.st_mode & __S_IFMT) != __S_IFDIR)
        return 0;

    if (retstat == -1 && errno == 2) 
        return 0;

    else if (retstat == -1 && errno != 2) 
        return -1;  

    else 
        return 1;
}

void setup_environment() {
    if (!exists_dir("ASDIR"))
        if (mkdir("ASDIR", 0700) == -1) {
            fprintf(stderr, "ERROR: unable to create ASDIR.\n");
            exit(1);
        }
    if (!exists_dir("ASDIR/USERS"))
        if (mkdir("ASDIR/USERS", 0700) == -1) {
            fprintf(stderr, "ERROR: unable to create USERS.\n");
            exit(1);
        }

    if (!exists_dir("ASDIR/AUCTIONS"))
        if (mkdir("ASDIR/AUCTIONS", 0700) == -1) {
            fprintf(stderr, "ERROR: unable to create AUCTIONS.\n");
            exit(1);
        }
}

void create_password(char *uid, char *password) {
    char pass_file_path[36];
    FILE *fp;
    
    sprintf(pass_file_path, "ASDIR/USERS/%s/%s_pass.txt", uid, uid);
    fp = fopen(pass_file_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: unable to create password file.\n");
        exit(1);
    }
    
    fprintf(fp, "%s\n", password);
    fclose(fp);
}

void create_login(char *uid) {
    char login_name[37];
    FILE *fp;
    
    sprintf(login_name, "ASDIR/USERS/%s/%s_login.txt", uid, uid);
    fp = fopen(login_name, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: unable to create login file.\n");
        exit(1);
    }
    
    fprintf(fp, "Logged in\n");
    fclose(fp);
}

void send_ERR(int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    int n = sendto(fd, "ERR\n", 4, 0, (struct sockaddr*) &addr, addrlen);
	if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit(1);
    }
}

void send_response_ERR(char *prefix, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    
    char response[9];
    sprintf(response, "%s ERR\n", prefix);

    int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
    if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit(1);
    }
}

void send_response(char *response, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    
    int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
	if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit(1);
    }
}

void handle_login_request(char *uid, char *user_password, int fd, struct sockaddr_in addr) {
    char response[9];

    if (strlen(uid) != 6 || !is_numeric(uid) || strlen(user_password) != 8 
        || !is_alphanumeric(user_password)) {
        send_response_ERR("RLI", fd, addr);
        return;
    }

    char path[19];
    sprintf(path, "ASDIR/USERS/%s", uid);
    
    if (!exists_dir(path)) { // directory does not exist
        if (mkdir(path, 0700) == -1) {
            fprintf(stderr, "ERROR: unable to create %s directory file.\n", uid);
            exit(1);
        }
        
        create_password(uid, user_password);
        create_login(uid);
        sprintf(response, "RLI REG\n");
    }

    else {
        char pass_file_path[35], file_password[9];
        sprintf(pass_file_path, "ASDIR/USERS/%s/%s_pass.txt", uid, uid);

        if (exists_file(pass_file_path) == 1) {
            FILE *fp = fopen(pass_file_path, "r");
            if (fp == NULL) {
                fprintf(stderr, "ERROR: %d unable to open pass file.\n", errno);
                exit(1);
            }
            
            fread(file_password, 1, 8, fp);
            file_password[8] = '\0';
            fclose(fp);

            if (!strcmp(file_password, user_password)) {
                create_login(uid);
                sprintf(response, "RLI OK\n");
            }

            else
                sprintf(response, "RLI NOK\n");
        }

        else {
            create_password(uid, user_password);
            create_login(uid);
            sprintf(response, "RLI REG\n");
        }
    }

    send_response(response, fd, addr);
}

void handle_logout_request(char *uid, char *user_password, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    char response[9];

    if (strlen(uid) != 6 || !is_numeric(uid) || strlen(user_password) != 8 
        || !is_alphanumeric(user_password)) {
        send_response_ERR("RLO", fd, addr);
        return;
    }

    char path[19];
    int found_pass = 0, found_login = 0;

    sprintf(path, "ASDIR/USERS/%s", uid);
    if (!exists_dir(path))    // directory does not exist
        sprintf(response, "RLO UNR\n");
    
    else {
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

    send_response(response, fd, addr);
}

void handle_unregister_request(char *uid, char *user_password, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    char response[9];

    if (strlen(uid) != 6 || !is_numeric(uid) || strlen(user_password) != 8 
        || !is_alphanumeric(user_password)) {
        send_response_ERR("RUR", fd, addr);
        return;
    }

    char path[19];
    int found_pass = 0, found_login = 0;

    sprintf(path, "ASDIR/USERS/%s", uid);
    if (!exists_dir(path)) // directory does not exist
        sprintf(response, "RUR UNR\n");

    else {
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

    send_response(response, fd, addr);
}

void append_auctions(char *response, struct dirent **filelist, int n_entries) {
    char aid[AID_SIZE], aid_state[7];
    int state = 1, i = 0;
    long len;

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

void handle_myauctions_request(char *uid, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    char response[MAX_BUFFER_MA_MB_L];
    
    if (strlen(uid) != 6 || !is_numeric(uid)) {
        send_response_ERR("RMA", fd, addr);
        return;
    }

    char login_file_path[36];
    sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

    if (exists_file(login_file_path) == 0) {
        sprintf(response, "RMA NLG\n");
        send_response(response, fd, addr);
        return;
    }
        
    char path[26];
    sprintf(path, "ASDIR/USERS/%s/HOSTED", uid);
    
    struct dirent **filelist;
    int n_entries;
    
    n_entries = scandir(path, &filelist, 0, alphasort);
    if (n_entries == 2 || (n_entries < 0 && errno == 2)) 
        sprintf(response, "RMA NOK\n");

    else if (n_entries <= 0 && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1); 
    }

    else {
        sprintf(response, "RMA OK");
        append_auctions(response, filelist, n_entries);
    }

    send_response(response, fd, addr);
}

void handle_mybids_request(char *uid, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    char response[MAX_BUFFER_MA_MB_L];
    
    if (strlen(uid) != 6 || !is_numeric(uid)) {
        send_response_ERR("RMB", fd, addr);
        return;
    }

    char login_file_path[36];
    sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

    if (exists_file(login_file_path) == 0) {
        sprintf(response, "RMB NLG\n");
        send_response(response, fd, addr);
        return;
    }
        
    char path[26];
    sprintf(path, "ASDIR/USERS/%s/BIDDED", uid);
    
    struct dirent **filelist;
    int n_entries;
    
    n_entries = scandir(path, &filelist, 0, alphasort);
    if (n_entries == 2 || (n_entries < 0 && errno == 2))
        sprintf(response, "RMB NOK\n");

    else if (n_entries <= 0 && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1); 
    }

    else {
        sprintf(response, "RMB OK");
        append_auctions(response, filelist, n_entries);
    }

   send_response(response, fd, addr);
}

void append_auctions_list(char *response, struct dirent **filelist, int n_entries) {
    char aid[AID_SIZE], aid_state[7];
    int state = 1, i = 0;
    long len;

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

void handle_list_request(int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    char response[MAX_BUFFER_MA_MB_L];
        
    char path[15] = "ASDIR/AUCTIONS";

    struct dirent **filelist;
    int n_entries;
    
    n_entries = scandir(path, &filelist, 0, alphasort);
    if (n_entries == 2 || (n_entries < 0 && errno == 2))
        sprintf(response, "RLS NOK\n");

    else if (n_entries <= 0 && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1); 
    }

    else {
        sprintf(response, "RLS OK");
        append_auctions_list(response, filelist, n_entries);
    }

    send_response(response, fd, addr);
}

int get_bid_list(char *bid_info, char *aid) {
    struct dirent **filelist;
    int n_entries, n_bids, len;
    char dirname[25], pathname[36], buffer[43];
    
    sprintf(dirname, "ASDIR/AUCTIONS/%s/BIDS", aid);
    
    n_entries = scandir(dirname, &filelist, 0, alphasort) ;
    
    if (n_entries == 2 || (n_entries < 0 && errno == 2))
        return 0;
        
    else if (n_entries <= 0 && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1); 
    }

    char bid_value[VALUE_SIZE] = "";

    n_bids = 0;
    while (n_entries--) {
        len = strlen(filelist[n_entries]->d_name) ;
        if (len == 10) {
            sscanf(filelist[n_entries]->d_name, "%s.txt", bid_value);
            sprintf(pathname, "ASDIR/AUCTIONS/%s/BIDS/%s", aid, bid_value) ;
            
            FILE *fp = fopen(pathname, "r");
            if (fp == NULL) {
                fprintf(stderr, "ERROR: unable to open bid file.\n");
                exit(1);
            }

            fgets(buffer, 40, fp);
            fclose(fp);

            char bidder_uid[UID_SIZE] = "", bid_date[DATE_SIZE] = "", 
                 bid_time[TIME_SIZE] = "", bid_sec_time[SEC_SIZE] = ""; 
            sscanf(buffer, "%6s %6s %10s %8s %s", bidder_uid, bid_value, bid_date, bid_time, bid_sec_time);

            if (strlen(bidder_uid) != 6 || !is_numeric(bidder_uid) 
                || strlen(bid_value) > 6 || !is_numeric(bid_value) 
                || !is_date(bid_date) || !is_time(bid_time) 
                || strlen(bid_sec_time) > 5 || !is_numeric(bid_sec_time)) {
                fprintf(stderr, "ERROR: bid file has message in wrong bids format\n");
                exit(1); 
            }

            strcat(bid_info, " B ");
            strcat(bid_info, buffer);

            ++n_bids;
        }
        
        free(filelist[n_entries]) ;
        
        if (n_bids == 50)
            break;
    }

    free(filelist);
    return n_bids;
}

int get_closed_info(char *closed_info, char *aid) {
    char end_file_path[31];
    sprintf(end_file_path, "ASDIR/AUCTIONS/%s/END_%s.txt", aid, aid);
    
    if (!exists_file(end_file_path))
        return 0;
    
    else {
        char buffer[26];

        FILE *fp = fopen(end_file_path, "r");
        if (fp == NULL) {
            fprintf(stderr, "ERROR: unable to open bid file.\n");
            exit(1);
        }

        fgets(buffer, 26, fp);
        fclose(fp);

        char end_date[DATE_SIZE] = "", end_time[TIME_SIZE] = "", end_sec_time[SEC_SIZE] = "";
        sscanf(buffer, "%10s %8s %s", end_date, end_time, end_sec_time);

        if (!is_date(end_date) || !is_time(end_time) 
            || strlen(end_sec_time) > 5 || !is_numeric(end_sec_time)) {
            fprintf(stderr, "ERROR: server sent message in wrong closure format\n");
            exit(1); 
        }

        strcat(closed_info, " E ");
        strcat(closed_info, buffer);
    }

    return 1;
}

void handle_show_record_request(char *aid, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);
    char response[SRC_BUFFER_SIZE], buffer[76];
    
    if (strlen(aid) != 3 || !is_numeric(aid)) {
        send_response_ERR("RRC", fd, addr);
        return;
    }

    char path[33];
    sprintf(path, "ASDIR/AUCTIONS/%s/START_%s.txt", aid, aid);
    
    if (!exists_file(path))
        sprintf(response, "RRC NOK\n"); 

    else {
        sprintf(response, "RRC OK ");
        
        FILE *fp = fopen(path, "r");
        if (fp == NULL) {
            fprintf(stderr, "ERROR: unable to open start file.\n");
            exit(1);
        }

        fgets(buffer, 76, fp);
        fclose(fp);

        int buffer_len = strlen(buffer);
        if (buffer_len < 76)
            buffer[buffer_len - 1] = '\0';

        char host_uid[UID_SIZE] = "", auction_name[NAME_SIZE] = "", 
             asset_fname[FILENAME_SIZE] = "", start_value[VALUE_SIZE] = "", 
             start_date[DATE_SIZE] = "", start_time[TIME_SIZE] = "", 
             timeactive[SEC_SIZE] = "";
        
        sscanf(buffer, "%6s %10s %24s %6s %10s %8s %s", host_uid, auction_name, 
               asset_fname, start_value, start_date, start_time, timeactive);

        if (strlen(host_uid) != 6 || !is_numeric(host_uid) || strlen(auction_name) > 10 
            || !is_alphanumeric(auction_name) || !is_filename(asset_fname) 
            || strlen(start_value) > 6 || !is_numeric(start_value) 
            || !is_date(start_date) || !is_time(start_time) || strlen(timeactive) > 5 
            || !is_numeric(timeactive)) {
            fprintf(stderr, "ERROR: start file information in wrong format\n");
            return;
        }

        strcat(response, buffer);
        
        char bid_info[BID_INFO_SIZE] = "";
        if (get_bid_list(bid_info, aid))
            strcat(response, bid_info);

        char closed_info[CLOSED_INFO_SIZE] = "";
        if (get_closed_info(closed_info, aid))
            strcat(response, closed_info);

        strcat(response, "\n");
        send_response(response, fd, addr);
    }
}

void handle_udp_request(int fd_udp, struct sockaddr_in addr_udp) {
    char buffer[LIN_LOU_UNR_MESSAGE_SIZE] = "", message_type[MESSAGE_TYPE_SIZE] = "";
    
    socklen_t addrlen = sizeof(addr_udp);
    int n = recvfrom(fd_udp, buffer, LIN_LOU_UNR_MESSAGE_SIZE, 0, (struct sockaddr*) &addr_udp, &addrlen);
    if (n == -1) /*error*/ exit(1);

    sscanf(buffer, "%3s", message_type);

    if (!strcmp(message_type, "LIN")) {
        char uid[UID_SIZE], password[PASSWORD_SIZE];
        sscanf(&buffer[4], "%s %s", uid, password);

        if (buffer[3] != ' ' || buffer[10] != ' ' || buffer[19] != '\n')
            send_ERR(fd_udp, addr_udp);

        else 
            handle_login_request(uid, password, fd_udp, addr_udp);
    }

    else if (!strcmp(message_type, "LOU")) {
        char uid[UID_SIZE], password[PASSWORD_SIZE];
        sscanf(&buffer[4], "%s %s", uid, password);

        if (buffer[3] != ' ' || buffer[10] != ' ' || buffer[19] != '\n')
            send_ERR(fd_udp, addr_udp);

        else 
            handle_logout_request(uid, password, fd_udp, addr_udp);
    }

    else if (!strcmp(message_type, "UNR")) {
        char uid[UID_SIZE], password[PASSWORD_SIZE];
        sscanf(&buffer[4], "%s %s", uid, password);

        if (buffer[3] != ' ' || buffer[10] != ' ' || buffer[19] != '\n')
            send_ERR(fd_udp, addr_udp);

        else 
            handle_unregister_request(uid, password, fd_udp, addr_udp);
    }

    else if (!strcmp(message_type, "LMA")) {
        char uid[UID_SIZE];
        sscanf(&buffer[4], "%s", uid);

        if (buffer[3] != ' ' || buffer[10] != '\n')
            send_ERR(fd_udp, addr_udp);

        else 
            handle_myauctions_request(uid, fd_udp, addr_udp);
    }

    else if (!strcmp(message_type, "LMB")) {
        char uid[UID_SIZE];
        sscanf(&buffer[4], "%s", uid);

        if (buffer[3] != ' ' || buffer[10] != '\n')
            send_ERR(fd_udp, addr_udp);

        else 
            handle_mybids_request(uid, fd_udp, addr_udp);
    }

    else if (!strcmp(message_type, "LST"))
        handle_list_request(fd_udp, addr_udp);

    else if (!strcmp(message_type, "SRC")) {
        char aid[AID_SIZE];
        sscanf(&buffer[4], "%s", aid);

        if (buffer[3] != ' ' || buffer[7] != '\n')
            send_ERR(fd_udp, addr_udp);

        else 
            handle_show_record_request(aid, fd_udp, addr_udp);
    }

    else
        send_ERR(fd_udp, addr_udp);
}

void handle_tcp_request(int fd_tcp, struct sockaddr_in addr_tcp) {
    char buffer[OPA_MESSAGE_SIZE] = "", message_type[MESSAGE_TYPE_SIZE] = "";
    
    socklen_t addrlen = sizeof(addr_tcp);
    int newfd, n;

    if ((newfd = accept(fd_tcp, (struct sockaddr *) &addr_tcp, &addrlen)) == -1)
        exit(1);

    n = read(newfd, buffer, OPA_MESSAGE_SIZE);
    if (n == -1) exit(1);

    sscanf(buffer, "%3s", message_type);

    if (!strcmp(message_type, "OPA")) {

    }

    else if (!strcmp(message_type, "CLS")) {

    }

    else if (!strcmp(message_type, "SAS")) {

    }

    else if (!strcmp(message_type, "BID")) {

    }

    else
        send_ERR(fd_tcp, addr_tcp);
}

int main(int argc, char **argv) {
    char ASport[ASPORT_SIZE] = "";
    int verbose = 0;

    handle_main_arguments(argc, argv, ASport, &verbose);
    setup_environment();

    int fd_udp, fd_tcp, errcode, out_fds;
    ssize_t n;
    struct addrinfo hints_udp, *res_udp, hints_tcp, *res_tcp;
    struct sockaddr_in addr_udp, addr_tcp;

    // UDP socket
    fd_udp = socket(AF_INET, SOCK_DGRAM, 0); 
    if (fd_udp == -1) /*error*/ exit(1);

    memset(&hints_udp, 0, sizeof hints_udp);
    hints_udp.ai_family = AF_INET; 
    hints_udp.ai_socktype = SOCK_DGRAM; 
    hints_udp.ai_flags = AI_PASSIVE;

    errcode = getaddrinfo("localhost", ASport, &hints_udp, &res_udp);
    if (errcode != 0) /*error*/ exit(1);

    n = bind(fd_udp, res_udp->ai_addr, res_udp->ai_addrlen);
    if (n == -1) /*error*/ exit(1);
    
    // TCP socket
    fd_tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_tcp == -1) exit(1);

    memset(&hints_tcp, 0, sizeof hints_tcp);
    hints_tcp.ai_family = AF_INET;
    hints_tcp.ai_socktype = SOCK_STREAM;
    hints_tcp.ai_flags = AI_PASSIVE;

    errcode = getaddrinfo("localhost", ASport, &hints_tcp, &res_tcp);
    if (errcode != 0) /*error*/ exit(1);

    n = bind(fd_tcp, res_tcp->ai_addr, res_tcp->ai_addrlen);
    if (n == -1) /*error*/ exit(1);

    if (listen(fd_tcp, 5) == -1) /*error*/ exit(1);

    // init select
    fd_set inputs, testfds;
    FD_ZERO(&inputs);        // Clear input mask
    FD_SET(0, &inputs);      // Set standard input channel on
    FD_SET(fd_udp, &inputs); // Set UDP channel on
    FD_SET(fd_tcp, &inputs); // Set TCP channel on

	while (1) {
        testfds = inputs; // Reload mask
        out_fds = select(FD_SETSIZE, &testfds, (fd_set *) NULL, (fd_set *) NULL, (struct timeval *) NULL);

        switch (out_fds) {
            case -1:
                perror("ERROR: select");
                exit(1);

            default:
                if (FD_ISSET(fd_udp, &testfds))
                    handle_udp_request(fd_udp, addr_udp);

                if (FD_ISSET(fd_tcp, &testfds))
                   handle_tcp_request(fd_tcp, addr_tcp);
        }
	}

    freeaddrinfo(res_udp);
    close(fd_udp);

    freeaddrinfo(res_tcp);
    close(fd_tcp);

    return 0;
}