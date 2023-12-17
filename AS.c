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
#include <time.h>
#include <signal.h>
#include <semaphore.h>

#include "common.h"
#include "AS.h"

// Global variables
int fd_udp, fd_tcp; // used to close the server graciously
sem_t *sem[1000]; // Semaphores used with the auctions or the whole ASDIR // TODO README
sem_t *sem_user; // Semaphore used with the users
pid_t main_pid; // stores the pid of the main process

void exit_server(int code) {
    close(fd_udp);
    close(fd_tcp);

    for (int i = 0; i < 1000; i++) {
        char semName[13];
        sprintf(semName, "semaphore%03d", i);
        sem_close(sem[i]);
        sem_unlink(semName);
    }
    sem_close(sem_user);
    sem_unlink("semaphore_user");
    exit(code);
}

void sem_wait_(sem_t *sem) {
    if (sem_wait(sem) == -1) {
        fprintf(stderr, "ERROR: unable to lock semaphore.\n");
        exit_server(1);
    }
}

void sem_post_(sem_t *sem) {
    if (sem_post(sem) == -1) {
        fprintf(stderr, "ERROR: unable to lock semaphore.\n");
        exit_server(1);
    }
}

void sigint_detected(int sig) {
    // In some systems, after the handler call the signal gets reverted
    // to SIG_DFL (the default action associated with the signal).
    // So we set the signal handler back to our function after each trap.

    if (sig == SIGINT) {
        if (signal(SIGINT, sigint_detected) != SIG_ERR) {
            if (getpid() == main_pid)
                write(0, "\nSIGINT DETECTED, SHUTTING DOWN PROCESS...\n", 44);
            exit_server(0);
        }
    }
}

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
        fclose(fp);
        exit_server(1);
    }

    fprintf(fp, "%s", password);
    fclose(fp);
}

void create_login(char *uid) {
    char login_name[37];
    FILE *fp;

    sprintf(login_name, "ASDIR/USERS/%s/%s_login.txt", uid, uid);
    fp = fopen(login_name, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: unable to create login file.\n");
        fclose(fp);
        exit_server(1);
    }

    fprintf(fp, "Logged in");
    fclose(fp);
}

void send_udp_ERR(int fd, struct sockaddr_in addr, int verbose) {
    socklen_t addrlen = sizeof(addr);
    int n = sendto(fd, "ERR\n", 4, 0, (struct sockaddr*) &addr, addrlen);
	if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit_server(1);
    }

    if (verbose)
        printf("Unexpected protocol message. ERR sent to client\n\n");
}

void send_udp_response_ERR(char *prefix, int fd, struct sockaddr_in addr, int verbose) {
    socklen_t addrlen = sizeof(addr);

    char response[9];
    sprintf(response, "%s ERR\n", prefix);

    int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
    if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit_server(1);
    }

    if (verbose)
        printf("Syntax of the request message was incorrect or parameter values are invalid. %s ERR sent to client\n\n", prefix);
}

void send_udp_response(char *response, int fd, struct sockaddr_in addr) {
    socklen_t addrlen = sizeof(addr);

    int n = sendto(fd, response, strlen(response), 0, (struct sockaddr*) &addr, addrlen);
	if (n == -1)  {
        fprintf(stderr, "ERROR: unable to send response.\n");
        exit_server(1);
    }
}

void handle_login_request(char *uid, char *user_password, int fd, struct sockaddr_in addr, int verbose) {
    char response[14];

    if (strlen(uid) != 6 || !is_numeric(uid) || strlen(user_password) != 8
        || !is_alphanumeric(user_password)) {
        send_udp_response_ERR("RLI", fd, addr, verbose);
        return;
    }

    char path[19];
    sprintf(path, "ASDIR/USERS/%s", uid);

    sem_wait_(sem_user);

    if (!exists_dir(path)) { // directory does not exist
        if (mkdir(path, 0700) == -1) {
            fprintf(stderr, "ERROR: unable to create %s directory.\n", uid);
            exit_server(1);
        }

        char hosted_dir_path[24];
        sprintf(hosted_dir_path, "ASDIR/USERS/%s/HOSTED/", uid);
        if (mkdir(hosted_dir_path, 0700) == -1) {
            fprintf(stderr, "ERROR: unable to create %s hosted directory.\n", uid);
            exit_server(1);
        }

        char bidded_dir_path[24];
        sprintf(bidded_dir_path, "ASDIR/USERS/%s/BIDDED/", uid);
        if (mkdir(bidded_dir_path, 0700) == -1) {
            fprintf(stderr, "ERROR: unable to create %s bidded directory.\n", uid);
            exit_server(1);
        }

        create_password(uid, user_password);
        create_login(uid);
        sprintf(response, "RLI REG\n");

        if (verbose)
            printf("UID=%s: login request; new user, registered in database\n\n", uid);
    }

    else {
        char pass_file_path[35], file_password[9];
        sprintf(pass_file_path, "ASDIR/USERS/%s/%s_pass.txt", uid, uid);

        if (exists_file(pass_file_path) == 1) {
            FILE *fp = fopen(pass_file_path, "r");
            if (fp == NULL) {
                fprintf(stderr, "ERROR: %d unable to open pass file.\n", errno);
                exit_server(1);
            }

            int ret = fread(file_password, 1, 8, fp);
            if (ret < 8) {
                fprintf(stderr, "ERROR: pass file read failed\n");
                exit_server(1);
            }

            file_password[8] = '\0';
            fclose(fp);

            if (!strcmp(file_password, user_password)) {
                create_login(uid);
                sprintf(response, "RLI OK\n");

                if (verbose)
                    printf("UID=%s: login request; registered user\n\n", uid);
            }

            else {
                sprintf(response, "RLI NOK\n");
                if (verbose)
                    printf("UID=%s: login request; incorrect match, login failed\n\n", uid);
            }
        }

        else {
            create_password(uid, user_password);
            create_login(uid);
            sprintf(response, "RLI REG\n");

            if (verbose)
                printf("UID=%s: login request; new user, registered in database\n\n", uid);
        }
    }

    sem_post_(sem_user);
    send_udp_response(response, fd, addr);
}

void handle_logout_request(char *uid, char *user_password, int fd, struct sockaddr_in addr, int verbose) {
    char response[9];

    if (strlen(uid) != 6 || !is_numeric(uid) || strlen(user_password) != 8
        || !is_alphanumeric(user_password)) {
        send_udp_response_ERR("RLO", fd, addr, verbose);
        return;
    }

    char path[19];
    int found_pass = 0, found_login = 0;

    sprintf(path, "ASDIR/USERS/%s", uid);
    sem_wait_(sem_user);

    if (!exists_dir(path)) {   // directory does not exist
        sprintf(response, "RLO UNR\n");

        if (verbose)
            printf("UID=%s: logout request; unregistered user, logout failed\n\n", uid);
    }

    else {
        char pass_file_path[35];
        sprintf(pass_file_path, "ASDIR/USERS/%s/%s_pass.txt", uid, uid);

        if (exists_file(pass_file_path) == 1) {
            found_pass = 1;

            char file_password[PASSWORD_SIZE];
            FILE *fp = fopen(pass_file_path, "r");
            if (fp == NULL) {
                fprintf(stderr, "ERROR: %d unable to open pass file.\n", errno);
                exit_server(1);
            }

            int ret = fread(file_password, 1, 8, fp);
            if (ret < 8) {
                fprintf(stderr, "ERROR: pass file read failed\n");
                exit_server(1);
            }

            file_password[8] = '\0';
            fclose(fp);

            if (strcmp(file_password, user_password)) {
                sprintf(response, "RLO NOK\n");

                if (verbose)
                    printf("UID=%s: logout request; password is incorrect, logout failed\n\n", uid);

                send_udp_response(response, fd, addr);
                return;
            }
        }

        char login_file_path[36];
        sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

        if (exists_file(login_file_path) == 1)
            found_login = 1;

        if (!found_pass && !found_login) {
            sprintf(response, "RLO UNR\n");

            if (verbose)
                printf("UID=%s: logout request; unregistered user, logout failed\n\n", uid);
        }

        else if (found_pass && !found_login) {
            sprintf(response, "RLO NOK\n");

            if (verbose)
                printf("UID=%s: logout request; user not logged in, logout failed\n\n", uid);
        }

        else {
            unlink(login_file_path);
            sprintf(response, "RLO OK\n");

            if (verbose)
                printf("UID=%s: logout request; user logged out\n\n", uid);
        }
    }

    sem_post_(sem_user);
    send_udp_response(response, fd, addr);
}

void handle_unregister_request(char *uid, char *user_password, int fd, struct sockaddr_in addr, int verbose) {
    char response[9];

    if (strlen(uid) != 6 || !is_numeric(uid) || strlen(user_password) != 8
        || !is_alphanumeric(user_password)) {
        send_udp_response_ERR("RUR", fd, addr, verbose);
        return;
    }

    char path[19];
    int found_pass = 0, found_login = 0;

    sprintf(path, "ASDIR/USERS/%s", uid);
    sem_wait_(sem_user);

    if (!exists_dir(path)) { // directory does not exist
        sprintf(response, "RUR UNR\n");

        if (verbose)
            printf("UID=%s: unregister request; unregistered user, unregister failed\n\n", uid);
    }

    else {
        char pass_file_path[35];
        sprintf(pass_file_path, "ASDIR/USERS/%s/%s_pass.txt", uid, uid);

        if (exists_file(pass_file_path) == 1)
            found_pass = 1;

        char login_file_path[36];
        sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

        if (exists_file(login_file_path) == 1)
            found_login = 1;

        if (!found_pass && !found_login) {
            sprintf(response, "RUR UNR\n");

            if (verbose)
                printf("UID=%s: unregister request; unregistered user, unregister failed\n\n", uid);
        }

        else if (found_pass && !found_login) {
            sprintf(response, "RUR NOK\n");

            if (verbose)
                printf("UID=%s: unregister request; user not logged in, unregister failed\n\n", uid);
        }

        else {
            unlink(login_file_path);
            unlink(pass_file_path);
            sprintf(response, "RUR OK\n");

            if (verbose)
                printf("UID=%s: unregister request; user unregistered\n\n", uid);
        }
    }

    sem_post_(sem_user);
    send_udp_response(response, fd, addr);
}

int auction_duration_has_expired(char *aid, char *start_file_path) {
    FILE *fp_start = fopen(start_file_path, "r");
    if (fp_start == NULL) {
        fprintf(stderr, "ERROR: unable to open start file.\n");
        return -1;
    }

    char buffer[96];
    fgets(buffer, 96, fp_start);  // read until \n

    int timeactive;
    sscanf(buffer, "%*s %*s %*s %*d %*s %*s %d", &timeactive);

    if (timeactive < 0 || timeactive > 99999)   
        exit_server(1);

    fgets(buffer, 20, fp_start);  // read start_fulltime (long max 19 digits)
    buffer[strlen(buffer)] = '\0';
    fclose(fp_start);

    int start_fulltime = atoi(buffer), time_limit = start_fulltime + timeactive;

    time_t fulltime;
    time(&fulltime);

    if (fulltime >= time_limit)
        return 1;

    return 0;
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
                    exit_server(1);
                }

                char start_file_path[33];
                sprintf(start_file_path, "ASDIR/AUCTIONS/%s/START_%s.txt", aid, aid);
                sem_wait_(sem[atoi(aid)]);

                if (exists_file(start_file_path) != 1) {
                    fprintf(stderr, "ERROR: start file for auction %s does not exist.\n", aid);
                    exit_server(1);
                }

                char end_file_path[31];
                sprintf(end_file_path, "ASDIR/AUCTIONS/%s/END_%s.txt", aid, aid);

                if (exists_file(end_file_path) == 1)
                    state = 0;

                else if (auction_duration_has_expired(aid, start_file_path)) {
                    state = 0;
                    create_close(end_file_path, start_file_path);
                }

                sem_post_(sem[atoi(aid)]);
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

void handle_myauctions_request(char *uid, int fd, struct sockaddr_in addr, int verbose) {
    char response[MAX_BUFFER_MA_MB_L];

    if (strlen(uid) != 6 || !is_numeric(uid)) {
        send_udp_response_ERR("RMA", fd, addr, verbose);
        return;
    }

    char login_file_path[36];
    sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

    if (exists_file(login_file_path) == 0) {
        sprintf(response, "RMA NLG\n");
        send_udp_response(response, fd, addr);

        if (verbose)
            printf("UID=%s: my_auctions request; user not logged in, listing failed\n\n", uid);
        return;
    }

    char path[26];
    sprintf(path, "ASDIR/USERS/%s/HOSTED", uid);

    struct dirent **filelist;
    int n_entries;

    n_entries = scandir(path, &filelist, 0, alphasort);
    if (n_entries == 2 || (n_entries < 0 && errno == 2)) {
        sprintf(response, "RMA NOK\n");

        if (verbose)
            printf("UID=%s: my_auctions request; user has no hosted auctions\n\n", uid);
    }

    else if (n_entries <= 0 && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1);
    }

    else {
        sprintf(response, "RMA OK");
        append_auctions(response, filelist, n_entries);

        if (verbose)
            printf("UID=%s: my_auctions request; auctions listed\n\n", uid);
    }

    send_udp_response(response, fd, addr);
}

void handle_mybids_request(char *uid, int fd, struct sockaddr_in addr, int verbose) {
    char response[MAX_BUFFER_MA_MB_L];

    if (strlen(uid) != 6 || !is_numeric(uid)) {
        send_udp_response_ERR("RMB", fd, addr, verbose);
        return;
    }

    char login_file_path[36];
    sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

    if (exists_file(login_file_path) == 0) {
        sprintf(response, "RMB NLG\n");
        send_udp_response(response, fd, addr);

        if (verbose)
            printf("UID=%s: my_bids request; user not logged in, listing failed\n\n", uid);
        return;
    }

    char path[26];
    sprintf(path, "ASDIR/USERS/%s/BIDDED", uid);

    struct dirent **filelist;
    int n_entries;

    n_entries = scandir(path, &filelist, 0, alphasort);
    if (n_entries == 2 || (n_entries < 0 && errno == 2)) {
        sprintf(response, "RMB NOK\n");

        if (verbose)
            printf("UID=%s: my_bids request; user has no placed bids\n\n", uid);
    }

    else if (n_entries <= 0 && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1);
    }

    else {
        sprintf(response, "RMB OK");
        append_auctions(response, filelist, n_entries);

        if (verbose)
            printf("UID=%s: my_bids request; bids listed\n\n", uid);
    }

   send_udp_response(response, fd, addr);
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
                sem_wait_(sem[atoi(aid)]);

                if (exists_file(start_file_path) != 1) {
                    fprintf(stderr, "ERROR: start file for auction %s does not exist.\n", aid);
                    exit(1);
                }

                char end_file_path[31];
                sprintf(end_file_path, "ASDIR/AUCTIONS/%s/END_%s.txt", aid, aid);

                if (exists_file(end_file_path) == 1)
                    state = 0;

                else if (auction_duration_has_expired(aid, start_file_path)) {
                    state = 0;
                    create_close(end_file_path, start_file_path);
                }

                sem_post_(sem[atoi(aid)]);
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

void handle_list_request(int fd, struct sockaddr_in addr, int verbose) {
    char response[MAX_BUFFER_MA_MB_L];

    char path[15] = "ASDIR/AUCTIONS";

    struct dirent **filelist;
    int n_entries;

    n_entries = scandir(path, &filelist, 0, alphasort);
    if (n_entries == 2 || (n_entries < 0 && errno == 2)) {
        sprintf(response, "RLS NOK\n");

        if (verbose)
            printf("list request; no auctions were placed\n\n");
    }

    else if (n_entries <= 0 && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n\n");
        exit(1);
    }

    else {
        sprintf(response, "RLS OK");
        append_auctions_list(response, filelist, n_entries);

        if (verbose)
            printf("list request; auctions listed\n\n");
    }

    send_udp_response(response, fd, addr);
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
            if (strlen(bid_value) > 6 || !is_numeric(bid_value))
                exit(1);

            sprintf(pathname, "ASDIR/AUCTIONS/%s/BIDS/%s", aid, bid_value);
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

void handle_show_record_request(char *aid, int fd, struct sockaddr_in addr, int verbose) {
    char response[SRC_BUFFER_SIZE], buffer[76];

    if (strlen(aid) != 3 || !is_numeric(aid)) {
        send_udp_response_ERR("RRC", fd, addr, verbose);
        return;
    }

    char path[33];
    sprintf(path, "ASDIR/AUCTIONS/%s/START_%s.txt", aid, aid);
    sem_wait(sem[atoi(aid)]);

    if (!exists_file(path)) {
        sprintf(response, "RRC NOK\n");

        if (verbose)
            printf("AID=%s: show_record request; auction does not exist, show_record failed\n\n", aid);
    }

    else {
        sprintf(response, "RRC OK ");

        if (verbose)
            printf("AID=%s: show_record request; record listed\n\n", aid);

        FILE *fp = fopen(path, "r");
        if (fp == NULL) {
            fprintf(stderr, "ERROR: unable to open start file.\n\n");
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
            || !is_auction_name(auction_name) || !is_filename(asset_fname)
            || strlen(start_value) > 6 || !is_numeric(start_value)
            || !is_date(start_date) || !is_time(start_time) || strlen(timeactive) > 5
            || !is_numeric(timeactive)) {
            fprintf(stderr, "ERROR: start file information in wrong format\n");
            sem_post_(sem[atoi(aid)]);
            return;
        }

        strcat(response, buffer);

        char bid_info[BID_INFO_SIZE] = "";
        if (get_bid_list(bid_info, aid))
            strcat(response, bid_info);

        char end_file_path[31];
        sprintf(end_file_path, "ASDIR/AUCTIONS/%s/END_%s.txt", aid, aid);
        if (!exists_file(end_file_path) && auction_duration_has_expired(aid, path))
            create_close(end_file_path, path);

        char closed_info[CLOSED_INFO_SIZE] = "";
        if (get_closed_info(closed_info, aid))
            strcat(response, closed_info);

        strcat(response, "\n");
    }

    sem_post(sem[atoi(aid)]);
    send_udp_response(response, fd, addr);
}

void handle_udp_request(int fd_udp, struct sockaddr_in addr_udp, int verbose) {
    char buffer[LIN_LOU_UNR_MESSAGE_SIZE] = "", message_type[MESSAGE_TYPE_SIZE] = "";

    socklen_t addrlen = sizeof(addr_udp);
    int n = recvfrom(fd_udp, buffer, LIN_LOU_UNR_MESSAGE_SIZE, 0, (struct sockaddr*) &addr_udp, &addrlen);
    if (n == -1) /*error*/ exit(1);

    if (verbose)
        printf("REQUEST BY: %s - PORT No: %d\n", inet_ntoa(addr_udp.sin_addr), ntohs(addr_udp.sin_port));

    sscanf(buffer, "%3s", message_type);

    if (!strcmp(message_type, "LIN")) {
        char uid[UID_SIZE], password[PASSWORD_SIZE];
        sscanf(&buffer[4], "%6s %s", uid, password);

        if (buffer[3] != ' ' || buffer[10] != ' ' || buffer[19] != '\n'
            || buffer[20] != '\0' || strlen(buffer) - 14 != 6)
            send_udp_ERR(fd_udp, addr_udp, verbose);

        else
            handle_login_request(uid, password, fd_udp, addr_udp, verbose);
    }

    else if (!strcmp(message_type, "LOU")) {
        char uid[UID_SIZE], password[PASSWORD_SIZE];
        sscanf(&buffer[4], "%6s %s", uid, password);

        if (buffer[3] != ' ' || buffer[10] != ' ' || buffer[19] != '\n'
            || buffer[20] != '\0' || strlen(buffer) - 14 != 6)
            send_udp_ERR(fd_udp, addr_udp, verbose);

        else
            handle_logout_request(uid, password, fd_udp, addr_udp, verbose);
    }

    else if (!strcmp(message_type, "UNR")) {
        char uid[UID_SIZE], password[PASSWORD_SIZE];
        sscanf(&buffer[4], "%6s %s", uid, password);

        if (buffer[3] != ' ' || buffer[10] != ' ' || buffer[19] != '\n'
            || buffer[20] != '\0' || strlen(buffer) - 14 != 6)
            send_udp_ERR(fd_udp, addr_udp, verbose);

        else
            handle_unregister_request(uid, password, fd_udp, addr_udp, verbose);
    }

    else if (!strcmp(message_type, "LMA")) {
        char uid[UID_SIZE];
        sscanf(&buffer[4], "%s", uid);

        if (buffer[3] != ' ' || buffer[10] != '\n' || buffer[11] != '\0'
            || strlen(buffer) - 6 != 5)
            send_udp_ERR(fd_udp, addr_udp, verbose);

        else
            handle_myauctions_request(uid, fd_udp, addr_udp, verbose);
    }

    else if (!strcmp(message_type, "LMB")) {
        char uid[UID_SIZE];
        sscanf(&buffer[4], "%s", uid);

        if (buffer[3] != ' ' || buffer[10] != '\n' || buffer[11] != '\0'
           || strlen(buffer) - 6 != 5)
            send_udp_ERR(fd_udp, addr_udp, verbose);

        else
            handle_mybids_request(uid, fd_udp, addr_udp, verbose);
    }

    else if (!strcmp(message_type, "LST")) {
        if (strcmp(buffer, "LST\n"))
            send_udp_ERR(fd_udp, addr_udp, verbose);

        else
            handle_list_request(fd_udp, addr_udp, verbose);
    }

    else if (!strcmp(message_type, "SRC")) {
        char aid[AID_SIZE];
        sscanf(&buffer[4], "%s", aid);

        if (buffer[3] != ' ' || buffer[7] != '\n' || buffer[8] != '\0'
            || strlen(buffer) - 3 != 5)
            send_udp_ERR(fd_udp, addr_udp, verbose);

        else
            handle_show_record_request(aid, fd_udp, addr_udp, verbose);
    }

    else
        send_udp_ERR(fd_udp, addr_udp, verbose);
}

void send_tcp_response(char *response, int fd) {
    int n, sum = 0;
    while (sum != strlen(response)) {
        n = write(fd, response, strlen(response));
        if (n == -1) exit(1);
        sum += n;
    }
}

void send_tcp_response_ERR(char *prefix, int fd, int verbose) {
    char response[9];
    sprintf(response, "%s ERR\n", prefix);

    int n, sum = 0;
    while (sum != strlen(response)) {
        n = write(fd, response, strlen(response));
        if (n == -1) exit(1);
        sum += n;
    }
}

void send_tcp_ERR(int fd, int verbose) {
    int n, sum = 0;
    while (sum != 4) {
        n = write(fd, "ERR\n", 4);
        if (n == -1) exit(1);
        sum += n;
    }

    if (verbose)
        printf("Unexpected protocol message. ERR sent to client\n\n");
}

void create_start(int aid, char *uid, char *name, char *asset_fname, char *start_value, char *timeactive) {
    char start_file_path[33];
    sprintf(start_file_path, "ASDIR/AUCTIONS/%03d/START_%03d.txt", aid, aid);

    FILE *fp = fopen(start_file_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: unable to create login file.\n");
        exit(1);
    }

    time_t fulltime;
    struct tm *current_time;
    char timestr[20];

    time(&fulltime);
    current_time = gmtime(&fulltime);
    sprintf(timestr, "%4d-%02d-%02d %02d:%02d:%02d",
        current_time->tm_year+1900, current_time->tm_mon + 1,
        current_time->tm_mday, current_time->tm_hour, current_time->tm_min,
        current_time->tm_sec
    );

    char buffer[96];
    sprintf(buffer, "%s %s %s %s %s %s\n%ld", uid, name, asset_fname, start_value, timestr, timeactive, fulltime);

    int size = strlen(buffer), n = fwrite(buffer, 1, size, fp);
    if (n < size) { /*error*/
        fprintf(stderr, "ERROR: copied data write to file failed\n");
        exit(1);
    }

    fclose(fp);
}

int store_asset(int fd, int aid, char *asset_fname, long f_size) {
    FILE *fp;

    char auction_dir[19];
    sprintf(auction_dir, "ASDIR/AUCTIONS/%03d", aid);
    // fprintf(stderr, "PID: %d;\taid: %d\n", getpid(), aid); // TODO

    if (!exists_dir(auction_dir))
        if (mkdir(auction_dir, 0700) == -1) {
            fprintf(stderr, "ERROR: unable to create auction directory.\n");
            fprintf(stderr, "ERRO1: %d\n", aid);
            exit(1);
        }

    char asset_dir[25];
    sprintf(asset_dir, "ASDIR/AUCTIONS/%03d/ASSET", aid);

    if (!exists_dir(asset_dir))
        if (mkdir(asset_dir, 0700) == -1) {
            fprintf(stderr, "ERROR: unable to create auction directory.\n");
            fprintf(stderr, "ERRO2: %d\n", aid);
            exit(1);
        }

    char asset_path[50];
    sprintf(asset_path, "ASDIR/AUCTIONS/%03d/ASSET/%s", aid, asset_fname);

    fp = fopen(asset_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: unable to create asset file.\n");
        exit(1);
    }

    int ret = copy_from_socket_to_file(f_size, fd, NULL, fp);
    fclose(fp);

    if (ret == 0 || ret == -1) {
        unlink(asset_path);
        rmdir(asset_dir);
        rmdir(auction_dir);
    }

    return ret;
}

void create_hosted(char *uid, int aid) {
    char hosted_auction_path[30];
    sprintf(hosted_auction_path, "ASDIR/USERS/%s/HOSTED/%03d.txt", uid, aid);

    FILE *fp = fopen(hosted_auction_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: unable to create hosted file.\n");
        exit(1);
    }
    fclose(fp);
}

void handle_open_auction_request(int newfd, char *uid, char *user_password, char *name,
                                 char *start_value, char *timeactive,
                                 char *asset_fname, long f_size, int verbose) {

    if (strlen(uid) != 6 || !is_numeric(uid) || strlen(user_password) != 8
        || !is_alphanumeric(user_password) || strlen(name) > 10
        || !is_auction_name(name) || !is_filename(asset_fname)
        || strlen(start_value) > 6 || !is_numeric(start_value)
        || strlen(timeactive) > 5 || !is_numeric(timeactive)) {
        send_tcp_response_ERR("ROA", newfd, verbose);
        return;
    }

    char path[15] = "ASDIR/AUCTIONS", response[12] = "";
    struct dirent **filelist;

    char login_file_path[36];
    sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

    if (!exists_file(login_file_path)) {
        sprintf(response, "ROA NLG\n");

        if (verbose)
            printf("UID=%s: open_auction request; user not logged in, open failed\n\n", uid);

        send_tcp_response(response, newfd);
        return;
    }

    char pass_file_path[35], file_password[9];
    sprintf(pass_file_path, "ASDIR/USERS/%s/%s_pass.txt", uid, uid);

    if (exists_file(pass_file_path) == 1) {
        FILE *fp = fopen(pass_file_path, "r");
        if (fp == NULL) {
            fprintf(stderr, "ERROR: %d unable to open pass file.\n", errno);
            exit(1);
        }

        int ret = fread(file_password, 1, 8, fp);
        if (ret < 8) {
            fprintf(stderr, "ERROR: pass file read failed\n");
            return;
        }

        file_password[8] = '\0';
        fclose(fp);

        if (strcmp(file_password, user_password)) {
            sprintf(response, "ROA NOK\n");

            if (verbose)
                printf("UID=%s: open_auction request; incorrect password match, open failed\n\n", uid);

            send_tcp_response(response, newfd);
            return;
        }
    }

    sem_wait_(sem[0]);

    int n_entries = scandir(path, &filelist, 0, alphasort);

    if (n_entries == 2 || (n_entries < 0 && errno == 2)) {
        sem_wait_(sem[1]);

        int ret = store_asset(newfd, 1, asset_fname, f_size);

        if (ret == -1) {
            send_tcp_ERR(newfd, verbose);
            return;
        }

        else if (ret == 0) {
            send_tcp_response_ERR("ROA", newfd, verbose);
            return;
        }

        else {
            sprintf(response, "ROA OK 001\n");
            create_start(1, uid, name, asset_fname, start_value, timeactive);

            create_hosted(uid, 1);

            if (verbose)
                printf("UID=%s: open_auction request; auction 001 created\n\n", uid);
        }

        sem_post_(sem[1]);
    }

    else if (n_entries <= 0 && errno != 2) {
        fprintf(stderr, "ERROR: unable to open directory.\n");
        exit(1);
    }

    else {
        int aid;
        sscanf(filelist[n_entries - 1]->d_name, "%d", &aid);

        if (aid < 1 || aid > 999)
            exit(1);

        if (aid == 999) {
            sprintf(response, "ROA NOK\n");

            if (verbose)
                printf("UID=%s: open_auction request; auction creation failed\n\n", uid);
        }

        else {
            aid++;
            sem_wait_(sem[aid]);
            int ret = store_asset(newfd, aid, asset_fname, f_size);

            if (ret == -1) {
                send_tcp_ERR(newfd, verbose);
                return;
            }

            else if (ret == 0) {
                send_tcp_response_ERR("ROA", newfd, verbose);
                return;
            }

            else {
                sprintf(response, "ROA OK %03d\n", aid);
                create_start(aid, uid, name, asset_fname, start_value, timeactive);
                create_hosted(uid, aid);

                if (verbose)
                    printf("UID=%s: open_auction request; auction %03d created\n\n", uid, aid);
            }

            sem_post_(sem[aid]);
        }
    }

    sem_post_(sem[0]);
    send_tcp_response(response, newfd);
}

int create_close(char *end_file_path, char *start_file_path) {
    FILE *fp_start = fopen(start_file_path, "r");
    if (fp_start == NULL) {
        fprintf(stderr, "ERROR: unable to open start file.\n");
        return 0;
    }

    char buffer[96];
    fgets(buffer, 96, fp_start);  // read until \n

    int timeactive;
    sscanf(buffer, "%*s %*s %*s %*d %*s %*s %d", &timeactive);

    if (timeactive < 0 || timeactive > 99999)   
        exit(1);

    fgets(buffer, 20, fp_start);  // read start_fulltime (int max 19 digits)
    buffer[strlen(buffer)] = '\0';
    fclose(fp_start);

    FILE *fp = fopen(end_file_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: unable to create end file.\n");
        return 0;
    }

    time_t fulltime, fulltime_start = atol(buffer);
    time(&fulltime);

    struct tm *current_time;
    char timestr[20];
    current_time = gmtime(&fulltime);
    sprintf(timestr, "%4d-%02d-%02d %02d:%02d:%02d",
        current_time->tm_year+1900, current_time->tm_mon + 1,
        current_time->tm_mday, current_time->tm_hour, current_time->tm_min,
        current_time->tm_sec
    );

    fulltime -= fulltime_start;

    if (fulltime > timeactive)
        fulltime = timeactive;

    fprintf(fp, "%s %ld", timestr, fulltime);
    fclose(fp);

    return 1;
}

void handle_close_auction_request(int newfd, char *uid, char *user_password, char *aid, int verbose) {
    if (strlen(uid) != 6 || !is_numeric(uid) || strlen(user_password) != 8
        || !is_alphanumeric(user_password) || strlen(aid) != 3 || !is_numeric(aid)) {
        send_tcp_response_ERR("RCL", newfd, verbose);
        return;
    }

    char response[9], pass_file_path[35], file_password[9];
    sprintf(pass_file_path, "ASDIR/USERS/%s/%s_pass.txt", uid, uid);
    sem_wait_(sem[atoi(aid)]);

    if (exists_file(pass_file_path) == 1) {
        FILE *fp = fopen(pass_file_path, "r");
        if (fp == NULL) {
            fprintf(stderr, "ERROR: %d unable to open pass file.\n", errno);
            exit(1);
        }

        int ret = fread(file_password, 1, 8, fp);
        if (ret < 8) {
            fprintf(stderr, "ERROR: pass file read failed\n");
            return;
        }

        file_password[8] = '\0';
        fclose(fp);

        if (!strcmp(file_password, user_password)) {
            char login_file_path[36];
            sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

            if (!exists_file(login_file_path)) {
                sprintf(response, "RCL NLG\n");

                if (verbose)
                    printf("UID=%s: closed_auction request; user not logged in, close failed\n\n", uid);
            }

            else {
                char start_file_path[33];
                sprintf(start_file_path, "ASDIR/AUCTIONS/%s/START_%s.txt", aid, aid);

                if (!exists_file(start_file_path)) {
                    sprintf(response, "RCL EAU\n");

                    if (verbose)
                        printf("UID=%s: closed_auction request; auction %s does not exist, close failed\n\n", uid, aid);
                }

                else {
                    char hosted_auction_path[30];
                    sprintf(hosted_auction_path, "ASDIR/USERS/%s/HOSTED/%s.txt", uid, aid);

                    if (!exists_file(hosted_auction_path)) {
                        sprintf(response, "RCL EOW\n");

                        if (verbose)
                            printf("UID=%s: closed_auction request; auction %s is not owned by %s, close failed\n\n", uid, aid, uid);
                    }

                    else {
                        char end_file_path[31];
                        sprintf(end_file_path, "ASDIR/AUCTIONS/%s/END_%s.txt", aid, aid);

                        if (exists_file(end_file_path)) {
                            sprintf(response, "RCL END\n");

                            if (verbose)
                                printf("UID=%s: closed_auction request; auction %s has ended, close failed\n\n", uid, aid);
                        }

                        else {
                            if (create_close(end_file_path, start_file_path)) {
                                sprintf(response, "RCL OK\n");

                                if (verbose)
                                    printf("UID=%s: closed_auction request; auction %s closed\n\n", uid, aid);
                            }
                        }
                    }
                }
            }
        }

        else {
            sprintf(response, "RCL NOK\n");

            if (verbose)
                printf("UID=%s: closed_auction request; user does not exist or password is incorrect, closed failed\n\n", uid);
        }
    }

    else {
        sprintf(response, "RCL NOK\n");

        if (verbose)
            printf("UID=%s: closed_auction request; user does not exist or password is incorrect, closed failed\n\n", uid);
    }

    sem_post_(sem[atoi(aid)]);
    send_tcp_response(response, newfd);
}

long asset_fsize(char *fname) {
    struct stat filestat;
    long retstat;
    retstat = stat(fname, &filestat);

    if (retstat == -1 || filestat.st_size == 0)
        return 0;
    return filestat.st_size;
}

void handle_show_asset_request(int newfd, char *aid, int verbose) {
    char response[RSA_PREFIX_SIZE];

    if (strlen(aid) != 3 || !is_numeric(aid)) {
        send_tcp_response_ERR("RSA", newfd, verbose);
        return;
    }

    char start_file_path[33], end_file_path[31];;
    sprintf(start_file_path, "ASDIR/AUCTIONS/%s/START_%s.txt", aid, aid);
    sprintf(end_file_path, "ASDIR/AUCTIONS/%s/END_%s.txt", aid, aid);

    sem_wait_(sem[atoi(aid)]);

    if (!exists_file(end_file_path) && auction_duration_has_expired(aid, start_file_path))
        create_close(end_file_path, start_file_path);

    if (!exists_file(start_file_path)) {
        sprintf(response, "RSA NOK\n");

        if (verbose)
            printf("AID=%s: show_asset request; no file to be sent, show_asset failed\n\n", aid);
    }

    else {
        char asset_fname[FILENAME_SIZE];

        FILE *fp = fopen(start_file_path, "r");
        if (fp == NULL) {
            fprintf(stderr, "ERROR: %d unable to open start file.\n", errno);
            exit(1);
        }
        char buffer[96];
        fgets(buffer, 96, fp);
        fclose(fp);

        sscanf(buffer, "%*s %*s %s", asset_fname);

        if (!is_filename(asset_fname))
            exit(1);

        char asset_path[50];
        sprintf(asset_path, "ASDIR/AUCTIONS/%s/ASSET/%s", aid, asset_fname);

        if (!exists_file(asset_path)) {
            sprintf(response, "RSA NOK\n");

            if (verbose)
                printf("AID=%s: show_asset request; no file to be sent or some other problem occured, show_asset failed\n\n", aid);
        }

        else {
            long f_size = asset_fsize(asset_path);

            sprintf(response, "RSA OK %s %ld ", asset_fname, f_size);
            send_tcp_response(response, newfd);

            FILE *fp = fopen(asset_path, "r");
            if (fp == NULL) {
                fprintf(stderr, "ERROR: %d unable to open asset file.\n", errno);
                exit(1);
            }
            send_asset(fp, newfd);
            fclose(fp);

            if (verbose)
                printf("AID=%s: show_asset request; asset %s sent\n\n", aid, asset_fname);

            sem_post_(sem[atoi(aid)]);
            return;
        }
    }

    sem_post_(sem[atoi(aid)]);
    send_tcp_response(response, newfd);
}

void create_bid(int highest_bid, char *aid, char *uid) {
    char bid_file_path[35], start_file_path[33];

    sprintf(bid_file_path, "ASDIR/AUCTIONS/%s/BIDS/%06d.txt", aid, highest_bid);

    FILE *fp = fopen(bid_file_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: unable to create login file.\n");
        exit(1);
    }

    sprintf(start_file_path, "ASDIR/AUCTIONS/%s/START_%s.txt", aid, aid);
    FILE *fp_start = fopen(start_file_path, "r");
    if (fp_start == NULL) {
        fprintf(stderr, "ERROR: unable to open start file.\n");
        return ;
    }

    char buffer[96];
    fgets(buffer, 96, fp_start);  // read until \n
    fgets(buffer, 20, fp_start);  // read start_fulltime (int max 19 digits)
    buffer[strlen(buffer)] = '\0';
    fclose(fp_start);

    time_t fulltime, fulltime_start = atol(buffer);
    time(&fulltime);

    struct tm *current_time;
    char timestr[20];
    current_time = gmtime(&fulltime);
    sprintf(timestr, "%4d-%02d-%02d %02d:%02d:%02d",
        current_time->tm_year+1900, current_time->tm_mon + 1,
        current_time->tm_mday, current_time->tm_hour, current_time->tm_min,
        current_time->tm_sec
    );

    fulltime -= fulltime_start;

    sprintf(buffer, "%s %d %s %ld", uid, highest_bid, timestr, fulltime);

    int size = strlen(buffer), n = fwrite(buffer, 1, size, fp);
    if (n < size) { /*error*/
        fprintf(stderr, "ERROR: copied data write to file failed\n");
        exit(1);
    }

    fclose(fp);
}

void create_bidded(char *uid, char *aid) {
    char bidded_auction_path[34];
    sprintf(bidded_auction_path, "ASDIR/USERS/%s/BIDDED/%s.txt", uid, aid);

    FILE *fp = fopen(bidded_auction_path, "w");
    if (fp == NULL) {
        fprintf(stderr, "ERROR: unable to create bidded file.\n");
        exit(1);
    }
    fclose(fp);
}

void attempt_bid(char *aid, char *uid, char *value, char *response, int verbose) {
    char dirname[25];
    sprintf(dirname, "ASDIR/AUCTIONS/%s/BIDS/", aid);

    char start_file_path[33];
    sprintf(start_file_path, "ASDIR/AUCTIONS/%s/START_%s.txt", aid, aid);

    if (!exists_dir(dirname)) {
        if (mkdir(dirname, 0700) == -1) {
            fprintf(stderr, "ERROR: unable to create ASDIR.\n");
            exit(1);
        }

        if (!exists_file(start_file_path)) {
            fprintf(stderr, "ERROR: unable to open start file.\n");
            exit(1);
        }

        else {
            FILE *fp_start = fopen(start_file_path, "r");
            if (fp_start == NULL) {
                fprintf(stderr, "ERROR: unable to open start file.\n");
                return ;
            }

            char buffer[96];
            fgets(buffer, 96, fp_start);  // read until \n

            int attemped_bid = atoi(value);
            int min_bid;
            sscanf(buffer, "%*s %*s %*s %d", &min_bid);
            fclose(fp_start);

            if (min_bid < 0 || min_bid > 999999)
                exit(1);

            if (attemped_bid > min_bid) {
                create_bid(attemped_bid, aid, uid);
                create_bidded(uid, aid);
                sprintf(response, "RBD ACC\n");

                if (verbose)
                    printf("UID=%s: bid request; bid for auction %s accepted\n\n", uid, aid);
            }

            else {
                sprintf(response, "RBD REF\n");

                if (verbose)
                    printf("UID=%s: bid request; bid for auction %s refused\n\n", uid, aid);
            }
        }
    }

    else {
        struct dirent **filelist;

        int n_entries = scandir(dirname, &filelist, 0, alphasort);
        if (n_entries <= 0 && errno != 2) {
            fprintf(stderr, "ERROR: unable to open directory.\n");
            exit(1);
        }

        else if (n_entries == 2) {
            FILE *fp_start = fopen(start_file_path, "r");
            if (fp_start == NULL) {
                fprintf(stderr, "ERROR: unable to open start file.\n");
                return ;
            }

            char buffer[96];
            fgets(buffer, 96, fp_start);  // read until \n

            int attemped_bid = atoi(value);
            int min_bid;
            sscanf(buffer, "%*s %*s %*s %d", &min_bid);
            fclose(fp_start);

            if (min_bid < 0 || min_bid > 999999)
                exit(1);

            if (attemped_bid > min_bid) {
                create_bid(attemped_bid, aid, uid);
                create_bidded(uid, aid);
                sprintf(response, "RBD ACC\n");

                if (verbose)
                    printf("UID=%s: bid request; bid for auction %s accepted\n\n", uid, aid);
            }

            else {
                sprintf(response, "RBD REF\n");

                if (verbose)
                    printf("UID=%s: bid request; bid for auction %s refused\n\n", uid, aid);
            }
        }

        else {
            int highest_bid, attemped_bid = atoi(value);
            sscanf(filelist[n_entries - 1]->d_name, "%d.txt", &highest_bid);

            if (highest_bid < 0 || highest_bid > 999999)
                exit(1);

            if (attemped_bid > highest_bid) {
                create_bid(attemped_bid, aid, uid);
                create_bidded(uid, aid);
                sprintf(response, "RBD ACC\n");

                if (verbose)
                    printf("UID=%s: bid request; bid for auction %s accepted\n\n", uid, aid);
            }

            else {
                sprintf(response, "RBD REF\n");

                if (verbose)
                    printf("UID=%s: bid request; bid for auction %s refused\n\n", uid, aid);
            }
        }
    }
}

void handle_bid_request(int newfd, char *uid, char *user_password, char *aid, char *value, int verbose) {
    if (strlen(uid) != 6 || !is_numeric(uid) || strlen(user_password) != 8
        || !is_alphanumeric(user_password) || strlen(aid) != 3 || !is_numeric(aid)
        || strlen(value) > 6 || !is_numeric(value)) {
        send_tcp_response_ERR("RBD", newfd, verbose);
        return;
    }

    char response[9], start_file_path[33], end_file_path[31];

    sprintf(start_file_path, "ASDIR/AUCTIONS/%s/START_%s.txt", aid, aid);
    sprintf(end_file_path, "ASDIR/AUCTIONS/%s/END_%s.txt", aid, aid);
    sem_wait_(sem[atoi(aid)]);

    if (!exists_file(end_file_path) && auction_duration_has_expired(aid, start_file_path))
        create_close(end_file_path, start_file_path);

    if (!exists_file(start_file_path) || exists_file(end_file_path)) {
        sprintf(response, "RBD NOK\n");

        if (verbose)
            printf("UID=%s: bid request; auction %s is not active, bid failed\n\n", uid, aid);
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

            int ret = fread(file_password, 1, 8, fp);
            if (ret < 8) {
                fprintf(stderr, "ERROR: pass file read failed\n");
                sem_post_(sem[atoi(aid)]);
                return; // TODO
            }

            file_password[8] = '\0';
            fclose(fp);

            if (!strcmp(file_password, user_password)) {
                char login_file_path[36];
                sprintf(login_file_path, "ASDIR/USERS/%s/%s_login.txt", uid, uid);

                if (!exists_file(login_file_path)) {
                    sprintf(response, "RBD NLG\n");

                    if (verbose)
                        printf("UID=%s: bid request; user not logged in, bid failed\n\n", uid);
                }

                else {
                    char hosted_auction_path[30];
                    sprintf(hosted_auction_path, "ASDIR/USERS/%s/HOSTED/%s.txt", uid, aid);

                    if (exists_file(hosted_auction_path)) {
                        sprintf(response, "RBD ILG\n");

                        if (verbose)
                            printf("UID=%s: bid request; auction %s is hosted by %s, bid failed\n\n", uid, aid, uid);
                    }

                    else
                        attempt_bid(aid, uid, value, response, verbose);
                }
            }
            
            else {
                sprintf(response, "RBD NOK\n");

                if (verbose)
                    printf("UID=%s: bid request; incorrect password match, bid failed\n\n", uid);
            }
        }

        else {
            sprintf(response, "RBD NLG\n");

            if (verbose)
                printf("UID=%s: bid request; user not logged in, bid failed\n\n", uid);
        }
    }

    sem_post_(sem[atoi(aid)]);
    send_tcp_response(response, newfd);
}

void handle_tcp_request(int newfd, struct sockaddr_in addr_tcp, int verbose) {
    char buffer[OPA_MESSAGE_SIZE] = "", message_type[MESSAGE_TYPE_SIZE] = "";

    if (verbose)
        printf("REQUEST BY: %s - PORT No: %d\n", inet_ntoa(addr_tcp.sin_addr), ntohs(addr_tcp.sin_port));

    int n = read(newfd, buffer, MESSAGE_TYPE_SIZE);
    if (n == -1) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            if (verbose)
                printf("Peer took too long to respond. Waiting for new tcp request\n\n");
            return;
        }

        close(newfd);
        exit(1);
    }
    sscanf(buffer, "%3s", message_type);

    if (!strcmp(message_type, "OPA")) {
        buffer[3] = ' ';
        int spaces = 0;

        for (int i = 4; i < OPA_MESSAGE_SIZE; i++) {
            n = read(newfd, &buffer[i], 1);
            if (n == -1) {
                fprintf(stderr, "ERROR: open message read failed\n");
                return;
            }

            if (buffer[i] == ' ')
                spaces++;

            if (spaces == 7)
                break;
        }

        char uid[UID_SIZE] = "", password[PASSWORD_SIZE] = "",
        name[NAME_SIZE] = "", asset_fname[FILENAME_SIZE] = "",
        start_value[VALUE_SIZE] = "", timeactive[SEC_SIZE] = "";
        long f_size;

        sscanf(&buffer[4], "%6s %8s %10s %6s %5s %24s %ld ", uid, password, name, start_value, timeactive, asset_fname, &f_size);

        int name_size = strlen(name), start_value_size = strlen(start_value),
            timeactive_size = strlen(timeactive), asset_fname_size = strlen(asset_fname);

        if (buffer[3] != ' ' || buffer[10] != ' ' || buffer[19] != ' '
            || buffer[20 + name_size] != ' '
            || buffer[21 + name_size + start_value_size] != ' '
            || buffer[22 + name_size + start_value_size + timeactive_size] != ' '
            || buffer[23 + name_size + start_value_size + timeactive_size + asset_fname_size] != ' '
            || buffer[24 + name_size + start_value_size + timeactive_size + asset_fname_size + OoM(f_size)] != ' '
            || strlen(buffer) - (14 + name_size + start_value_size + timeactive_size + asset_fname_size + OoM(f_size)) != 11
        )
            send_tcp_ERR(newfd, verbose);

        else
            handle_open_auction_request(newfd, uid, password, name, start_value, timeactive, asset_fname, f_size, verbose);
    }

    else if (!strcmp(message_type, "CLS")) {
        char uid[UID_SIZE], password[PASSWORD_SIZE], aid[AID_SIZE];

        read_tcp_socket(newfd, NULL, &buffer[4], 21);
        sscanf(&buffer[4], "%6s %8s %s", uid, password, aid);

        if (buffer[3] != ' ' || buffer[10] != ' ' || buffer[19] != ' '
            || buffer[23] != '\n' || strlen(buffer) - 17 != 7)
            send_tcp_ERR(newfd, verbose);

        else
            handle_close_auction_request(newfd, uid, password, aid , verbose);
    }

    else if (!strcmp(message_type, "SAS")) {
        char aid[AID_SIZE];

        read_tcp_socket(newfd, NULL, &buffer[4], 5);
        sscanf(&buffer[4], "%s", aid);

        if (buffer[3] != ' ' || buffer[7] != '\n' || strlen(buffer) - 3 != 5)
            send_tcp_ERR(newfd, verbose);

        else
            handle_show_asset_request(newfd, aid, verbose);
    }

    else if (!strcmp(message_type, "BID")) {
        char uid[UID_SIZE], password[PASSWORD_SIZE], aid[AID_SIZE], value[VALUE_SIZE];

        read_tcp_socket(newfd, NULL, &buffer[4], 28);
        sscanf(&buffer[4], "%8s %6s %3s %s", uid, password, aid, value);

        int value_size = strlen(value);

        if (buffer[3] != ' ' || buffer[10] != ' ' || buffer[19] != ' '
            || buffer[23] != ' ' || buffer[24 + value_size] != '\n'
            || strlen(buffer) - (17 + value_size) != 8)
            send_tcp_ERR(newfd, verbose);

        else
            handle_bid_request(newfd, uid, password, aid, value, verbose);
    }

    else
        send_tcp_ERR(newfd, verbose);
}

int main(int argc, char **argv) {
    char ASport[ASPORT_SIZE] = "";
    int verbose = 0;
    main_pid = getpid();

    handle_main_arguments(argc, argv, ASport, &verbose);
    setup_environment();

    int errcode;
    ssize_t n;
    struct addrinfo hints_udp, hints_tcp, *res_udp, *res_tcp;
    struct sockaddr_in addr_udp, addr_tcp;

    // UDP socket
    fd_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_udp == -1) /*error*/ exit(1);

    memset(&hints_udp, 0, sizeof hints_udp);
    hints_udp.ai_family = AF_INET;
    hints_udp.ai_socktype = SOCK_DGRAM;
    hints_udp.ai_flags = AI_PASSIVE;

    errcode = getaddrinfo(NULL, ASport, &hints_udp, &res_udp);
    if (errcode != 0) {/*error*/ 
        close(fd_udp);
        exit(1);
    }

    n = bind(fd_udp, res_udp->ai_addr, res_udp->ai_addrlen);
    if (n == -1) {/*error*/ 
        close(fd_udp);
        freeaddrinfo(res_udp);
        exit(1);
    }

    // TCP socket
    fd_tcp = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_tcp == -1) {
        close(fd_udp);
        freeaddrinfo(res_udp);
        exit(1);
    }

    memset(&hints_tcp, 0, sizeof hints_tcp);
    hints_tcp.ai_family = AF_INET;
    hints_tcp.ai_socktype = SOCK_STREAM;
    hints_tcp.ai_flags = AI_PASSIVE;

    errcode = getaddrinfo(NULL, ASport, &hints_tcp, &res_tcp);
    if (errcode != 0) {
        close(fd_tcp);
        close(fd_udp);
        freeaddrinfo(res_udp);
        exit(1);
    }

    n = bind(fd_tcp, res_tcp->ai_addr, res_tcp->ai_addrlen);
    if (n == -1) {
        close(fd_tcp);
        close(fd_udp);
        freeaddrinfo(res_tcp);
        freeaddrinfo(res_udp);
        exit(1);
    }

    for (int i = 0; i < 1000; i++) {
        char semName[13];
        sprintf(semName, "semaphore%03d", i);
        if ((sem[i] = sem_open(semName, O_CREAT, 0600, 1)) == SEM_FAILED) {
            fprintf(stderr, "ERROR: sem_open failed\n");
            close(fd_tcp);
            close(fd_udp);
            freeaddrinfo(res_tcp);
            freeaddrinfo(res_udp);
            for (int j = 0; j < i; j++) {
                char semName[13];
                sprintf(semName, "semaphore%03d", j);
                sem_close(sem[j]);
                sem_unlink(semName);
            }
            exit(1);
        }
    }

    char semName[15] = "semaphore_user";
    if ((sem_user = sem_open(semName, O_CREAT, 0600, 1)) == SEM_FAILED) {
        fprintf(stderr, "ERROR: sem_open failed\n");
        close(fd_tcp);
        close(fd_udp);
        freeaddrinfo(res_tcp);
        freeaddrinfo(res_udp);
        for (int i = 0; i < 1000; i++) {
            char semName[13];
            sprintf(semName, "semaphore%03d", i);
            sem_close(sem[i]);
            sem_unlink(semName);
        }
        exit(1);
    }

    pid_t p;
    p = fork();

    if (p < 0) {
        perror("fork fail");
        exit_server(1);
    }

    else if (p == 0) {
        freeaddrinfo(res_tcp);
        close(fd_tcp);

        while (1)
            handle_udp_request(fd_udp, addr_udp, verbose);
    }

    else {  // p == child_pid
        freeaddrinfo(res_udp);
        close(fd_udp);

        signal(SIGINT, sigint_detected);

        if (listen(fd_tcp, 5) == -1) /*error*/ exit_server(1);

        while (1) {
            socklen_t addrlen = sizeof(addr_tcp);
            int newfd;

            if ((newfd = accept(fd_tcp, (struct sockaddr *) &addr_tcp, &addrlen)) == -1)
                exit_server(1);

            struct timeval timeout;
            timeout.tv_sec = 5;  // 5 seconds timeout
            timeout.tv_usec = 0;

            if (setsockopt(newfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
                fprintf(stderr, "ERROR: socket timeout creation was not sucessful\n");
                close(newfd);
                exit_server(1);
            }

            pid_t p;
            p = fork();

            if (p < 0) {
                perror("fork fail");
                exit_server(1);
            }

            else if (p == 0) {
                handle_tcp_request(newfd, addr_tcp, verbose);
                close(newfd);
            }
        }
    }

    return 0;
}