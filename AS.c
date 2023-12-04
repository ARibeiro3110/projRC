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

int main(int argc, char **argv) {
    char ASport[ASPORT_SIZE] = "";
    int verbose = 0;

    handle_main_arguments(argc, argv, ASport, &verbose);

    printf("ASport: %s Verbose: %d\n", ASport, verbose);

    return 0;
}