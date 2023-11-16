#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>

#define PORT "58046"

int main() {
    char command[100];

    while (1) {
        printf("Input your command:\n");
        scanf("%s", command);

        if (!strcmp(command, "login"))
            login();

        else if (!strcmp(command, "logout"))
            logout();

        else if (!strcmp(command, "unregister"))
            unregister();

        else if (!strcmp(command,  "open"))
            open_auction();

        else if (!strcmp(command, "close"))
            close_auction();

        else if (!strcmp(command, "myauctions") || !strcmp(command, "ma"))
            myauctions();

        else if (!strcmp(command, "mybids") || !strcmp(command, "mb"))
            mybids();

        else if (!strcmp(command, "list") || !strcmp(command, "l"))
            list();

        else if (!strcmp(command, "show_asset") || !strcmp(command, "sa"))
            show_asset();

        else if (!strcmp(command, "bid") || !strcmp(command, "b"))
            bid();

        else if (!strcmp(command,  "show_record") || !strcmp(command,  "sr"))
            show_record();

        else if (!strcmp(command,  "exit"))
            exit_user();

        else 
            printf("Command not found. Please try again\n");

        printf("%s", command);
    }
    
    return 0;
}