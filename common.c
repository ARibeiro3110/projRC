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
#include <ctype.h>
#include <math.h>

#include "common.h"

void exit_error(int fd, struct addrinfo *res) {
    freeaddrinfo(res);
    close(fd); 
    exit(1);
}

int is_port_no(char* ASport) {
    return 0 < atoi(ASport) && atoi(ASport) <= 99999;
}

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
        if (!isalnum(word[i]))
            return 0;
    return 1;
}

int is_auction_name(char *word) {
    int l = strlen(word);
    for (int i = 0; i < l; i++)
        if (word[i] != '-' && word[i] != '_' && !isalnum(word[i]))
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
        
        if (i > l - 4 && !('a' <= word[i] <= 'z' || '0' <= word[i] <= '9'))
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

int copy_from_socket_to_file(int size, int fd, struct addrinfo *res, FILE *fp) {
    int written = 0, bytes_read = 0, n;
    char data[BUFFER_DEFAULT] = "";
    memset(data, 0, 128);

    while (written < size) {
        bytes_read = read(fd, data, 128);
        if (bytes_read == -1) { /*error*/ 
            fprintf(stderr, "ERROR: data read from socket failed\n");
            exit_error(fd, res);
        }

        if (bytes_read == size + 1 && data[bytes_read - 1] == '\n')
            // doesn't write the \n char
            bytes_read--;

        n = fwrite(data, 1, bytes_read, fp);
        if (n == -1) { /*error*/ 
            fprintf(stderr, "ERROR: copied data write to file failed\n");
            exit_error(fd, res);
        }
        written += n;
        memset(data, 0, 128);
    }

    return written;
}

void send_asset(FILE *file_fd, int fd) {
    char buffer[BUFFER_DEFAULT];

    // write the rest of the message (data from the file)
    int bytes_read = 0, n;
    while ((bytes_read = fread(buffer, 1, 128, file_fd)) != 0) {
        buffer[bytes_read] = '\0';
        n = write(fd, buffer, bytes_read);
        if (n == -1) { /*error*/ 
            fprintf(stderr, "ERROR: data write to socket failed\n");
            exit(1);
        }
    }

    // write terminator (\n)
    n = write(fd, "\n", 1);
    if (n == -1) { /*error*/ 
        fprintf(stderr, "ERROR: terminator write failed\n");
        exit(1);
    }
}

int OoM(long number) {
    int count = 0;

    while(number != 0) {  
       number = number / 10;  
       count++;  
    }  

    return count;
}