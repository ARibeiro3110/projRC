#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

#define PORT "58046"

int fd, newfd, errcode; // newfd é fd da nova ligação (existem 2 sockets em TCP)
ssize_t n;
socklen_t addrlen;
struct addrinfo hints, *res;
struct sockaddr_in addr;
char buffer[128];

int main() {
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        exit(1);
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    errcode = getaddrinfo(NULL, PORT, &hints, &res);
    if ((errcode) != 0) {
        exit(1);
    }

    n = bind(fd, res->ai_addr, res->ai_addrlen);
    if (n == -1) {
        exit(1);
    }

    /* Prepara para receber até 5 conexões na socket fd.
    Recusa outras conexões enquanto estiverem 5 conexões pendentes. */
    if (listen(fd, 5) == -1) {
        exit(1);
    }

    /* Loop para processar uma socket de cada vez */
    while (1) {
        addrlen = sizeof(addr);
        /* Aceita uma nova conexão e cria uma nova socket para a mesma.
        Quando a conexão é aceite, é automaticamente criada uma nova socket
        para ela, guardada no `newfd`.
        Do lado do cliente, esta conexão é feita através da função `connect()`. */
        if ((newfd = accept(fd, (struct sockaddr *)&addr, &addrlen)) == -1) {
            exit(1);
        }

        /* Já conectado, o cliente então escreve algo para a sua socket.
        Esses dados são lidos para o buffer. */
        n = read(newfd, buffer, 128);
        if (n == -1) {
            exit(1);
        }

        /* Faz `echo` da mensagem recebida para o STDOUT do servidor */
        write(1, "received: ", 10);
        write(1, buffer, n);

        read(0, buffer, 128);

        n = write(newfd, buffer, strlen(buffer) * sizeof(char));
        if (n == -1) {
            exit(1);
        }

        /* Fecha a socket atualmente estabelecida */
        close(newfd);
    }

    freeaddrinfo(res);
    close(fd);
}