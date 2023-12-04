#include "common.h"

int is_port_no(char* ASport) {
    return 0 < atoi(ASport) && atoi(ASport) <= 99999;
}

int main() {
    return 0;
}