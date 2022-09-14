#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <unistd.h>

int main() {

    char name [52];
    int loopCount = 4;

    printf("Hello! I'm so excited to meet you! What's your name?\n");

    gets(name);

    for (int i = 0; i < loopCount; i++) {
        printf("Hello %s!! Hope you're having a fantastic day!\n", name);
        if (i == 5) {
            char *flag = malloc(0x100);
            int fd = open("flag", 0);
            read(fd, flag, 0x100);
            printf("I've never been so excited to meet someone before! Here, take this flag, you deserve it :)\n%s\n", flag);
            close(fd);
        }
    }

    return 0;
}