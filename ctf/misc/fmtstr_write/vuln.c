// ASLR is enabled

// File was compiled using
// gcc-11 -w -z execstack -o vuln ./vuln.c
// vuln-test is the same binary as vuln but just without setuid, you can use it to test your exploit
// PLEASE DO NOT RECOMPILE THE CODE IN THIS VM

// Secret in root directory

#include <stdio.h>

void setup(){
    setvbuf(stdout, NULL, _IONBF, 0);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
}

int login() {
    char username[32];
    char password[32];
    char name[32];
    printf("name: ");
    read(0, name, 32);
    printf("username: ");   
    read(0, username, 32);
    printf("password: ");
    read(0, password, 32);
    if (strcmp(username, "admin") == 0 && strcmp(password, "password123") == 0) {
        printf("Welcome %s\n", name);
        return 1;
    } else {
        printf("Wrong password\n");
        return 0;
    }
}

void note() {
    char *note = (char *)malloc(100);
    char category[240];
    printf("Enter note category: ");
    fgets(category, sizeof(category), stdin);
    printf(category);
    printf("Enter your note: ");
    fgets(note, 100, stdin);
    printf("%s", note);
}

int main() {
    setup();
    if (login()) {
        note();
    }
    return 0;
}
