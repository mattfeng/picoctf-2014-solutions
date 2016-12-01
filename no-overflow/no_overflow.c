#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define BUFSIZE 256

void greet(int length){
    char buf[BUFSIZE];
    puts("What is your name?");
    read(0, buf, length);
    printf("Hello, %s\n!", buf);
}

// A size_t value is always positive even if you pass a negative value
// to malloc. The negative value is converted to an unsigned value
// of type size_t which leads to a huge positive value.

// NX disabled
// stack: 0xffffd5c0

void be_nice_to_people(){
    gid_t gid = getegid();
    setresgid(gid, gid, gid);
}

int main(int argc, char **argv){
    int length;
    be_nice_to_people();

    puts("How long is your name?");
    scanf("%d", &length);

    if(length < BUFSIZE) //don't allow buffer overflow
        greet(length);
    else
        puts("Length was too long!");
}
