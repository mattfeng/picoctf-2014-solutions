#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// eip: TTTT
// input: AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTT
// length: 80 (64 + 12 + 4)
// gadget: 0x080994cc
// 0x08050b54: jmp eax

void be_nice_to_people(){
    gid_t gid = getegid();
    setresgid(gid, gid, gid);
}

void vuln(char *name){
    char buf[64];
    strcpy(buf, name);
}

int main(int argc, char **argv){
    be_nice_to_people();
    if(argc > 1)
        vuln(argv[1]);
    return 0;
}
