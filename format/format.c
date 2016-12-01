#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

int secret = 0;

// location: 0804a030
// payload: '%1337x%7$n'
// flag: who_thought_%n_was_a_good_idea?

void give_shell(){
    gid_t gid = getegid();
    setresgid(gid, gid, gid);
    system("/bin/sh -i");
}

int main(int argc, char **argv){
    int *ptr = &secret;
    printf(argv[1]);

    if (secret == 1337){
        give_shell();
    }
    return 0;
}
