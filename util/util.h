#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>

extern uint64_t user_cs,user_ss,user_sp,user_rflags;

typedef struct {
    ulong r15;
    ulong r14;
    ulong r13;
    ulong r12;
    ulong bp;
    ulong bx;
    ulong r11;
    ulong r10;
    ulong r9;
    ulong r8;
    ulong ax;
    ulong cx;
    ulong dx;
    ulong si;
    ulong di;
    ulong orig_ax;
    ulong ip;
    ulong cs;
    ulong flags;
    ulong sp;
    ulong ss;
} pt_regs_t;

#define WAIT(void) {getc(stdin); fflush(stdin);}
#define errExit(msg) do { perror(msg); exit(EXIT_FAILURE);} while (0)
#define fail(msg) do {error(msg); exit(EXIT_FAILURE);} while (0)

#define ARRAY_SIZE(a) (sizeof((a)) / sizeof((a)[0]))
#define HEAP_MASK 0xffff000000000000
#define KERNEL_MASK 0xffffffff00000000
#define PAGE_SZ 0x1000

bool is_kernel_ptr(uint64_t val);

bool is_heap_ptr(uint64_t val);

void info(const char *format, ...);

void error(const char *format, ...);

void hexdump(void* buf, size_t len);

void get_shell_docker(void);

void assign_thread_to_core(int core_id);

void assign_to_core(int core_id);

int ulimit_fd(void);

void save_state(void);

void unshare_setup(uid_t uid, gid_t gid);

void print_regs(pt_regs_t* regs);

uint64_t stext_phys_leak_pte();
