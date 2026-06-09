#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

extern uint64_t user_cs, user_ss, user_sp, user_rflags;

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

#define WAIT(void)                                                             \
    {                                                                          \
        getc(stdin);                                                           \
        fflush(stdin);                                                         \
    }

#define errExit(fmt, ...)                                                      \
    do {                                                                       \
        int saved_errno = errno;                                               \
        fprintf(stderr, fmt ": %s\n", ##__VA_ARGS__, strerror(saved_errno));   \
        exit(EXIT_FAILURE);                                                    \
    } while (0)

#define ARRAY_SIZE(a) (sizeof((a)) / sizeof((a)[0]))
#define HEAP_MASK 0xffff000000000000
#define KERNEL_MASK 0xffffffff00000000
#define PAGE_SIZE 0x1000

#define _pte_index_to_virt(i) (i << 12)
// pmd = Page Middle Directory
// (often called PDE (page directory entry))
#define _pmd_index_to_virt(i) (i << 21)
#define _pud_index_to_virt(i) (i << 30)
#define _pgd_index_to_virt(i) (i << 39)
#define PTI_TO_VIRT(pud_index, pmd_index, pte_index, page_index)               \
    ((void *)(_pgd_index_to_virt((uint64_t)(pud_index)) +                      \
              _pud_index_to_virt((uint64_t)(pmd_index)) +                      \
              _pmd_index_to_virt((uint64_t)(pte_index)) +                      \
              _pte_index_to_virt((uint64_t)(page_index))))

bool is_kernel_ptr(uint64_t val);

bool is_heap_ptr(uint64_t val);

void info(const char *format, ...);

void error(const char *format, ...);

void hexdump(void *buf, size_t len);

void get_shell_docker(void);

void assign_thread_to_core(int core_id);

void assign_to_core(int core_id);

int ulimit_fd(void);

void save_state(void);

void unshare_setup(uid_t uid, gid_t gid);

void print_regs(pt_regs_t *regs);

void evict_tlb(void);
void evict_tlb2(void);

uint64_t stext_phys_leak_pte();

void spray_unix_control(void *data, size_t len);

bool is_writable(void *addr);
void install_fault_handler(void);
