#define _GNU_SOURCE
#include "util/util.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <err.h>

#include "shm_race.h"

#define FALLOC_LEN 64 * 1024 * 1024 // Max on Ubuntu 25.04

void shm_race_hole_punc(shm_race_args_t* args) {
    void** buf = args->buf;
    pthread_barrier_t* barrier = args->barrier;

    int fd = open("/dev/shm", O_TMPFILE | O_RDWR, 0666);
    if (fd < 0) {
        errExit("open /dev/shm");
    }

    int ret = fallocate(fd, 0, 0, FALLOC_LEN);
    if (ret < 0) {
        errExit("fallocate");
    }

    *buf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        errExit("mmap /dev/shm");
    }

    pthread_barrier_wait(barrier);

    ret = fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, FALLOC_LEN);

    if (ret < 0) {
        errExit("fallocate punch hole");
    }
}