#include "shm_race.h"
#include "util/util.h"
#include <pthread.h>
#include <stdio.h>

#ifdef POC
int main(void) {
    pthread_barrier_t barrier;
    pthread_barrier_init(&barrier, NULL, 2);
    void *buf;

    shm_race_args_t args = {.barrier = &barrier, .buf = &buf};

    pthread_t hole_punch_thread;
    int ret = pthread_create(&hole_punch_thread, NULL,
                             (void *)shm_race_hole_punc, (void *)&args);
    if (ret < 0) {
        errExit("Pthread create");
    }

    struct timespec start, end;
    ret = pthread_barrier_wait(&barrier); // barrier 1
    if (ret < 0) {
        errExit("pthread barrier wait");
    }

    clock_gettime(CLOCK_MONOTONIC, &start);
    volatile char dummy =
        *(char *)buf; // Simulated kernel access during hole punch
    clock_gettime(CLOCK_MONOTONIC, &end);

    long long stall_ns = (end.tv_sec - start.tv_sec) * 1000000000LL +
                         (end.tv_nsec - start.tv_nsec);

    printf("Stall time: %lld ns\n", stall_ns);
}
#endif