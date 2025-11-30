#include <pthread.h>

typedef struct {
    void** buf;
    pthread_barrier_t* barrier;
} shm_race_args_t;

void shm_race_hole_punc(shm_race_args_t* args);