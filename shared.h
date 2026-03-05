#ifndef __SHARED_H
#define __SHARED_H

#define TASK_COMM_LEN 16
#define MAX_ENTRIES 10240

struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    uint32_t entropy;
};

struct velocity_stats {
    uint64_t window_start;
    uint32_t count;
};

#endif
