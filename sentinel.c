#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "shared.h"
#include "sentinel.skel.h"

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    printf("BLOCK: PID %d [%s] Entropy: %d/1024\n", e->pid, e->comm, e->entropy);
    fflush(stdout);
    kill(e->pid, SIGSTOP);
    return 0;
}

int main() {
    struct sentinel_bpf *skel = sentinel_bpf__open_and_load();
    if (!skel) return 1;
    if (sentinel_bpf__attach(skel)) goto cleanup;

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) goto cleanup;

    while (1) {
        ring_buffer__poll(rb, 100);
    }

cleanup:
    sentinel_bpf__destroy(skel);
    return 0;
}

