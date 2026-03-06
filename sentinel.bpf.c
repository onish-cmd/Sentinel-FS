#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "shared.h"

static const u32 log_lut[257] = {
    0, 0, 1024, 1623, 2048, 2377, 2647, 2875, 3072, 3247, 3405, 3549, 3682, 3806, 3921, 4030,
    4132, 4230, 4323, 4411, 4496, 4577, 4655, 4731, 4803, 4874, 4942, 5008, 5073, 5136, 5197, 5257,
    5315, 5372, 5427, 5482, 5535, 5587, 5638, 5688, 5737, 5786, 5833, 5880, 5926, 5971, 6016, 6060,
    6103, 6146, 6188, 6229, 6270, 6311, 6351, 6390, 6429, 6468, 6506, 6544, 6582, 6619, 6656, 6692,
    6728, 6764, 6799, 6834, 6869, 6903, 6937, 6971, 7004, 7038, 7071, 7104, 7136, 7169, 7201, 7233,
    7265, 7296, 7327, 7358, 7389, 7420, 7450, 7480, 7511, 7540, 7570, 7600, 7629, 7659, 7688, 7717,
    7746, 7775, 7803, 7832, 7860, 7888, 7917, 7945, 7972, 8000, 8028, 8055, 8083, 8110, 8137, 8165,
    8192, 8219, 8246, 8272, 8299, 8326, 8352, 8379, 8405, 8432, 8458, 8484, 8510, 8536, 8562, 8588,
    8614, 8640, 8665, 8691, 8716, 8742, 8767, 8793, 8818, 8843, 8868, 8894, 8919, 8944, 8969, 8994,
    9019, 9043, 9068, 9093, 9118, 9142, 9167, 9191, 9216, 9240, 9265, 9289, 9313, 9338, 9362, 9386,
    9410, 9434, 9458, 9482, 9506, 9530, 9554, 9578, 9602, 9625, 9649, 9673, 9696, 9720, 9743, 9767,
    9790, 9814, 9837, 9860, 9884, 9907, 9930, 9953, 9976, 9999, 10022, 10045, 10068, 10091, 10114, 10137,
    10160, 10182, 10205, 10228, 10251, 10273, 10296, 10318, 10341, 10363, 10386, 10408, 10431, 10453, 10475, 10498,
    10520, 10542, 10564, 10587, 10609, 10631, 10653, 10675, 10697, 10719, 10741, 10763, 10785, 10807, 10829, 10850,
    10872, 10894, 10916, 10937, 10959, 10981, 11002, 11024, 11046, 11067, 11089, 11110, 11132, 11153, 11175, 11196,
    11217, 11239, 11260, 11281, 11303, 11324, 11345, 11366, 11388, 11409, 11430, 11451, 11472, 11493, 11514, 11535, 11556
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u32);
} histogram_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct velocity_stats);
} write_velocity SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u8);
} blocked_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Formula: H = 8 - (1/256) * sum(c * log2(c))
static __always_inline u32 calc_entropy_256(const unsigned char *data) {
    u32 sum_clogc = 0;
    
    #pragma unroll
    for (int i = 0; i < 256; i++) {
        u32 key = i;
        u32 *val = bpf_map_lookup_elem(&histogram_scratch, &key);
        if (val) *val = 0;
    }

    #pragma unroll
    for (int i = 0; i < 256; i++) {
        u32 key = data[i];
        u32 *val = bpf_map_lookup_elem(&histogram_scratch, &key);
        if (val) *val += 1;
    }

    #pragma unroll
    for (int i = 0; i < 256; i++) {
        u32 key = i;
        u32 *val = bpf_map_lookup_elem(&histogram_scratch, &key);
        if (val && *val > 0 && *val <= 256) {
            sum_clogc += log_lut[*val];
        }
    }

    return (8 << 10) - (sum_clogc >> 8);
}

static __always_inline bool is_high_velocity(u32 pid) {
    u64 now = bpf_ktime_get_ns();
    struct velocity_stats *stats = bpf_map_lookup_elem(&write_velocity, &pid);

    if (!stats) {
        struct velocity_stats new_stats = { .window_start = now, .count = 1 };
        bpf_map_update_elem(&write_velocity, &pid, &new_stats, BPF_ANY);
        return false;
    }

    if (now - stats->window_start > 1000000000ULL) {
        stats->window_start = now;
        stats->count = 1;
        return false;
    }

    stats->count++;
    return (stats->count > 5);
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_write_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    size_t count = (size_t)ctx->args[2];
    const char *buf = (const char *)ctx->args[1];
    u8 one = 1;

    if (count < 256) return 0;

    unsigned char sample[256];
    if (bpf_probe_read_user(sample, sizeof(sample), buf) < 0) return 0;

    u32 entropy = calc_entropy_256(sample);

    if (entropy > 5000) {
        if (is_high_velocity(pid)) {
            bpf_map_update_elem(&blocked_pids, &pid, &one, BPF_ANY);
            struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
            if (e) {
                e->pid = pid;
                e->entropy = entropy;
                bpf_get_current_comm(&e->comm, sizeof(e->comm));
                bpf_ringbuf_submit(e, 0);
            }
        }
    }
    return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(sentinel_block, struct file *file, int mask) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&blocked_pids, &pid)) return -1;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

