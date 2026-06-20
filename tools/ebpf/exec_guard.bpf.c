// SPDX-License-Identifier: GPL-2.0-only
//
// babbleon untrusted-exec-guard BPF LSM program.
//
// Hook: bprm_check_security (fires before execve actually starts the binary).
//
// Logic:
//   1. Read the calling task's mnt-NS inode.
//   2. Look up the trusted-NS inode from the TRUSTED_INODE map.
//   3. If they differ → untrusted tier → check if the path being exec'd is
//      under the scrambled wrapper dir.
//   4. If the path is NOT under the scrambled dir → return -EACCES.
//
// Build:
//   clang -O2 -target bpf -D__TARGET_ARCH_x86 \
//         -I/usr/include/bpf \
//         -c exec_guard.bpf.c -o exec_guard.bpf.o
//   llvm-strip -g exec_guard.bpf.o
//
// The resulting .o is embedded by the Rust build step.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Map: key=0 → trusted mount-NS inode (u64).
// Populated by babbleon-cli after loading the program.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} trusted_inode_map SEC(".maps");

// Map: key=0 → scrambled root path prefix (null-terminated, max 256 bytes).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[256]);
} scrambled_root_map SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_guard, struct linux_binprm *bprm)
{
    __u32 key = 0;
    __u64 *trusted_inode;
    char (*scrambled_root)[256];

    trusted_inode = bpf_map_lookup_elem(&trusted_inode_map, &key);
    if (!trusted_inode || *trusted_inode == 0)
        return 0; // not configured yet — allow

    scrambled_root = bpf_map_lookup_elem(&scrambled_root_map, &key);
    if (!scrambled_root)
        return 0;

    // Get this task's mount NS inode
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
    __u64 my_inode = BPF_CORE_READ(mnt_ns, ns.inum);

    if (my_inode == *trusted_inode)
        return 0; // trusted tier — allow everything

    // Untrusted tier: check path prefix
    const char *path = bprm->filename;
    char root[256];
    bpf_probe_read_kernel_str(root, sizeof(root), scrambled_root);

    // Compare prefix: first find length of root
    int root_len = 0;
    for (int i = 0; i < 255 && root[i] != '\0'; i++)
        root_len = i + 1;

    if (root_len == 0)
        return 0; // scrambled root not configured — allow

    // Read path prefix and compare
    char path_prefix[256] = {};
    bpf_probe_read_user_str(path_prefix, sizeof(path_prefix), path);

    for (int i = 0; i < root_len && i < 255; i++) {
        if (path_prefix[i] != root[i])
            return -EACCES; // path not under scrambled root
    }

    return 0; // path starts with scrambled root — allow
}

char _license[] SEC("license") = "GPL";
