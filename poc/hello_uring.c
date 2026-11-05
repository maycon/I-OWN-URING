/*
 * hello_uring.c — Phase 1 PoC: read /etc/hostname via raw io_uring
 *
 * No liburing. All io_uring interaction via raw syscall().
 * Prints all io_uring_params offsets and internal pointers for inspection.
 *
 * Build: gcc -Wall -O0 -o hello_uring hello_uring.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <linux/io_uring.h>

#define __NR_io_uring_setup  425
#define __NR_io_uring_enter  426

/* AGENTS.md rule: runtime kernel check with a clear error message. */
static int require_kernel(int major, int minor, const char *feature) {
    struct utsname u = {0};
    int a = 0, b = 0;
    if (uname(&u) != 0 || sscanf(u.release, "%d.%d", &a, &b) < 2) {
        fprintf(stderr, "[-] cannot determine kernel version\n");
        return 0;
    }
    if (a > major || (a == major && b >= minor))
        return 1;
    fprintf(stderr,
            "[-] needs kernel >= %d.%d for %s — this kernel is %s\n",
            major, minor, feature, u.release);
    return 0;
}

static int io_uring_setup(unsigned entries, struct io_uring_params *p) {
    return syscall(__NR_io_uring_setup, entries, p);
}
static int io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                          unsigned flags, void *sig) {
    return syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, sig);
}

struct ring {
    int fd;
    struct io_uring_params params;
    void *sq_ptr, *cq_ptr;
    unsigned *sq_head, *sq_tail, *sq_mask, *sq_array;
    unsigned *cq_head, *cq_tail, *cq_mask;
    struct io_uring_cqe *cqes;
    struct io_uring_sqe *sqes;
};

int main(void) {
    struct ring r = {0};
    char buf[256] = {0};

    if (!require_kernel(5, 1, "io_uring"))
        return 1;

    r.fd = io_uring_setup(8, &r.params);
    if (r.fd < 0) { perror("io_uring_setup"); return 1; }
    fprintf(stderr, "fd=%d  sq_entries=%u  features=0x%x\n",
            r.fd, r.params.sq_entries, r.params.features);

    size_t sq_sz = r.params.sq_off.array + r.params.sq_entries * sizeof(unsigned);
    size_t cq_sz = r.params.cq_off.cqes  + r.params.cq_entries * sizeof(*r.cqes);
    size_t se_sz = r.params.sq_entries * sizeof(*r.sqes);

    r.sq_ptr = mmap(0, sq_sz, PROT_READ|PROT_WRITE,
                    MAP_SHARED|MAP_POPULATE, r.fd, IORING_OFF_SQ_RING);
    r.cq_ptr = (r.params.features & IORING_FEAT_SINGLE_MMAP)
             ? r.sq_ptr
             : mmap(0, cq_sz, PROT_READ|PROT_WRITE,
                    MAP_SHARED|MAP_POPULATE, r.fd, IORING_OFF_CQ_RING);
    r.sqes   = mmap(0, se_sz, PROT_READ|PROT_WRITE,
                    MAP_SHARED|MAP_POPULATE, r.fd, IORING_OFF_SQES);

    r.sq_head  = r.sq_ptr + r.params.sq_off.head;
    r.sq_tail  = r.sq_ptr + r.params.sq_off.tail;
    r.sq_mask  = r.sq_ptr + r.params.sq_off.ring_mask;
    r.sq_array = r.sq_ptr + r.params.sq_off.array;
    r.cq_head  = r.cq_ptr + r.params.cq_off.head;
    r.cq_tail  = r.cq_ptr + r.params.cq_off.tail;
    r.cq_mask  = r.cq_ptr + r.params.cq_off.ring_mask;
    r.cqes     = r.cq_ptr + r.params.cq_off.cqes;

    fprintf(stderr, "sq_tail=%p  cq_head=%p  sqes=%p\n",
            (void*)r.sq_tail, (void*)r.cq_head, (void*)r.sqes);

    int fd = open("/etc/hostname", O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    unsigned idx = *r.sq_tail & *r.sq_mask;
    struct io_uring_sqe *sqe = &r.sqes[idx];
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode    = IORING_OP_READ;
    sqe->fd        = fd;
    sqe->addr      = (unsigned long)buf;
    sqe->len       = sizeof(buf) - 1;
    sqe->user_data = 0x1337;
    r.sq_array[idx] = idx;
    (*r.sq_tail)++;

    if (io_uring_enter(r.fd, 1, 1, IORING_ENTER_GETEVENTS, NULL) < 0) {
        perror("io_uring_enter"); return 1;
    }

    struct io_uring_cqe *cqe = &r.cqes[*r.cq_head & *r.cq_mask];
    fprintf(stderr, "CQE res=%d  user_data=0x%llx\n",
            cqe->res, (unsigned long long)cqe->user_data);
    if (cqe->res > 0) {
        buf[cqe->res] = '\0';
        printf("hostname: %s", buf);
    }
    (*r.cq_head)++;

    close(fd);
    close(r.fd);
    return 0;
}
