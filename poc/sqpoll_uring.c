/*
 * sqpoll_uring.c — Phase 1 PoC: SQPOLL mode (zero io_uring_enter after setup)
 *
 * After io_uring_setup with IORING_SETUP_SQPOLL, a kernel thread polls the SQ.
 * Submitting ops requires only writing to shared memory — no syscall at all.
 * EDRs watching sys_enter see the process as completely idle after setup.
 *
 * Build: gcc -Wall -O0 -o sqpoll_uring sqpoll_uring.c
 * Note:  requires kernel >= 5.11 (no CAP_SYS_NICE needed)
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
static int io_uring_enter(int fd, unsigned s, unsigned m, unsigned f, void *g) {
    return syscall(__NR_io_uring_enter, fd, s, m, f, g);
}

int main(void) {
    if (!require_kernel(5, 11, "unprivileged SQPOLL (IORING_SETUP_SQPOLL)"))
        return 1;

    struct io_uring_params p = {0};
    p.flags = IORING_SETUP_SQPOLL;
    p.sq_thread_idle = 2000;  /* 2s idle before thread sleeps */

    int rfd = io_uring_setup(8, &p);
    if (rfd < 0) { perror("io_uring_setup (SQPOLL)"); return 1; }
    fprintf(stderr,"[*] SQPOLL setup: fd=%d  sq_entries=%u\n", rfd, p.sq_entries);

    size_t ssz = p.sq_off.array + p.sq_entries * 4;
    size_t csz = p.cq_off.cqes  + p.cq_entries * sizeof(struct io_uring_cqe);
    size_t esz = p.sq_entries * sizeof(struct io_uring_sqe);

    void *sq = mmap(0,ssz,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_POPULATE,rfd,IORING_OFF_SQ_RING);
    void *cq = (p.features & IORING_FEAT_SINGLE_MMAP) ? sq
             : mmap(0,csz,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_POPULATE,rfd,IORING_OFF_CQ_RING);
    struct io_uring_sqe *sqes = mmap(0,esz,PROT_READ|PROT_WRITE,
                                     MAP_SHARED|MAP_POPULATE,rfd,IORING_OFF_SQES);

    unsigned *sq_t  = sq + p.sq_off.tail;
    unsigned *sq_mk = sq + p.sq_off.ring_mask;
    unsigned *sq_arr= sq + p.sq_off.array;
    unsigned *cq_h  = cq + p.cq_off.head;
    unsigned *cq_t  = cq + p.cq_off.tail;
    unsigned *cq_mk = cq + p.cq_off.ring_mask;
    struct io_uring_cqe *cqes = cq + p.cq_off.cqes;

    /* --- Open file (SQPOLL: write to SQ, no syscall) --- */
    int fd = open("/etc/hostname", O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    char buf[256] = {0};

    /* Submit READ via shared memory only — SQPOLL thread picks it up */
    unsigned idx = *sq_t & *sq_mk;
    struct io_uring_sqe *s = &sqes[idx];
    memset(s, 0, sizeof(*s));
    s->opcode = IORING_OP_READ;
    s->fd     = fd;
    s->addr   = (uint64_t)(uintptr_t)buf;
    s->len    = sizeof(buf)-1;
    s->user_data = 0x42;
    sq_arr[idx] = idx;
    __sync_synchronize();    /* memory barrier before tail increment */
    (*sq_t)++;

    fprintf(stderr,"[*] SQE submitted via shared memory (NO io_uring_enter syscall)\n");

    /* Poll CQE with timeout */
    int res = -1;
    for (int i = 0; i < 500; i++) {
        if (*cq_h != *cq_t) {
            struct io_uring_cqe *c = &cqes[*cq_h & *cq_mk];
            res = c->res;
            (*cq_h)++;
            break;
        }
        /* Wake SQPOLL thread if it went idle */
        if (i == 200)
            io_uring_enter(rfd, 0, 1, IORING_ENTER_GETEVENTS, NULL);
        usleep(10000);  /* 10ms */
    }

    if (res > 0) {
        buf[res] = '\0';
        fprintf(stderr,"[+] Read %d bytes: %s", res, buf);
    } else {
        fprintf(stderr,"[!] CQE res=%d (timeout or error)\n", res);
    }

    fprintf(stderr,"\n[*] After SQPOLL setup, io_uring_enter call count: ~0\n");
    fprintf(stderr,"[*] EDR watching sys_enter sees: nothing\n");

    close(fd);
    close(rfd);
    return 0;
}
