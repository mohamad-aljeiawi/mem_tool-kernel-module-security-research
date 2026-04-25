/*
 * dumper.c — kprobe-based init_module umod buffer extractor
 *
 * What it does:
 *   1. Installs a kernel kprobe on __arm64_sys_init_module.
 *      Probe captures pt_regs.regs[0] (umod ptr) and pt_regs.regs[1] (len).
 *   2. Blocks reading /sys/kernel/tracing/trace_pipe.
 *   3. On the first matching event:
 *        a. Parses pid, umod, len from the trace line.
 *        b. Strips the MTE / TBI top byte from umod (& 0x00FFFFFFFFFFFFFF).
 *        c. open("/proc/<pid>/mem", O_RDONLY).
 *        d. lseek to umod.
 *        e. read(len) into a heap buffer.
 *        f. write to OUT_FILE.
 *   4. Removes the kprobe and exits.
 *
 * Build:
 *   $NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android33-clang \
 *     src/dumper.c -O2 -static -o prebuilt/dumper
 *
 * Run (on device, as root):
 *   /data/local/tmp/dumper &
 *   /data/local/tmp/X.X.elf
 *   # dumper writes /data/local/tmp/dumped_bing_rw.ko on first event
 *
 * The reaction-time budget is ~30-100 ms (between init_module entry and
 * binary exit). Native C with ~120 µs total dispatch leaves plenty of margin.
 *
 * Dependencies: just libc. Statically link with -static so the binary runs
 * regardless of what's on the device.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>

#define TRACE_DIR     "/sys/kernel/tracing"
#define KPROBE_EVENTS TRACE_DIR "/kprobe_events"
#define TRACE_PIPE    TRACE_DIR "/trace_pipe"
#define KPROBE_NAME   "ft_init_x"
#define OUT_FILE      "/data/local/tmp/dumped_bing_rw.ko"

/* MTE / TBI top-byte mask — keep low 56 bits. */
#define UNTAG_MASK    0x00FFFFFFFFFFFFFFULL

static int write_str(const char *path, const char *s, int extra_flags)
{
    int fd = open(path, O_WRONLY | extra_flags);
    if (fd < 0) return -1;
    ssize_t n = write(fd, s, strlen(s));
    int saved = errno;
    close(fd);
    errno = saved;
    return (int)n;
}

static int set_event_enable(const char *event, int enable)
{
    char path[256];
    snprintf(path, sizeof(path),
             TRACE_DIR "/events/kprobes/%s/enable", event);
    return write_str(path, enable ? "1" : "0", 0);
}

static volatile int g_done = 0;
static void on_sig(int s) { (void)s; g_done = 1; }

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    signal(SIGINT,  on_sig);
    signal(SIGTERM, on_sig);

    /*
     * Best-effort cleanup of a stale kprobe of the same name.
     * If our previous run didn't shut down cleanly, the kprobe persists.
     */
    char rm_buf[128];
    snprintf(rm_buf, sizeof(rm_buf), "-:kprobes/%s\n", KPROBE_NAME);
    write_str(KPROBE_EVENTS, rm_buf, O_APPEND);

    /*
     * Install kprobe on __arm64_sys_init_module.
     *
     * Why pt_regs deref?
     *   On modern aarch64 kernels, syscall handlers are wrapped:
     *     long __arm64_sys_init_module(const struct pt_regs *regs);
     *   x0 holds `regs`, NOT the userland umod pointer.
     *   The original syscall args are at:
     *     regs->regs[0] = umod   (offset 0 in pt_regs)
     *     regs->regs[1] = len    (offset 8)
     *     regs->regs[2] = uargs  (offset 16)
     */
    const char *probe =
        "p:" KPROBE_NAME " __arm64_sys_init_module "
        "umod=+0(%x0):x64 len=+8(%x0):x64\n";

    if (write_str(KPROBE_EVENTS, probe, O_APPEND) < 0) {
        fprintf(stderr, "[!] kprobe install failed: %s\n", strerror(errno));
        fprintf(stderr, "    (need root + writable %s)\n", KPROBE_EVENTS);
        return 1;
    }

    if (set_event_enable(KPROBE_NAME, 1) < 0) {
        fprintf(stderr, "[!] kprobe enable failed: %s\n", strerror(errno));
        return 1;
    }

    write_str(TRACE_DIR "/tracing_on", "1", 0);

    fprintf(stderr, "[*] kprobe installed; reading trace_pipe...\n");
    fflush(stderr);

    int fd = open(TRACE_PIPE, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[!] open trace_pipe: %s\n", strerror(errno));
        return 1;
    }

    char buf[8192];
    int dumped = 0;

    while (!g_done && !dumped) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        buf[n] = 0;

        /* Iterate over lines in this read. */
        char *p = buf, *nl;
        while (p && *p) {
            nl = strchr(p, '\n');
            if (nl) *nl++ = 0;

            if (!strstr(p, KPROBE_NAME ":")) {
                p = nl;
                continue;
            }

            fprintf(stderr, "[+] event: %s\n", p);

            /*
             * Trace line format example:
             *   ft_test.elf-16694 [007] d..1 92.114483: ft_init_x:
             *   (__arm64_sys_init_module+0x0/0x2e4)
             *   umod=0xb4000076ffe73320 len=0x7038
             *
             * Parse pid (after first '-'), umod (after "umod="), len (after "len=").
             */
            int pid = 0;
            const char *dash = strchr(p, '-');
            if (dash && dash[1]) {
                pid = (int)strtol(dash + 1, NULL, 10);
            }

            unsigned long long umod = 0, len = 0;
            const char *up = strstr(p, "umod=");
            const char *lp = strstr(p, "len=");
            if (up) umod = strtoull(up + 5, NULL, 0);  /* base 0 -> auto-hex on 0x */
            if (lp) len  = strtoull(lp + 4, NULL, 0);

            fprintf(stderr, "[+] pid=%d umod=0x%llx len=%llu\n",
                    pid, umod, len);

            if (pid <= 0 || umod == 0 || len == 0 ||
                len > 16ULL * 1024 * 1024) {
                fprintf(stderr, "[!] parse rejected\n");
                p = nl; continue;
            }

            /* Strip MTE / TBI top-byte tag. */
            unsigned long long umod_addr = umod & UNTAG_MASK;

            char mem_path[64];
            snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
            int mfd = open(mem_path, O_RDONLY | O_CLOEXEC);
            if (mfd < 0) {
                fprintf(stderr, "[!] open %s: %s\n",
                        mem_path, strerror(errno));
                p = nl; continue;
            }

            if (lseek(mfd, (off_t)umod_addr, SEEK_SET) == (off_t)-1) {
                fprintf(stderr, "[!] lseek: %s\n", strerror(errno));
                close(mfd);
                p = nl; continue;
            }

            unsigned char *kobuf = (unsigned char *)malloc((size_t)len);
            if (!kobuf) {
                fprintf(stderr, "[!] malloc(%llu) failed\n", len);
                close(mfd);
                p = nl; continue;
            }

            size_t total = 0;
            while (total < (size_t)len) {
                ssize_t r = read(mfd, kobuf + total, (size_t)len - total);
                if (r <= 0) break;
                total += (size_t)r;
            }
            close(mfd);

            fprintf(stderr, "[+] read %zu / %llu bytes\n", total, len);

            if (total > 0) {
                int ofd = open(OUT_FILE,
                               O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (ofd >= 0) {
                    ssize_t w = write(ofd, kobuf, total);
                    close(ofd);
                    fprintf(stderr, "[+] wrote %zd bytes -> %s\n",
                            w, OUT_FILE);
                } else {
                    fprintf(stderr, "[!] open %s: %s\n",
                            OUT_FILE, strerror(errno));
                }

                if (total >= 4 &&
                    memcmp(kobuf, "\x7f""ELF", 4) == 0) {
                    fprintf(stderr,
                            "[+] ELF MAGIC PRESENT — looks like a .ko!\n");
                }
                dumped = 1;
            }

            free(kobuf);
            p = nl;
        }
    }

    close(fd);

    /* Cleanup: disable + remove our kprobe. */
    set_event_enable(KPROBE_NAME, 0);
    write_str(KPROBE_EVENTS, rm_buf, O_APPEND);

    fprintf(stderr, "[*] dumper exit, dumped=%d\n", dumped);
    return dumped ? 0 : 2;
}
