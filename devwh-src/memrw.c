// SPDX-License-Identifier: GPL-2.0
/*
 * memrw.c -- cross-process memory R/W primitives.
 *
 * These two functions implement read/write of another process's virtual
 * memory by walking its mm->pgd by hand and addressing the underlying
 * physical page through the linear map. This bypasses ptrace scope
 * checks (Yama, SELinux, seccomp filters) and -- more importantly for
 * the author -- avoids leaving any userspace audit trail.
 *
 * The page-table walk is written for the 4-level, 4K-page, 39-bit VA
 * ARM64 layout used by Android kernels. If you retarget to 16K pages or
 * 48-bit VA you MUST update the shift/mask constants.
 *
 * NOTE: This file intentionally uses generic kernel helpers
 * (copy_to_user/copy_from_user) rather than the hand-rolled PAN-toggle
 * sequences present in the original binary. The kernel's own helpers
 * already handle PAN correctly on all supported ARM64 kernels; the
 * hand-rolled version in the .ko exists because Clang PAC/BTI/CFI caused
 * LTO to inline copy_{to,from}_user into something the author did not
 * want to debug. Functionally equivalent, same result.
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>

#include "devwh.h"

/* --- page-table walk ------------------------------------------------ */

static phys_addr_t devwh_va_to_pa(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    phys_addr_t pa = 0;

    if (!mm || !mm->pgd)
        return 0;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;

    pud = pud_offset((p4d_t *)pgd, va);
    if (pud_none(*pud) || pud_bad(*pud))
        return 0;

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return 0;

    pte = pte_offset_kernel(pmd, va);
    if (!pte || !pte_present(*pte))
        return 0;

    pa = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT) | (va & ~PAGE_MASK);
    return pa;
}

static size_t devwh_size_in_page(uintptr_t addr, size_t size)
{
    size_t left = PAGE_SIZE - (addr & ~PAGE_MASK);
    return size < left ? size : left;
}

/* --- physical-address R/W scratch buffer ---------------------------- */

static DEFINE_MUTEX(devwh_phys_mutex);
static void *devwh_rbuf;
static size_t devwh_rbuf_sz;
static void *devwh_wbuf;
static size_t devwh_wbuf_sz;

static int devwh_ensure_buf(void **buf, size_t *cur_sz, size_t need)
{
    void *nb;

    if (*buf && *cur_sz >= need)
        return 0;
    kfree(*buf);
    nb = kmalloc(need, GFP_KERNEL);
    if (!nb) {
        *buf = NULL;
        *cur_sz = 0;
        return -ENOMEM;
    }
    *buf = nb;
    *cur_sz = need;
    return 0;
}

static bool devwh_read_pa(phys_addr_t pa, void __user *ubuf, size_t size)
{
    struct page *page;
    unsigned long pfn = pa >> PAGE_SHIFT;
    void *src;
    bool ok = false;

    if (!pfn_valid(pfn))
        return false;

    page = pfn_to_page(pfn);

    mutex_lock(&devwh_phys_mutex);
    if (devwh_ensure_buf(&devwh_rbuf, &devwh_rbuf_sz, size) != 0)
        goto out;

    src = kmap(page);
    memcpy(devwh_rbuf, (char *)src + (pa & ~PAGE_MASK), size);
    kunmap(page);

    if (copy_to_user(ubuf, devwh_rbuf, size) == 0)
        ok = true;
out:
    mutex_unlock(&devwh_phys_mutex);
    return ok;
}

static bool devwh_write_pa(phys_addr_t pa, const void __user *ubuf, size_t size)
{
    struct page *page;
    unsigned long pfn = pa >> PAGE_SHIFT;
    void *dst;
    bool ok = false;

    if (!pfn_valid(pfn))
        return false;

    page = pfn_to_page(pfn);

    mutex_lock(&devwh_phys_mutex);
    if (devwh_ensure_buf(&devwh_wbuf, &devwh_wbuf_sz, size) != 0)
        goto out;

    if (copy_from_user(devwh_wbuf, ubuf, size) != 0)
        goto out;

    dst = kmap(page);
    memcpy((char *)dst + (pa & ~PAGE_MASK), devwh_wbuf, size);
    /*
     * ARM64 userspace uses VIPT-aliasing-safe I-cache semantics, but the
     * page we just wrote is almost always a data page for another task;
     * flushing dcache to PoU is sufficient. The observed .ko uses DC
     * CIVAC (Clean & Invalidate by VA to PoC) across the touched range.
     */
    flush_dcache_page(page);
    kunmap(page);
    ok = true;
out:
    mutex_unlock(&devwh_phys_mutex);
    return ok;
}

/* --- public API ----------------------------------------------------- */

static struct task_struct *devwh_get_task(pid_t pid_nr)
{
    struct pid *pid;
    struct task_struct *task;

    pid = find_get_pid(pid_nr);
    if (!pid)
        return NULL;
    task = get_pid_task(pid, PIDTYPE_PID);
    put_pid(pid);
    return task;
}

bool devwh_read_process_memory(pid_t pid, uintptr_t addr,
                               void __user *user_buf, size_t size)
{
    struct task_struct *task;
    struct mm_struct   *mm;
    bool ok = true;

    task = devwh_get_task(pid);
    if (!task)
        return false;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return false;

    while (size) {
        size_t chunk = devwh_size_in_page(addr, size);
        phys_addr_t pa;

        pa = devwh_va_to_pa(mm, addr);
        if (!pa || !devwh_read_pa(pa, user_buf, chunk)) {
            ok = false;
            break;
        }
        addr     += chunk;
        user_buf  = (char __user *)user_buf + chunk;
        size     -= chunk;
    }

    mmput(mm);
    return ok;
}

bool devwh_write_process_memory(pid_t pid, uintptr_t addr,
                                const void __user *user_buf, size_t size)
{
    struct task_struct *task;
    struct mm_struct   *mm;
    bool ok = true;

    task = devwh_get_task(pid);
    if (!task)
        return false;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return false;

    while (size) {
        size_t chunk = devwh_size_in_page(addr, size);
        phys_addr_t pa;

        pa = devwh_va_to_pa(mm, addr);
        if (!pa || !devwh_write_pa(pa, user_buf, chunk)) {
            ok = false;
            break;
        }
        addr     += chunk;
        user_buf  = (const char __user *)user_buf + chunk;
        size     -= chunk;
    }

    mmput(mm);
    return ok;
}

void devwh_memrw_release(void)
{
    mutex_lock(&devwh_phys_mutex);
    kfree(devwh_rbuf); devwh_rbuf = NULL; devwh_rbuf_sz = 0;
    kfree(devwh_wbuf); devwh_wbuf = NULL; devwh_wbuf_sz = 0;
    mutex_unlock(&devwh_phys_mutex);
}
