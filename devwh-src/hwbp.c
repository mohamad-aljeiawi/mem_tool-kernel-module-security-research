// SPDX-License-Identifier: GPL-2.0
/*
 * hwbp.c -- cross-process hardware-breakpoint install/hit/auto-restore.
 *
 * Implementation notes (matching the observed 6.6.ko):
 *
 * - We resolve register_user_hw_breakpoint / unregister_hw_breakpoint /
 *   modify_user_hw_breakpoint via kallsyms on first use. These live
 *   under hw_breakpoint.c in the kernel and are GPL-only EXPORTs; the
 *   binary resolves them by name to avoid depending on having a GPL
 *   license visible in modinfo (but we DO declare GPL -- see main.c).
 *
 * - Each installed breakpoint gets a struct devwh_bp that carries its
 *   HW_BP_INFO parameters (the register-overwrite plan) and a small
 *   16-slot ring buffer of hit records. The ring is drained into user
 *   space by OP_CMD_HWBP_GET_HITS.
 *
 * - The overflow callback runs in IRQ context on the task that tripped
 *   the breakpoint. It:
 *     1. Captures pt_regs into the next ring slot (if capture enabled).
 *     2. If is_write_gp_regs, overwrites the requested GP regs in the
 *        user-context pt_regs so the breakpointed instruction sees the
 *        attacker-chosen values on resume.
 *     3. Re-arms the breakpoint with a +/- 4 byte address trick so the
 *        same instruction doesn't re-fire immediately on return.
 *
 * - The 4-byte re-arm trick mirrors what the binary does. It is hacky
 *   -- the "right" way is a single-step, but the author avoided the
 *   arch_install_hw_breakpoint single-step path for portability.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <asm/ptrace.h>
#include <linux/timekeeping.h>

#include "devwh.h"

struct perf_event *(*kfn_register_user_hw_breakpoint)(
    struct perf_event_attr *, perf_overflow_handler_t, void *,
    struct task_struct *);
void (*kfn_unregister_hw_breakpoint)(struct perf_event *);
int  (*kfn_modify_user_hw_breakpoint)(struct perf_event *,
                                      struct perf_event_attr *);
void (*kfn_fpsimd_save)(void);
void (*kfn_fpsimd_flush_task_state)(struct task_struct *);

/* ---- per-breakpoint record --------------------------------------- */

struct devwh_bp {
    struct list_head   node;
    pid_t              pid;
    uintptr_t          addr;
    struct perf_event *bp;
    int                type;
    int                len;

    /* Re-arm state: we flip between the original addr and addr+4.     */
    bool               toggled;

    /* GP-register overwrite plan. */
    bool               is_write_gp_regs;
    int                gp_reg_count;
    int                gp_reg_indices[DEVWH_MAX_MODIFY_REGS];
    u64                gp_reg_values [DEVWH_MAX_MODIFY_REGS];

    /* FP-register overwrite plan (128-bit per reg). */
    bool               is_write_fp_regs;
    int                fp_reg_count;
    int                fp_reg_indices[DEVWH_MAX_MODIFY_REGS];
    u64                fp_reg_values [DEVWH_MAX_MODIFY_REGS][2];

    /* Hit ring buffer (drained by OP_CMD_HWBP_GET_HITS). */
    struct devwh_hwbp_hit_item  ring[DEVWH_HITS_MAX];
    u32                         ring_head;  /* write index          */
    u32                         ring_tail;  /* read  index          */
    u32                         ring_count; /* valid entries        */
    raw_spinlock_t              ring_lock;
};

static LIST_HEAD(devwh_bp_list);
static DEFINE_MUTEX(devwh_bp_mutex);

/* ---- symbol resolution ------------------------------------------- */

static int devwh_hwbp_resolve(void)
{
    if (kfn_register_user_hw_breakpoint && kfn_unregister_hw_breakpoint)
        return 0;

    kfn_register_user_hw_breakpoint = devwh_ksym("register_user_hw_breakpoint");
    kfn_unregister_hw_breakpoint    = devwh_ksym("unregister_hw_breakpoint");
    kfn_modify_user_hw_breakpoint   = devwh_ksym("modify_user_hw_breakpoint");

    kfn_fpsimd_save = devwh_ksym("fpsimd_save");
    if (!kfn_fpsimd_save)
        kfn_fpsimd_save = devwh_ksym("fpsimd_preserve_current_state");
    kfn_fpsimd_flush_task_state = devwh_ksym("fpsimd_flush_task_state");

    if (!kfn_register_user_hw_breakpoint ||
        !kfn_unregister_hw_breakpoint    ||
        !kfn_modify_user_hw_breakpoint) {
        pr_err("[HWBP] Core symbols not found\n");
        return -ENOENT;
    }
    return 0;
}

/* ---- lookup helpers ---------------------------------------------- */

static struct devwh_bp *devwh_bp_find_locked(pid_t pid, uintptr_t addr)
{
    struct devwh_bp *e;

    list_for_each_entry(e, &devwh_bp_list, node)
        if (e->pid == pid && e->addr == addr)
            return e;
    return NULL;
}

/* ---- overflow handler -------------------------------------------- */

static void devwh_bp_capture_hit(struct devwh_bp *e, struct pt_regs *regs)
{
    unsigned long flags;

    raw_spin_lock_irqsave(&e->ring_lock, flags);
    {
        struct devwh_hwbp_hit_item *slot = &e->ring[e->ring_head];

        slot->task_id  = task_pid_nr(current);
        slot->hit_addr = e->addr;
        slot->hit_time = ktime_get_ns() / NSEC_PER_MSEC;

        memcpy(slot->regs_info.regs, regs->regs, sizeof(slot->regs_info.regs));
        slot->regs_info.sp     = regs->sp;
        slot->regs_info.pc     = regs->pc;
        slot->regs_info.pstate = regs->pstate;

        e->ring_head = (e->ring_head + 1) & (DEVWH_HITS_MAX - 1);
        if (e->ring_count < DEVWH_HITS_MAX)
            e->ring_count++;
        else
            /* Overwrite oldest -- advance tail too. */
            e->ring_tail = (e->ring_tail + 1) & (DEVWH_HITS_MAX - 1);
    }
    raw_spin_unlock_irqrestore(&e->ring_lock, flags);
}

static void devwh_bp_overwrite_regs(struct devwh_bp *e, struct pt_regs *regs)
{
    int i;

    if (e->is_write_gp_regs) {
        for (i = 0; i < e->gp_reg_count && i < DEVWH_MAX_MODIFY_REGS; i++) {
            unsigned int idx = (unsigned int)e->gp_reg_indices[i];

            if (idx < 31)
                regs->regs[idx] = e->gp_reg_values[i];
        }
    }
    /*
     * FP register writes require fpsimd context swap. The binary resolves
     * fpsimd_save / fpsimd_preserve_current_state / fpsimd_flush_task_state
     * but the handler body never actually walks the FP plan -- it only
     * validates bounds. We match that behavior: the FP fields are parsed
     * and stored (so userland GET_HITS returns them) but not injected.
     * If you want real FP injection, extend this block to set fields in
     * task->thread.uw.fpsimd_state and call kfn_fpsimd_flush_task_state().
     */
    (void)e->is_write_fp_regs;
}

static void devwh_bp_rearm(struct devwh_bp *e, struct perf_event *bp)
{
    struct perf_event_attr attr;

    if (!kfn_modify_user_hw_breakpoint)
        return;

    memcpy(&attr, &bp->attr, sizeof(attr));
    attr.disabled = 0;
    /*
     * Toggle between addr and addr+4 so the breakpoint doesn't refire on
     * return-from-exception at the same PC. This is what the 6.6.ko
     * handler does; a proper single-step is cleaner but needs more
     * kernel-version-specific wiring.
     */
    attr.bp_addr = e->toggled ? e->addr : (e->addr + 4);
    e->toggled   = !e->toggled;
    kfn_modify_user_hw_breakpoint(bp, &attr);
}

static void devwh_bp_overflow_handler(struct perf_event *bp,
                                      struct perf_sample_data *data,
                                      struct pt_regs *regs)
{
    struct devwh_bp *e = bp->overflow_handler_context;

    if (!regs || !e)
        return;

    devwh_bp_capture_hit(e, regs);
    devwh_bp_overwrite_regs(e, regs);
    devwh_bp_rearm(e, bp);
}

/* ---- install / modify / disable / clear -------------------------- */

static int devwh_bp_type_to_perf(int t)
{
    switch (t) {
    case HW_BP_TYPE_R:  return HW_BREAKPOINT_R;
    case HW_BP_TYPE_W:  return HW_BREAKPOINT_W;
    case HW_BP_TYPE_RW: return HW_BREAKPOINT_RW;
    case HW_BP_TYPE_X:  return HW_BREAKPOINT_X;
    default:            return HW_BREAKPOINT_RW;
    }
}

static void devwh_copy_plan(struct devwh_bp *e, const struct devwh_hw_bp_info *i)
{
    int n, k;

    e->is_write_gp_regs = i->is_write_gp_regs;
    n = clamp_t(int, i->gp_reg_count, 0, DEVWH_MAX_MODIFY_REGS);
    e->gp_reg_count = n;
    for (k = 0; k < n; k++) {
        e->gp_reg_indices[k] = i->gp_reg_indices[k];
        e->gp_reg_values [k] = i->gp_reg_values [k];
    }

    e->is_write_fp_regs = i->is_write_fp_regs;
    n = clamp_t(int, i->fp_reg_count, 0, DEVWH_MAX_MODIFY_REGS);
    e->fp_reg_count = n;
    for (k = 0; k < n; k++) {
        e->fp_reg_indices[k]    = i->fp_reg_indices[k];
        e->fp_reg_values [k][0] = i->fp_reg_values [k][0];
        e->fp_reg_values [k][1] = i->fp_reg_values [k][1];
    }
}

int devwh_hwbp_install(struct devwh_hw_bp_info *info)
{
    struct perf_event_attr attr;
    struct task_struct *task;
    struct pid *pid;
    struct devwh_bp *e;
    int ret;

    ret = devwh_hwbp_resolve();
    if (ret)
        return ret;

    mutex_lock(&devwh_bp_mutex);

    if (devwh_bp_find_locked(info->pid, info->addr)) {
        mutex_unlock(&devwh_bp_mutex);
        return -EEXIST;
    }

    pid  = find_get_pid(info->pid);
    task = pid ? get_pid_task(pid, PIDTYPE_PID) : NULL;
    if (pid) put_pid(pid);
    if (!task) {
        mutex_unlock(&devwh_bp_mutex);
        return -ESRCH;
    }

    e = kzalloc(sizeof(*e), GFP_KERNEL);
    if (!e) {
        put_task_struct(task);
        mutex_unlock(&devwh_bp_mutex);
        return -ENOMEM;
    }

    e->pid    = info->pid;
    e->addr   = info->addr;
    e->type   = info->type;
    e->len    = info->len;
    raw_spin_lock_init(&e->ring_lock);
    devwh_copy_plan(e, info);

    hw_breakpoint_init(&attr);
    attr.bp_addr   = info->addr;
    attr.bp_len    = info->len;
    attr.bp_type   = devwh_bp_type_to_perf(info->type);
    attr.disabled  = 0;

    e->bp = kfn_register_user_hw_breakpoint(&attr,
                                            devwh_bp_overflow_handler,
                                            e, task);
    put_task_struct(task);

    if (IS_ERR_OR_NULL(e->bp)) {
        ret = e->bp ? PTR_ERR(e->bp) : -EINVAL;
        kfree(e);
        mutex_unlock(&devwh_bp_mutex);
        return ret;
    }

    list_add_tail(&e->node, &devwh_bp_list);
    mutex_unlock(&devwh_bp_mutex);
    return 0;
}

int devwh_hwbp_enable(struct devwh_hw_bp_info *info)
{
    struct devwh_bp *e;
    struct perf_event_attr attr;
    int ret = 0;

    mutex_lock(&devwh_bp_mutex);
    e = devwh_bp_find_locked(info->pid, info->addr);
    if (!e) {
        mutex_unlock(&devwh_bp_mutex);
        return -ENOENT;
    }

    devwh_copy_plan(e, info);

    if (e->bp && kfn_modify_user_hw_breakpoint) {
        memcpy(&attr, &e->bp->attr, sizeof(attr));
        attr.disabled = 0;
        ret = kfn_modify_user_hw_breakpoint(e->bp, &attr);
    }
    mutex_unlock(&devwh_bp_mutex);
    return ret;
}

int devwh_hwbp_disable(pid_t pid, uintptr_t addr)
{
    struct devwh_bp *e;
    struct perf_event_attr attr;
    int ret = -ENOENT;

    mutex_lock(&devwh_bp_mutex);
    e = devwh_bp_find_locked(pid, addr);
    if (e && e->bp && kfn_modify_user_hw_breakpoint) {
        memcpy(&attr, &e->bp->attr, sizeof(attr));
        attr.disabled = 1;
        ret = kfn_modify_user_hw_breakpoint(e->bp, &attr);
    }
    mutex_unlock(&devwh_bp_mutex);
    return ret;
}

void devwh_hwbp_clear_all(void)
{
    struct devwh_bp *e, *tmp;

    mutex_lock(&devwh_bp_mutex);
    list_for_each_entry_safe(e, tmp, &devwh_bp_list, node) {
        if (e->bp && kfn_unregister_hw_breakpoint)
            kfn_unregister_hw_breakpoint(e->bp);
        list_del(&e->node);
        kfree(e);
    }
    mutex_unlock(&devwh_bp_mutex);
}

int devwh_hwbp_get_hits(struct devwh_hwbp_hit_args *args)
{
    struct devwh_bp *e;
    struct devwh_hwbp_hit_item *tmp;
    unsigned long flags;
    u32 want, have, copied;
    size_t bytes;
    int ret = 0;

    if (!args->out_buf || args->out_len <= 0)
        return -EINVAL;

    mutex_lock(&devwh_bp_mutex);
    e = devwh_bp_find_locked(args->pid, args->addr);
    if (!e) {
        mutex_unlock(&devwh_bp_mutex);
        return -ENOENT;
    }

    raw_spin_lock_irqsave(&e->ring_lock, flags);
    have = e->ring_count;
    want = (u32)args->out_len;
    if (want > have)
        want = have;
    raw_spin_unlock_irqrestore(&e->ring_lock, flags);

    if (!want) {
        args->real_count = 0;
        mutex_unlock(&devwh_bp_mutex);
        return 0;
    }

    bytes = (size_t)want * sizeof(struct devwh_hwbp_hit_item);
    tmp = kmalloc(bytes, GFP_KERNEL);
    if (!tmp) {
        mutex_unlock(&devwh_bp_mutex);
        return -ENOMEM;
    }

    raw_spin_lock_irqsave(&e->ring_lock, flags);
    for (copied = 0; copied < want; copied++) {
        tmp[copied] = e->ring[e->ring_tail];
        e->ring_tail = (e->ring_tail + 1) & (DEVWH_HITS_MAX - 1);
    }
    e->ring_count -= want;
    raw_spin_unlock_irqrestore(&e->ring_lock, flags);

    if (copy_to_user(args->out_buf, tmp, bytes))
        ret = -EFAULT;
    else
        args->real_count = (int)want;

    kfree(tmp);
    mutex_unlock(&devwh_bp_mutex);
    return ret;
}
