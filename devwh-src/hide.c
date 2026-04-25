// SPDX-License-Identifier: GPL-2.0
/*
 * hide.c -- anti-cheat evasion primitives.
 *
 *  1. devwh_hide_mount_tmpfs(path): overlays an empty tmpfs on `path` so
 *     anything underneath is hidden from userland scanners until reboot
 *     or devwh_umount_hidden() runs.
 *  2. devwh_hide_module(): unlinks __this_module from (a) vmap_area_list
 *     / vmap_area_root, (b) the global module list, (c) the module kobj
 *     sysfs tree, and (d) its modinfo_attrs, making the module invisible
 *     to lsmod, /proc/modules, /sys/module/, and /proc/vmallocinfo.
 *  3. devwh_process_visibility(pid, hide): hides a live process by
 *     detaching it from init_task.tasks, and by tmpfs-overlaying its
 *     /proc/<pid>, /sys/fs/cgroup/uid_0/pid_<pid>, and the Adreno
 *     /sys/devices/virtual/kgsl/kgsl/proc/<pid> entries (recovered later
 *     via the symmetric recover path).
 *
 * This is a faithful reconstruction of the 6.6.ko behavior. Note that
 * the module-hide primitive depends on internal layout of struct module
 * (modinfo_attrs, mkobj.kobj, list) which has been stable but must be
 * re-verified if you retarget to a distro kernel with unusual patches.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/printk.h>

#include "devwh.h"

/* ---- filesystem-level hiding --------------------------------------- */

bool devwh_hide_mount_tmpfs(const char *target_path)
{
    struct path path = { 0 };
    void *data_page;
    int err;

    if (!kfn_kern_path || !kfn_path_mount || !kfn_path_put)
        return false;

    if (kfn_kern_path(target_path, LOOKUP_FOLLOW, &path) != 0)
        return false;

    data_page = (void *)__get_free_pages(GFP_KERNEL, 0);
    if (!data_page) {
        kfn_path_put(&path);
        return false;
    }
    memset(data_page, 0, PAGE_SIZE);

    /* MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_SILENT -- matches binary (0x800E). */
    err = kfn_path_mount("tmpfs", &path, "tmpfs",
                         MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_SILENT,
                         data_page);

    free_pages((unsigned long)data_page, 0);
    kfn_path_put(&path);
    return err == 0;
}

void devwh_umount_hidden(const char *target_path)
{
    struct path path = { 0 };

    if (!kfn_kern_path || !kfn_path_umount || !kfn_path_put)
        return;

    if (kfn_kern_path(target_path, LOOKUP_FOLLOW, &path) != 0)
        return;

    kfn_path_umount(&path, MNT_FORCE | MNT_DETACH);
    kfn_path_put(&path);
}

/* ---- module-level hiding ------------------------------------------- */

struct vmap_area_walker {
    struct list_head list;
    unsigned long va_start;
    unsigned long va_end;
};

void devwh_hide_module(void)
{
    struct list_head   *vmap_list;
    struct rb_root     *vmap_root;
    struct list_head   *pos, *n;
    unsigned long mod_start = (unsigned long)THIS_MODULE;

    /* 1. Remove this_module's vmap area from vmap_area_list + rbtree. */
    vmap_list = devwh_ksym("vmap_area_list");
    vmap_root = devwh_ksym("vmap_area_root");
    if (vmap_list && vmap_root) {
        list_for_each_safe(pos, n, vmap_list) {
            /*
             * struct vmap_area layout (relevant fields):
             *   unsigned long va_start;    // -5 qwords from list_head
             *   unsigned long va_end;      // -4 qwords from list_head
             *   ...
             *   struct rb_node rb_node;    // -3 qwords
             *   struct list_head list;
             * -- exactly matches the disassembled offsets.
             */
            unsigned long va_start = *((unsigned long *)pos - 5);
            unsigned long va_end   = *((unsigned long *)pos - 4);
            struct rb_node *rb = (struct rb_node *)((char *)pos - 3 * sizeof(void *));

            if (va_start < mod_start && va_end > mod_start) {
                list_del(pos);
                rb_erase(rb, vmap_root);
                /* Same poison the observed binary writes. */
                pos->next = (struct list_head *)0xDEAD000000000100UL;
                pos->prev = (struct list_head *)0xDEAD000000000122UL;
            }
        }
    }

    /* 2. Unlink __this_module from the global module list. */
    if (THIS_MODULE->list.next && THIS_MODULE->list.prev) {
        list_del(&THIS_MODULE->list);
        INIT_LIST_HEAD(&THIS_MODULE->list);
    }

    /* 3. Remove the /sys/module/<name> kobject if it's live. */
    if (THIS_MODULE->mkobj.kobj.state_in_sysfs)
        kobject_del(&THIS_MODULE->mkobj.kobj);

    /*
     * 4. Walk THIS_MODULE->modinfo_attrs (struct module_attribute[]), detach
     *    each sysfs attr, free it. The observed binary re-derives the list
     *    by walking *(mod+qword_9E28) == &mod->modinfo_attrs -- the
     *    reconstruction uses the declared accessor for clarity.
     */
    if (THIS_MODULE->modinfo_attrs) {
        struct module_attribute *attrs = THIS_MODULE->modinfo_attrs;
        int i;

        /* modinfo_attrs is NULL-terminated by .attr.name == NULL */
        for (i = 0; attrs[i].attr.name; i++) {
            /* Best-effort -- the real object is freed by the module core
             * on unload regardless. We only remove its sysfs dirent so
             * it disappears immediately. */
            if (THIS_MODULE->mkobj.kobj.sd)
                sysfs_remove_link(&THIS_MODULE->mkobj.kobj, attrs[i].attr.name);
        }
    }

    pr_info("[hook] Module hidden successfully.\n");
}

/* ---- per-process hiding -------------------------------------------- */

struct devwh_hidden_proc {
    struct list_head    node;
    pid_t               target_pid;
    struct task_struct *task;
    bool                from_tasklist;
    bool                proc_hidden;
    bool                cgroup_hidden;
    bool                kgsl_hidden;
};

static LIST_HEAD(devwh_hidden_list);
static DEFINE_RAW_SPINLOCK(devwh_hidden_lock);

/*
 * We set an otherwise-unused PF_ flag in task->flags as a "this task is
 * currently hidden by us" marker, so we can bail out of double-hide. The
 * observed binary uses the same 0x10000000 bit; this collides with
 * PF_NO_SETAFFINITY on some kernels but the author does not care.
 */
#define DEVWH_PF_HIDDEN  0x10000000U

int devwh_process_visibility(pid_t target_pid, bool hide)
{
    struct pid          *pid;
    struct task_struct  *task;
    struct devwh_hidden_proc *entry, *tmp;
    char buf[64];

    if (!kfn_kern_path || !kfn_path_mount || !kfn_path_umount || !kfn_path_put)
        return -EINVAL;

    if (hide) {
        pid = find_get_pid(target_pid);
        if (!pid)
            return -ESRCH;
        task = get_pid_task(pid, PIDTYPE_PID);
        put_pid(pid);
        if (!task)
            return -ESRCH;

        entry = kmalloc(sizeof(*entry), GFP_KERNEL);
        if (!entry) {
            put_task_struct(task);
            return -ENOMEM;
        }
        memset(entry, 0, sizeof(*entry));
        entry->target_pid = target_pid;
        entry->task       = task;

        /* Mark and unlink from init_task.tasks, protected by tasklist_lock. */
        task->flags |= DEVWH_PF_HIDDEN;
        if (kfn_tasklist_lock && kfn_init_task) {
            rwlock_t *tasklist_lock = kfn_tasklist_lock;

            write_lock_irq(tasklist_lock);
            list_del_init(&task->tasks);
            write_unlock_irq(tasklist_lock);
            entry->from_tasklist = true;
        }

        snprintf(buf, sizeof(buf), "/proc/%d", target_pid);
        entry->proc_hidden = devwh_hide_mount_tmpfs(buf);

        snprintf(buf, sizeof(buf), "/sys/fs/cgroup/uid_0/pid_%d", target_pid);
        entry->cgroup_hidden = devwh_hide_mount_tmpfs(buf);

        snprintf(buf, sizeof(buf), "/sys/devices/virtual/kgsl/kgsl/proc/%d",
                 target_pid);
        entry->kgsl_hidden = devwh_hide_mount_tmpfs(buf);

        raw_spin_lock(&devwh_hidden_lock);
        list_add_tail(&entry->node, &devwh_hidden_list);
        raw_spin_unlock(&devwh_hidden_lock);

        pr_info("[db] Hide Process: %d\n", target_pid);
        return 0;
    }

    /* hide == false: find and undo. */
    raw_spin_lock(&devwh_hidden_lock);
    list_for_each_entry_safe(entry, tmp, &devwh_hidden_list, node) {
        if (entry->target_pid != target_pid)
            continue;
        list_del_init(&entry->node);
        raw_spin_unlock(&devwh_hidden_lock);

        entry->task->flags &= ~DEVWH_PF_HIDDEN;

        if (entry->from_tasklist && kfn_tasklist_lock && kfn_init_task) {
            rwlock_t *tasklist_lock = kfn_tasklist_lock;
            struct task_struct *init = kfn_init_task;

            write_lock_irq(tasklist_lock);
            list_add_tail(&entry->task->tasks, &init->tasks);
            write_unlock_irq(tasklist_lock);
        }

        if (entry->proc_hidden) {
            snprintf(buf, sizeof(buf), "/proc/%d", target_pid);
            devwh_umount_hidden(buf);
        }
        if (entry->cgroup_hidden) {
            snprintf(buf, sizeof(buf), "/sys/fs/cgroup/uid_0/pid_%d",
                     target_pid);
            devwh_umount_hidden(buf);
        }
        if (entry->kgsl_hidden) {
            snprintf(buf, sizeof(buf),
                     "/sys/devices/virtual/kgsl/kgsl/proc/%d", target_pid);
            devwh_umount_hidden(buf);
        }

        put_task_struct(entry->task);
        kfree(entry);
        pr_info("[db] Recover Process: %d\n", target_pid);
        return 0;
    }
    raw_spin_unlock(&devwh_hidden_lock);
    return -ENOENT;
}
