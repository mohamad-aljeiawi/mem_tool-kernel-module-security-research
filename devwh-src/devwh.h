/* SPDX-License-Identifier: GPL-2.0 */
/*
 * devwh.h -- module-internal declarations.
 *
 * This file is in-tree only and must not be exposed to user space.
 */

#ifndef DEVWH_INTERNAL_H
#define DEVWH_INTERNAL_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/perf_event.h>

#include "uapi/devwh_uapi.h"

/* ----- build-time identity ----- */

#define DEVWH_MODNAME    "devwh"
#define DEVWH_RAND_LEN   6
#define DEVWH_HITS_MAX   16    /* per-bp hit ring size */

/* ----- global state, defined in main.c ----- */

extern char          devwh_devname[DEVWH_RAND_LEN + 1];
extern dev_t         devwh_devt;
extern struct cdev   devwh_cdev;
extern struct class *devwh_class;

extern bool          devwh_class_hidden;
extern bool          devwh_virtual_hidden;
extern bool          devwh_tmp_hidden;

/* ----- kallsyms.c ----- */

int  devwh_kallsyms_init(void);
void *devwh_ksym(const char *name);

/* Pre-resolved well-known symbols (used on hot paths). */
extern int   (*kfn_kern_path)(const char *, unsigned int, struct path *);
extern int   (*kfn_path_mount)(const char *, struct path *, const char *,
                               unsigned long, void *);
extern int   (*kfn_path_umount)(struct path *, int);
extern void  (*kfn_path_put)(const struct path *);
extern void *kfn_tasklist_lock;   /* rwlock_t *tasklist_lock         */
extern void *kfn_init_task;       /* struct task_struct *init_task   */

/* HW-breakpoint helpers, resolved lazily in hwbp.c. */
extern struct perf_event *(*kfn_register_user_hw_breakpoint)(
    struct perf_event_attr *, perf_overflow_handler_t, void *,
    struct task_struct *);
extern void (*kfn_unregister_hw_breakpoint)(struct perf_event *);
extern int  (*kfn_modify_user_hw_breakpoint)(struct perf_event *,
                                             struct perf_event_attr *);
extern void (*kfn_fpsimd_save)(void);          /* optional */
extern void (*kfn_fpsimd_flush_task_state)(struct task_struct *);

/* ----- rand.c ----- */

void devwh_rand_name(char out[DEVWH_RAND_LEN + 1]);

/* ----- hide.c ----- */

bool devwh_hide_mount_tmpfs(const char *path);
void devwh_umount_hidden(const char *path);
void devwh_hide_module(void);

int  devwh_process_visibility(pid_t pid, bool hide);

/* ----- memrw.c ----- */

bool devwh_read_process_memory(pid_t pid, uintptr_t addr,
                               void __user *user_buf, size_t size);
bool devwh_write_process_memory(pid_t pid, uintptr_t addr,
                                const void __user *user_buf, size_t size);
void devwh_memrw_release(void);

/* ----- hwbp.c ----- */

int  devwh_hwbp_install (struct devwh_hw_bp_info *info);
int  devwh_hwbp_enable  (struct devwh_hw_bp_info *info);
int  devwh_hwbp_disable (pid_t pid, uintptr_t addr);
void devwh_hwbp_clear_all(void);
int  devwh_hwbp_get_hits(struct devwh_hwbp_hit_args *args);

/* ----- fops.c ----- */

extern const struct file_operations devwh_fops;

/* ----- version-specific thin shims ----- */

static inline struct class *devwh_class_create(const char *name)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    return class_create(name);
#else
    return class_create(THIS_MODULE, name);
#endif
}

#endif /* DEVWH_INTERNAL_H */
