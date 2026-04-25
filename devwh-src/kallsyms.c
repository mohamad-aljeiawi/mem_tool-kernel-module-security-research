// SPDX-License-Identifier: GPL-2.0
/*
 * kallsyms.c -- resolve un-exported kernel symbols at module-init time.
 *
 * kallsyms_lookup_name() stopped being EXPORTed in 5.7.0 (commit 0bd476e6c671
 * "kallsyms: unexport kallsyms_lookup_name() and kallsyms_on_each_symbol()"),
 * so we steal its address via a temporary kprobe, which is the same trick
 * the observed binary uses. On kernels <5.7 this would also work but is
 * unnecessary; we keep the single code path to match the upstream build.
 *
 * After kfn_kallsyms is known, we pre-resolve a small set of VFS and
 * task-accounting symbols that callers hit on hot paths, to avoid paying
 * the lookup cost repeatedly.
 */

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/version.h>

#include "devwh.h"

/* Resolved function pointer for kallsyms_lookup_name. */
typedef unsigned long (*kallsyms_fn_t)(const char *name);
static kallsyms_fn_t kfn_kallsyms;

int   (*kfn_kern_path)(const char *, unsigned int, struct path *);
int   (*kfn_path_mount)(const char *, struct path *, const char *,
                        unsigned long, void *);
int   (*kfn_path_umount)(struct path *, int);
void  (*kfn_path_put)(const struct path *);
void *kfn_tasklist_lock;
void *kfn_init_task;

int devwh_kallsyms_init(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };
    int ret;

    ret = register_kprobe(&kp);
    if (ret < 0)
        return ret;

    kfn_kallsyms = (kallsyms_fn_t)kp.addr;
    unregister_kprobe(&kp);

    if (!kfn_kallsyms)
        return -ENOENT;

    /*
     * Pre-resolve VFS helpers. We tolerate individual misses here and
     * let the caller check the pointer -- the binary does the same and
     * refuses only the specific operation that needs a missing symbol.
     */
    kfn_kern_path     = devwh_ksym("kern_path");
    kfn_path_mount    = devwh_ksym("path_mount");
    kfn_path_umount   = devwh_ksym("path_umount");
    kfn_path_put      = devwh_ksym("path_put");
    kfn_tasklist_lock = devwh_ksym("tasklist_lock");
    kfn_init_task     = devwh_ksym("init_task");
    return 0;
}

void *devwh_ksym(const char *name)
{
    if (unlikely(!kfn_kallsyms))
        return NULL;
    return (void *)kfn_kallsyms(name);
}
