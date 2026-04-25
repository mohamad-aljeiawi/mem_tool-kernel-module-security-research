// SPDX-License-Identifier: GPL-2.0
/*
 * fops.c -- character device file_operations + ioctl dispatch.
 *
 * The ioctl cmd numbers are NOT _IO/_IOR/_IOW-encoded. They are raw
 * unsigned ints picked by the author to match the userland wrapper
 * exactly (see uapi/devwh_uapi.h). This file dispatches on those raw
 * numbers.
 *
 * Observed 6.6.ko quirk: OP_INIT_KEY (0x800) and the HWBP add/enable/
 * disable/get-hits ioctls are NOT wired into the dispatcher in that
 * specific build -- only HIDE/RECOVER, R/W, MODULE_BASE and HWBP_CLEAR
 * are. The implementations for all the HWBP ops DO exist as functions
 * in that binary, they just aren't reachable. This reconstruction
 * exposes the full interface, matching the header.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/fs_struct.h>
#include <linux/version.h>

#include "devwh.h"

/* ---- open / release ---------------------------------------------- */

static int devwh_open(struct inode *ino, struct file *f)
{
    return 0;
}

static int devwh_release(struct inode *ino, struct file *f)
{
    return 0;
}

/* ---- module-base resolution (OP_MODULE_BASE) --------------------- */

static long devwh_ioctl_module_base(void __user *uarg)
{
    struct devwh_module_base mb;
    struct task_struct *task;
    struct mm_struct   *mm;
    struct vm_area_struct *vma;
    struct pid *pid;
    char *wanted = NULL;        /* module name the user asked for    */
    char *scratch = NULL;       /* d_path scratch buffer             */
    size_t wanted_len;
    uintptr_t found = 0;
    int ret = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    VMA_ITERATOR(vmi, NULL, 0);
#endif

    if (copy_from_user(&mb, uarg, sizeof(mb)))
        return -EFAULT;
    if (!mb.name)
        return -EINVAL;

    wanted  = kzalloc(NAME_MAX + 1, GFP_KERNEL);
    scratch = kzalloc(PATH_MAX,     GFP_KERNEL);
    if (!wanted || !scratch) {
        ret = -ENOMEM;
        goto out;
    }
    if (strncpy_from_user(wanted, mb.name, NAME_MAX) <= 0) {
        ret = -EFAULT;
        goto out;
    }
    wanted_len = strnlen(wanted, NAME_MAX);

    pid  = find_get_pid(mb.pid);
    task = pid ? get_pid_task(pid, PIDTYPE_PID) : NULL;
    if (pid) put_pid(pid);
    if (!task) {
        ret = -ESRCH;
        goto out;
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        ret = -ESRCH;
        goto out;
    }

    mmap_read_lock(mm);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma) {
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        struct file *vf = vma->vm_file;
        const char *base;
        char *p;

        if (!vf)
            continue;

        p = d_path(&vf->f_path, scratch, PATH_MAX);
        if (IS_ERR(p))
            continue;
        base = strrchr(p, '/');
        base = base ? base + 1 : p;
        if (strncmp(base, wanted, wanted_len) == 0 &&
            (base[wanted_len] == '\0' || base[wanted_len] == '\n')) {
            found = (uintptr_t)vma->vm_start;
            break;
        }
    }
    mmap_read_unlock(mm);
    mmput(mm);

out:
    mb.base = found;
    kfree(wanted);
    kfree(scratch);

    if (ret)
        return ret;
    if (copy_to_user(uarg, &mb, sizeof(mb)))
        return -EFAULT;
    return found ? 0 : -ENOENT;
}

/* ---- ioctl dispatch --------------------------------------------- */

static long devwh_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    void __user *uarg = (void __user *)arg;

    switch (cmd) {
    case OP_INIT_KEY:
        /*
         * The observed binary declares this op but the handler body is
         * empty/absent. We keep a stub so userland's init phase does
         * not ENOTTY-out. Returning 0 mirrors "key accepted".
         */
        return 0;

    case OP_READ_MEM: {
        struct devwh_copy_memory cm;

        if (copy_from_user(&cm, uarg, sizeof(cm)))
            return -EFAULT;
        if (!devwh_read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -EFAULT;
        return 0;
    }

    case OP_WRITE_MEM: {
        struct devwh_copy_memory cm;

        if (copy_from_user(&cm, uarg, sizeof(cm)))
            return -EFAULT;
        if (!devwh_write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -EFAULT;
        return 0;
    }

    case OP_MODULE_BASE:
        return devwh_ioctl_module_base(uarg);

    case OP_CMD_HWBP_ADD: {
        struct devwh_hw_bp_info *bi;
        int ret;

        bi = kmalloc(sizeof(*bi), GFP_KERNEL);
        if (!bi)
            return -ENOMEM;
        if (copy_from_user(bi, uarg, sizeof(*bi))) {
            kfree(bi);
            return -EFAULT;
        }
        ret = devwh_hwbp_install(bi);
        kfree(bi);
        return ret;
    }

    case OP_CMD_HWBP_ENABLE: {
        struct devwh_hw_bp_info *bi;
        int ret;

        bi = kmalloc(sizeof(*bi), GFP_KERNEL);
        if (!bi)
            return -ENOMEM;
        if (copy_from_user(bi, uarg, sizeof(*bi))) {
            kfree(bi);
            return -EFAULT;
        }
        ret = devwh_hwbp_enable(bi);
        kfree(bi);
        return ret;
    }

    case OP_CMD_HWBP_DISABLE: {
        struct devwh_hw_bp_info bi;

        if (copy_from_user(&bi, uarg, sizeof(bi)))
            return -EFAULT;
        return devwh_hwbp_disable(bi.pid, bi.addr);
    }

    case OP_CMD_HWBP_CLEAR:
        devwh_hwbp_clear_all();
        return 0;

    case OP_CMD_HWBP_GET_HITS: {
        struct devwh_hwbp_hit_args ha;
        int ret;

        if (copy_from_user(&ha, uarg, sizeof(ha)))
            return -EFAULT;
        ret = devwh_hwbp_get_hits(&ha);
        if (!ret && copy_to_user(uarg, &ha, sizeof(ha)))
            return -EFAULT;
        return ret;
    }

    case OP_CMD_HIDE_PROCESS:
        return devwh_process_visibility((pid_t)arg, true);

    case OP_CMD_RECOVER_PROCESS:
        return devwh_process_visibility((pid_t)arg, false);

    default:
        return -ENOTTY;
    }
}

const struct file_operations devwh_fops = {
    .owner          = THIS_MODULE,
    .open           = devwh_open,
    .release        = devwh_release,
    .unlocked_ioctl = devwh_ioctl,
    .compat_ioctl   = devwh_ioctl,
};
