// SPDX-License-Identifier: GPL-2.0
/*
 * main.c -- module init / exit.
 *
 * Reconstruction of the observed 6.6.ko's driver_entry + driver_unload.
 *
 * Init sequence (matches binary exactly):
 *   1. Resolve kallsyms via kprobe.
 *   2. Generate a 6-char random device name.
 *   3. alloc_chrdev_region(devwh_devt, 0, 1, <rand>)
 *   4. cdev_init + cdev_add
 *   5. class_create(<rand>)                                -- 6.4+ shim
 *   6. device_create(class, NULL, devt, NULL, <rand>)
 *   7. hide_mount_tmpfs("/sys/class/<rand>")
 *   8. hide_mount_tmpfs("/sys/devices/virtual/<rand>")
 *   9. hide_module()                                       -- self-hide
 *  10. hide_mount_tmpfs("/data/local/tmp/")                -- drop zone
 *
 * Exit undoes the tmpfs overlays and rips the chrdev/class back out.
 * The module-hide cannot be fully undone (we've already removed ourselves
 * from module lists), but device-teardown still works because it only
 * touches our cdev + class which we kept pointers to.
 *
 * License: this is dual-licensed GPL/BSD -- the kernel insists on a GPL
 * declaration for GPL-EXPORT'd symbols we use (register_user_hw_breakpoint).
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>

#include "devwh.h"

char          devwh_devname[DEVWH_RAND_LEN + 1];
dev_t         devwh_devt;
struct cdev   devwh_cdev;
struct class *devwh_class;

bool devwh_class_hidden;
bool devwh_virtual_hidden;
bool devwh_tmp_hidden;

static struct device *devwh_device;

static int __init devwh_init(void)
{
    char hide_path[96];
    int ret;

    ret = devwh_kallsyms_init();
    if (ret) {
        pr_err("[devwh] kallsyms init failed: %d\n", ret);
        return ret;
    }

    devwh_rand_name(devwh_devname);
    pr_info("[devwh] chrdev name: %s\n", devwh_devname);

    ret = alloc_chrdev_region(&devwh_devt, 0, 1, devwh_devname);
    if (ret) {
        pr_err("[devwh] alloc_chrdev_region failed: %d\n", ret);
        return ret;
    }

    cdev_init(&devwh_cdev, &devwh_fops);
    devwh_cdev.owner = THIS_MODULE;
    ret = cdev_add(&devwh_cdev, devwh_devt, 1);
    if (ret) {
        unregister_chrdev_region(devwh_devt, 1);
        return ret;
    }

    devwh_class = devwh_class_create(devwh_devname);
    if (IS_ERR(devwh_class)) {
        ret = PTR_ERR(devwh_class);
        cdev_del(&devwh_cdev);
        unregister_chrdev_region(devwh_devt, 1);
        return ret;
    }

    devwh_device = device_create(devwh_class, NULL, devwh_devt,
                                 NULL, "%s", devwh_devname);
    if (IS_ERR(devwh_device)) {
        ret = PTR_ERR(devwh_device);
        class_destroy(devwh_class);
        cdev_del(&devwh_cdev);
        unregister_chrdev_region(devwh_devt, 1);
        return ret;
    }

    snprintf(hide_path, sizeof(hide_path), "/sys/class/%s", devwh_devname);
    devwh_class_hidden = devwh_hide_mount_tmpfs(hide_path);

    snprintf(hide_path, sizeof(hide_path),
             "/sys/devices/virtual/%s", devwh_devname);
    devwh_virtual_hidden = devwh_hide_mount_tmpfs(hide_path);

    devwh_hide_module();

    devwh_tmp_hidden = devwh_hide_mount_tmpfs("/data/local/tmp/");

    return 0;
}

static void __exit devwh_exit(void)
{
    char hide_path[96];

    devwh_hwbp_clear_all();

    if (devwh_tmp_hidden)
        devwh_umount_hidden("/data/local/tmp/");

    if (devwh_virtual_hidden) {
        snprintf(hide_path, sizeof(hide_path),
                 "/sys/devices/virtual/%s", devwh_devname);
        devwh_umount_hidden(hide_path);
    }
    if (devwh_class_hidden) {
        snprintf(hide_path, sizeof(hide_path), "/sys/class/%s", devwh_devname);
        devwh_umount_hidden(hide_path);
    }

    if (!IS_ERR_OR_NULL(devwh_class))
        device_destroy(devwh_class, devwh_devt);
    if (!IS_ERR_OR_NULL(devwh_class))
        class_destroy(devwh_class);
    cdev_del(&devwh_cdev);
    unregister_chrdev_region(devwh_devt, 1);

    devwh_memrw_release();
}

module_init(devwh_init);
module_exit(devwh_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("reconstructed from 6.6.ko");
MODULE_DESCRIPTION("audit/rebuild of a game-cheat kernel driver (devwh)");
MODULE_VERSION("0.1-audit");
