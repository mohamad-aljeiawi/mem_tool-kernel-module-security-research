// SPDX-License-Identifier: GPL-2.0
/*
 * rand.c -- 6-character random device name generator.
 *
 * The userland probe (kernel_client.h :: driver_path) scans /dev for a
 * chardev whose name is exactly 6 characters from the [A-Za-z0-9] alphabet
 * with atime == ctime, size == 0, uid == gid == 0. This module generates
 * that name once at init and uses it as its cdev and sysfs class name.
 *
 * Bit-for-bit equivalent to the observed get_rand_str(): one call to
 * get_random_bytes() per character, modulo 62 into the 62-char alphabet.
 */

#include <linux/kernel.h>
#include <linux/random.h>

#include "devwh.h"

static const char devwh_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

void devwh_rand_name(char out[DEVWH_RAND_LEN + 1])
{
    unsigned int i;

    for (i = 0; i < DEVWH_RAND_LEN; i++) {
        int r;

        get_random_bytes(&r, sizeof(r));
        if (r < 0)
            r = -r;
        out[i] = devwh_alphabet[r % (sizeof(devwh_alphabet) - 1)];
    }
    out[DEVWH_RAND_LEN] = '\0';
}
