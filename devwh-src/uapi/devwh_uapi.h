/* SPDX-License-Identifier: GPL-2.0 */
/*
 * devwh_uapi.h -- ioctl interface between userland and the devwh kernel
 * module, reconstructed from the prebuilt mem_tool .ko binaries and
 * the userland header shipped with them (see mem_tool_driver/kernel_client.h).
 *
 * This file is the "contract" between kernel and user space. Values here
 * MUST match the prebuilt userland wrapper exactly, or the random-device
 * probe + ioctl dispatch in that wrapper will fail.
 */

#ifndef DEVWH_UAPI_H
#define DEVWH_UAPI_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/types.h>
#endif

#define DEVWH_MAX_MODIFY_REGS   10

/*
 * ioctl command numbers. NOTE: these are raw unsigned ints used directly
 * as the "cmd" arg to ioctl(); they intentionally do NOT follow the
 * _IOR/_IOW macro convention because the prebuilt userland does not either.
 */
enum devwh_ops {
    OP_INIT_KEY            = 0x800, /* reserved; see note in fops.c       */
    OP_READ_MEM            = 0x801, /* COPY_MEMORY -> pgd-walk read       */
    OP_WRITE_MEM           = 0x802, /* COPY_MEMORY -> pgd-walk write      */
    OP_MODULE_BASE         = 0x803, /* MODULE_BASE  -> vma base resolve   */
    OP_CMD_HWBP_ADD        = 0x804, /* HW_BP_INFO   -> install breakpoint */
    OP_CMD_HWBP_GET_HITS   = 0x805, /* HWBP_HIT_ARGS -> drain ring        */
    OP_CMD_HWBP_ENABLE     = 0x806, /* HW_BP_INFO   -> update + enable    */
    OP_CMD_HWBP_CLEAR      = 0x807, /* no-arg       -> clear all bps      */
    OP_CMD_HWBP_DISABLE    = 0x809, /* HW_BP_INFO   -> disable one bp     */
    OP_CMD_HIDE_PROCESS    = 0x810, /* arg = pid                          */
    OP_CMD_RECOVER_PROCESS = 0x811, /* arg = pid                          */
};

/* Breakpoint trigger type -- mirrors HW_BREAKPOINT_R/W/X. */
#define HW_BP_TYPE_R    1
#define HW_BP_TYPE_W    2
#define HW_BP_TYPE_RW   3
#define HW_BP_TYPE_X    4

struct devwh_copy_memory {
    pid_t      pid;
    uintptr_t  addr;
    void      *buffer;
    size_t     size;
};

struct devwh_module_base {
    pid_t      pid;
    char      *name;       /* userland pointer to NUL-terminated name */
    uintptr_t  base;       /* OUT */
    short      index;      /* reserved */
};

struct devwh_hw_bp_info {
    pid_t      pid;
    uintptr_t  addr;
    int        type;
    int        len;

    /*
     * On hit, overwrite these GP regs with these values before returning
     * to user space. Entry i takes regs[gp_reg_indices[i]] = gp_reg_values[i].
     */
    _Bool      is_write_gp_regs;
    int        gp_reg_count;
    int        gp_reg_indices[DEVWH_MAX_MODIFY_REGS];
    uint64_t   gp_reg_values[DEVWH_MAX_MODIFY_REGS];

    /* Same for FP regs (V0..V31), 128-bit wide. */
    _Bool      is_write_fp_regs;
    int        fp_reg_count;
    int        fp_reg_indices[DEVWH_MAX_MODIFY_REGS];
    uint64_t   fp_reg_values[DEVWH_MAX_MODIFY_REGS][2];
};

/* Captured register state per breakpoint hit. */
struct devwh_regs_info {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

struct devwh_hwbp_hit_item {
    pid_t                   task_id;
    uintptr_t               hit_addr;
    uint64_t                hit_time;
    struct devwh_regs_info  regs_info;
};

/* GET_HITS argument; user provides the ring-drain buffer. */
struct devwh_hwbp_hit_args {
    pid_t       pid;
    uintptr_t   addr;
    void       *out_buf;
    int         out_len;
    int         real_count; /* OUT */
};

#endif /* DEVWH_UAPI_H */
