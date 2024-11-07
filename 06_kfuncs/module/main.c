
// SPDX-License-Identifier: Apache-2.0

#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <net/sock.h>

MODULE_AUTHOR("Davide Collovigh");
MODULE_DESCRIPTION("ebpf_examples_kfunc: some description");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");

/* Disables missing prototype warnings */
__bpf_kfunc_start_defs();

__bpf_kfunc struct task_struct *bpf_find_get_task_by_vpid(pid_t nr)
{
    return find_get_task_by_vpid(nr);
}

__bpf_kfunc_end_defs();

static int __init ebpf_examples_kfunc_init(void)
{
    int err;
    err = 0;

    pr_info("Loaded module\n");

    return 0;
}

static void __exit ebpf_examples_kfunc_exit(void)
{
    pr_info("Unloaded module\n");
}

module_init(ebpf_examples_kfunc_init);
module_exit(ebpf_examples_kfunc_exit);
