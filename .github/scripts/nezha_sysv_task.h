/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NEZHA_SYSV_TASK_H
#define _LINUX_NEZHA_SYSV_TASK_H

#include <linux/list.h>
#include <linux/types.h>

struct task_struct;
struct sem_undo_list;

struct nezha_sysv_state {
	struct sem_undo_list *undo_list;
	struct list_head shm_clist;
};

#ifdef CONFIG_SYSVIPC
/* Caller must pin task's lifetime; allocation is only from sleepable context. */
struct nezha_sysv_state *nezha_sysv_get(struct task_struct *task, bool alloc);
void nezha_sysv_free(struct task_struct *task);
struct sem_undo_list *nezha_sysv_undo(struct task_struct *task);
#ifdef CONFIG_NEZHA_SYSV_STATE_KUNIT_TEST
long nezha_sysv_test_remove_shm(int shmid);
#endif
#else
static inline void nezha_sysv_free(struct task_struct *task) { }
#endif
#endif
