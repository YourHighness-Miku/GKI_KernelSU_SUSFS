// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/nezha_sysv_task.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/xarray.h>

static DEFINE_XARRAY_FLAGS(nezha_sysv_states, XA_FLAGS_LOCK_IRQ);

struct nezha_sysv_state *nezha_sysv_get(struct task_struct *task, bool alloc)
{
	unsigned long index = (unsigned long)task;
	struct nezha_sysv_state *state, *old;

	state = xa_load(&nezha_sysv_states, index);
	if (state || !alloc)
		return state;

	state = kzalloc(sizeof(*state), GFP_KERNEL_ACCOUNT);
	if (!state)
		return NULL;
	INIT_LIST_HEAD(&state->shm_clist);

	old = xa_cmpxchg_irq(&nezha_sysv_states, index, NULL, state,
			 GFP_KERNEL_ACCOUNT);
	if (xa_is_err(old)) {
		kfree(state);
		return NULL;
	}
	if (old) {
		kfree(state);
		return old;
	}
	return state;
}

struct sem_undo_list *nezha_sysv_undo(struct task_struct *task)
{
	struct nezha_sysv_state *state = nezha_sysv_get(task, false);

	return state ? READ_ONCE(state->undo_list) : NULL;
}

/* Only free_task may erase entries, after exit_sem/exit_shm and last task ref. */
void nezha_sysv_free(struct task_struct *task)
{
	struct nezha_sysv_state *state;
	unsigned long flags;

	xa_lock_irqsave(&nezha_sysv_states, flags);
	state = __xa_erase(&nezha_sysv_states, (unsigned long)task);
	xa_unlock_irqrestore(&nezha_sysv_states, flags);
	if (!state)
		return;
	WARN_ON_ONCE(state->undo_list || !list_empty(&state->shm_clist));
	kfree(state);
}
