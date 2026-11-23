// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/nezha_sysv_task.h>
#include <linux/sched/task.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/syscalls.h>

struct state_test_worker {
	struct completion *start;
	struct completion done;
	struct task_struct *target;
	struct nezha_sysv_state *result;
};

static int race_worker(void *arg)
{
	struct state_test_worker *worker = arg;

	wait_for_completion(worker->start);
	worker->result = nezha_sysv_get(worker->target, true);
	complete(&worker->done);
	return 0;
}

static void state_race_test(struct kunit *test)
{
	DECLARE_COMPLETION_ONSTACK(start);
	struct state_test_worker workers[8] = {};
	struct task_struct *threads[8];
	struct nezha_sysv_state *state;
	int i, count = 0;

	KUNIT_ASSERT_PTR_EQ(test, nezha_sysv_get(current, false), NULL);
	for (i = 0; i < ARRAY_SIZE(workers); i++) {
		workers[i].start = &start;
		workers[i].target = current;
		init_completion(&workers[i].done);
		threads[i] = kthread_create(race_worker, &workers[i], "sysv-race-%d", i);
		if (IS_ERR(threads[i]))
			break;
		get_task_struct(threads[i]);
		count++;
		wake_up_process(threads[i]);
	}
	complete_all(&start);
	for (i = 0; i < count; i++) {
		wait_for_completion(&workers[i].done);
		put_task_struct(threads[i]);
	}
	state = nezha_sysv_get(current, false);
	KUNIT_EXPECT_EQ(test, count, (int)ARRAY_SIZE(workers));
	KUNIT_ASSERT_NOT_NULL(test, state);
	for (i = 0; i < count; i++)
		KUNIT_EXPECT_PTR_EQ(test, workers[i].result, state);
	KUNIT_EXPECT_TRUE(test, list_empty(&state->shm_clist));
	KUNIT_EXPECT_PTR_EQ(test, state->undo_list, NULL);
	nezha_sysv_free(current);
	KUNIT_EXPECT_PTR_EQ(test, nezha_sysv_get(current, false), NULL);
	state = nezha_sysv_get(current, true);
	KUNIT_ASSERT_NOT_NULL(test, state);
	KUNIT_EXPECT_TRUE(test, list_empty(&state->shm_clist));
	KUNIT_EXPECT_PTR_EQ(test, state->undo_list, NULL);
	nezha_sysv_free(current);
}

static void semundo_share_test(struct kunit *test)
{
	DECLARE_COMPLETION_ONSTACK(start);
	struct state_test_worker worker = { .start = &start };
	struct task_struct *child;
	struct sem_undo_list *shared;
	int result;

	worker.target = current;
	init_completion(&worker.done);
	child = kthread_create(race_worker, &worker, "sysv-share");
	KUNIT_ASSERT_FALSE(test, IS_ERR(child));
	get_task_struct(child);
	result = copy_semundo(CLONE_SYSVSEM, child);
	KUNIT_EXPECT_EQ(test, result, 0);
	shared = nezha_sysv_undo(current);
	KUNIT_EXPECT_NOT_NULL(test, shared);
	KUNIT_EXPECT_PTR_EQ(test, nezha_sysv_undo(child), shared);
	exit_sem(child);
	KUNIT_EXPECT_PTR_EQ(test, nezha_sysv_undo(child), NULL);
	KUNIT_EXPECT_PTR_EQ(test, nezha_sysv_undo(current), shared);
	complete_all(&start);
	wake_up_process(child);
	wait_for_completion(&worker.done);
	put_task_struct(child);
	exit_sem(current);
	KUNIT_EXPECT_PTR_EQ(test, nezha_sysv_undo(current), NULL);
	nezha_sysv_free(current);
}

static void shm_lifecycle_test(struct kunit *test)
{
	struct nezha_sysv_state *state;
	long shmid = ksys_shmget(IPC_PRIVATE, PAGE_SIZE, IPC_CREAT | 0600);

	KUNIT_ASSERT_GE(test, shmid, 0L);
	state = nezha_sysv_get(current, false);
	KUNIT_EXPECT_NOT_NULL(test, state);
	if (state) {
		KUNIT_EXPECT_FALSE(test, list_empty(&state->shm_clist));
		shm_init_task(current);
		KUNIT_EXPECT_FALSE(test, list_empty(&state->shm_clist));
		exit_shm(current);
		KUNIT_EXPECT_TRUE(test, list_empty(&state->shm_clist));
	}
	KUNIT_EXPECT_EQ(test, nezha_sysv_test_remove_shm(shmid), 0L);
	nezha_sysv_free(current);
}

static int idle_child(void *unused)
{
        return 0;
}

static void semundo_alloc_failure_test(struct kunit *test)
{
        struct task_struct *child;
        int err, phase;

        KUNIT_ASSERT_PTR_EQ(test, nezha_sysv_get(current, false), NULL);
        child = kthread_create(idle_child, NULL, "sysv-fault");
        KUNIT_ASSERT_FALSE(test, IS_ERR(child));
        for (phase = 0; phase < 3; phase++) {
                /* Fail child state, then parent state, then the undo-list allocation. */
                WRITE_ONCE(current->fail_nth, 1);
                err = copy_semundo(CLONE_SYSVSEM, child);
                WRITE_ONCE(current->fail_nth, 0);
                KUNIT_EXPECT_EQ(test, err, -ENOMEM);
                KUNIT_EXPECT_PTR_EQ(test, nezha_sysv_undo(child), NULL);
                KUNIT_EXPECT_PTR_EQ(test, nezha_sysv_undo(current), NULL);
                if (err != -ENOMEM || phase == 2)
                        break;
                if (!nezha_sysv_get(phase ? current : child, true)) {
                        KUNIT_FAIL(test, "preallocation failed");
                        break;
                }
        }
        exit_sem(child);
        kthread_stop(child);
        exit_sem(current);
}

static struct kunit_case state_cases[] = {
	KUNIT_CASE(state_race_test),
	KUNIT_CASE(semundo_share_test),
	KUNIT_CASE(shm_lifecycle_test),
	KUNIT_CASE(semundo_alloc_failure_test),
	{}
};

static struct kunit_suite state_suite = {
	.name = "nezha-sysv-state",
	.test_cases = state_cases,
};
kunit_test_suite(state_suite);
MODULE_LICENSE("GPL");
