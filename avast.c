// License: GPL v2
// Copyright :3 DeKrain 20XX, all rights reverberated

#include "linux/mm.h"
#include "linux/fs.h"
#include "linux/file.h"
#include "linux/pid.h"
#include "linux/random.h"
#include "linux/sched/signal.h"
#include "linux/signal.h"
#include "linux/sched.h"
#include "linux/sched/mm.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/init_task.h>

MODULE_DESCRIPTION("Very unsuspicious looking module");
MODULE_LICENSE("GPL");

static struct task_struct* find_anchor_process(void) {
	struct task_struct *init, *child;
	struct task_struct *anchor = NULL;
	struct pid *init_pid;
	struct cred const* creds;

	init_pid = find_pid_ns(1, &init_pid_ns);
	if (!init_pid || !(init = pid_task(init_pid, PIDTYPE_PID))) {
		pr_warn("Init does not exist\n");
		return NULL;
	}
	list_for_each_entry(child, &init->children, sibling) {
		//pr_info("Debug: process name=%s real uid=%u\n", child->comm, child->real_cred->uid.val);
		rcu_read_lock();
		creds = __task_cred(child);
		if (strcmp(child->comm, "systemd") == 0 && creds->uid.val != 0) {
			rcu_read_unlock();
			anchor = child;
			break;
		}
		rcu_read_unlock();
	}
	if (anchor) {
		list_for_each_entry(child, &anchor->children, sibling) {
			if (strcmp(child->comm, "plasmashell") == 0) {
				anchor = child;
				break;
			}
		}
	}
	return anchor;
}

struct call_context {
	struct task_struct *anchor;
	unsigned long pages;
	unsigned long num_pages;
	char **env;
};

static int call_init(struct subprocess_info* info, struct cred* new) {
	struct call_context *context = info->data;
	struct task_struct *anchor = context->anchor;
	struct cred const *old;
	struct file* dev_null;

	rcu_read_lock();
	old = __task_cred(anchor);
	new->uid = old->uid;
	new->gid = old->gid;
	new->suid = old->suid;
	new->sgid = old->sgid;
	new->euid = old->euid;
	new->egid = old->egid;
	new->fsuid = old->fsuid;
	new->fsgid = old->fsgid;
	new->user = /*get_user(*/old->user;
	new->user_ns = old->user_ns;
	rcu_read_unlock();
	dev_null = filp_open("/dev/null", O_RDWR, 0);
	if (dev_null) {
		fd_install(get_unused_fd_flags(0), get_file(dev_null));
		fd_install(get_unused_fd_flags(0), get_file(dev_null));
		fd_install(get_unused_fd_flags(0), dev_null);
	} else {
		pr_err("Error: failed to open /dev/null\n");
	}
	// Give time to inspect
	//msleep_interruptible(50000);
	pr_info("Env:");
	for (char **env = context->env; *env; ++env) {
		printk(" \"%s\"", *env);
	}
	printk("\n");
	return 0;
}

static void call_free(struct subprocess_info *info) {
	struct call_context *context = info->data;
	free_pages(context->pages, context->num_pages);
	kfree(context->env);
	kfree(context);
}

static struct pid* anchor_pid;

static struct task_struct* find_anchor(void)
{
	struct task_struct *anchor;

	if (anchor_pid) {
		anchor = pid_task(anchor_pid, PIDTYPE_PID);
		if (anchor)
			return anchor;
		put_pid(anchor_pid);
		anchor_pid = NULL;
	}

	anchor = find_anchor_process();
	if (anchor) {
		pr_info("Found anchor process: %d (%s)\n", anchor->pid, anchor->comm);
		anchor_pid = get_pid(task_pid(anchor));
		return anchor;
	} else {
		pr_err("Anchor process not found\n");
		return 0;
	}
}

static int spawn_process(struct task_struct* anchor)
{
	static char* firefox_args[] = {
		"firefox", "https://youtu.be/dQw4w9WgXcQ", NULL};

	struct subprocess_info* info;
	struct mm_struct *mm;
	struct call_context *ctx;
	char *pages;
	size_t num_pages, env_size;
	int err = 0;

	unsigned long num_envs, idx;
	bool non_empty;

	char* next_env;

	ctx = kzalloc(sizeof *ctx, GFP_KERNEL);
	if (!ctx) {
		return -ENOMEM;
	}

	mm = anchor->mm;
	if (!mm || !mm->env_end || !mm->env_start) {
		pr_info("Process doesn't have an environment\n");
		goto free_ctx;
	}
	if (!mmget_not_zero(mm)) {
		pr_info("Couldn't get mm\n");
		goto free_ctx;
	}

	num_pages = (mm->env_end - mm->env_start + PAGE_SIZE - 1) >> PAGE_SHIFT;
	pages = (char *)__get_free_pages(GFP_KERNEL, num_pages);
	if (!pages) {
		err = -ENOMEM;
		goto free_mm;
	}
	pr_info("Pages address: %016lx; num pages %lu\n", pages, num_pages);

	env_size = mm->env_end - mm->env_start;
	err = access_process_vm(anchor, mm->env_start, pages, env_size, FOLL_ANON);

	mmput(mm);
	if (err < 0) {
		pr_err("Failed to access pages: %d\n", err);
		free_pages((unsigned long)pages, num_pages);
		goto free_ctx;
	}

	ctx->anchor = anchor;
	ctx->pages = (unsigned long)pages;
	ctx->num_pages = num_pages;

	for (num_envs = 0, idx = 0; idx < env_size; ++idx) {
		if (pages[idx] == 0 && non_empty) {
			++num_envs;
			non_empty = false;
		} else if (pages[idx] != 0)
			non_empty = true;
	}

	pr_info("Num envs: %lu\n", num_envs);

	ctx->env = kcalloc(num_envs + 1, sizeof(char*), GFP_KERNEL);
	if (!ctx->env) {
		err = -ENOMEM;
		free_pages((unsigned long)pages, num_pages);
		goto free_ctx;
	}

	next_env = pages;
	non_empty = false;
	for (num_envs = 0, idx = 0; idx < env_size; ++idx) {
		if (pages[idx] == 0 && non_empty) {
			ctx->env[num_envs] = next_env;
			++num_envs;
			non_empty = false;
			next_env = pages + idx + 1;
		} else if (pages[idx] != 0) {
			non_empty = true;
		}
	}

	info = call_usermodehelper_setup("/usr/bin/firefox", firefox_args, ctx->env, GFP_KERNEL, 
		call_init, call_free, ctx);
	if (info == NULL) {
		pr_err("Usermodehelper failed\n");
	} else {
		pr_info("Call start\n");
		call_usermodehelper_exec(info, UMH_WAIT_EXEC);
	}
	return 0;

	free_mm:
	mmput(mm);

	free_ctx:
	kfree(ctx);
	return err;
}

static int my_thread(void*)
{
	struct task_struct* anchor;

	pr_info("Thread start\n");
	allow_signal(SIGCONT);

	do {
		/* Target range: [300..1200] s -> [300'000..1200'000] */
		/* Don't do this, kids */
		u32 timeout = get_random_u32() % 900000 + 300000;
		msleep_interruptible(timeout);
		while (signal_pending(current))
			kernel_dequeue_signal();
		if (kthread_should_stop())
			break;

		if (!(anchor = find_anchor()))
			return 0;
		spawn_process(anchor);
	} while (!kthread_should_stop());

	pr_info("Thread end\n");
	return 0;
}

static struct pid* main_task_pid;

int init_module(void)
{
	struct task_struct* task;
	pr_info("My module loaded\n");
	task = kthread_run(my_thread, NULL, "kavast");
	main_task_pid = get_pid(task_pid(task));
	return 0;
}

void cleanup_module(void)
{
	struct task_struct* task;
	task = pid_task(main_task_pid, PIDTYPE_PID);
	if (task) {
		send_sig(SIGCONT, task, false);
		kthread_stop(task);
	}
	put_pid(main_task_pid);
	put_pid(anchor_pid);
	pr_info("My module cleaned\n");
}
