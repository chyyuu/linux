/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

/*
 * Wed Apr 17 16:05:29 EDT 2002 (James Roth)
 *
 *  - Fixed an unlikely sys_thread_new() race condition.
 *
 *  - Made current_thread() work with threads which where
 *    not created with sys_thread_new().  This includes
 *    the main thread and threads made with pthread_create().
 *
 *  - Catch overflows where more than SYS_MBOX_SIZE messages
 *    are waiting to be read.  The sys_mbox_post() routine
 *    will block until there is more room instead of just
 *    leaking messages.
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <linux/semaphore.h>
#include <linux/slab.h>

#include <linux/lwip/lwip/sys.h>
#include <linux/lwip/lwip/opt.h>
#include <linux/lwip/lwip/stats.h>
#include <linux/lwip/arch/sys_arch.h>

// stupid classic producer-consumer
struct sys_mbox {
	sys_sem_t free, used, lock;
	int head, next;
	void *slots[SYS_MBOX_SIZE];
};


/*****************************************************************************
 * semaphores
 ****************************************************************************/
err_t
sys_sem_new(sys_sem_t *sem, u8_t count)
{
	*sem = kmalloc(sizeof(struct semaphore), GFP_KERNEL);
	if (*sem == NULL)
		return -ENOMEM;
	sema_init(*sem, count);
	return 0;
}


u32_t
sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout_ms)
{
	if (timeout_ms == 0) {
		down(*sem);
		return 0;
	} else {
		int t = down_timeout(*sem, msecs_to_jiffies(jiffies));
		if (t == -ETIME)
			return SYS_ARCH_TIMEOUT;
		return timeout_ms - 1; // stupid hack
	}
}


void
sys_sem_free(sys_sem_t *sem)
{
	kfree(*sem);
}


void
sys_sem_signal(sys_sem_t *sem)
{
	up(*sem);
}


/*****************************************************************************
 * mailboxes
 ****************************************************************************/
err_t
sys_mbox_new(sys_mbox_t *mb, int size)
{
	err_t err;
	if (size > SYS_MBOX_SIZE)
		return -ENOMEM;
	*mb = kmalloc(sizeof(struct sys_mbox), GFP_KERNEL);
	if (size == 0) size = SYS_MBOX_SIZE;
	err = sys_sem_new(&(*mb)->free, size);
	if (err < 0) return err;
	err = sys_sem_new(&(*mb)->used, 0);
	if (err < 0) return err;
	err = sys_sem_new(&(*mb)->lock, 1);
	if (err < 0) return err;
	(*mb)->head = 0;
	(*mb)->next = 0;
	return 0;
}


void
sys_mbox_free(sys_mbox_t *mb)
{
	sys_sem_free(&(*mb)->free);
	sys_sem_free(&(*mb)->used);
	sys_sem_free(&(*mb)->lock);
	kfree(*mb);
}


static void sys_mbox_dopost(sys_mbox_t mbox, void *msg)
{
	sys_arch_sem_wait(&(mbox->lock), 0);
	{
		int slot = mbox->next;
		mbox->next = (slot + 1) % SYS_MBOX_SIZE;
		mbox->slots[slot] = msg;
	}
	sys_sem_signal(&(mbox->lock));
	sys_sem_signal(&(mbox->used));
}


err_t
sys_mbox_trypost(sys_mbox_t *mb, void *msg)
{
	int ret = sys_arch_sem_wait(&(*mb)->free, 1);
	if (ret == SYS_ARCH_TIMEOUT)
		return (err_t) SYS_ARCH_TIMEOUT;
	sys_mbox_dopost(*mb, msg);
	return ERR_OK;
}


void
sys_mbox_post(sys_mbox_t *mb, void *msg)
{
	sys_arch_sem_wait(&(*mb)->free, 0);
	// can't have timeout because of wait(0)
	sys_mbox_dopost(*mb, msg);
}


static void sys_mbox_dofetch(sys_mbox_t mbox, void **msg)
{
	sys_arch_sem_wait(&mbox->lock, 0);
	{
		int slot = mbox->head;
		mbox->head = (slot + 1) % SYS_MBOX_SIZE;
		if (msg != NULL)
			*msg = mbox->slots[slot];
	}
	sys_sem_signal(&(mbox->lock));
	sys_sem_signal(&(mbox->free));
}


u32_t
sys_arch_mbox_tryfetch(sys_mbox_t *mb, void **msg)
{
	int ret = sys_arch_sem_wait(&(*mb)->used, 1);
	if (ret == SYS_ARCH_TIMEOUT)
		return SYS_MBOX_EMPTY;
	sys_mbox_dofetch(*mb, msg);
	return 0;
}


u32_t
sys_arch_mbox_fetch(sys_mbox_t *mb, void **msg, u32_t timeout)
{
	int ret = sys_arch_sem_wait(&(*mb)->used, timeout);
	if (ret == SYS_ARCH_TIMEOUT)
		return SYS_MBOX_EMPTY;
	sys_mbox_dofetch(*mb, msg);
	return 0;
}


/*****************************************************************************
 * others
 ****************************************************************************/
void
sys_init(void)
{
}

sys_thread_t
sys_thread_new(const char *name, lwip_thread_fn function, void *arg, int stacksize, int prio)
{
	struct task_struct* tsk;
	int pid = kernel_thread((int (*)(void*)) function, arg, 0);
	if (pid <= 0) {
		printk(KERN_ERR "lwip::sys_thread_new:kernel_thread %s failed\n", name);
		return pid;
	}
	tsk = find_task_by_vpid(pid);
	if (tsk == NULL) {
		printk(KERN_ERR "lwip::sys_thread_new:find_task_by_vpid %s failed\n", name);
		return -1;
	}
	set_task_comm(tsk, name);
	// ignore stack size and prio now
	return pid;
}


