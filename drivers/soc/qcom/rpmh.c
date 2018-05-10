// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 */

#include <linux/atomic.h>
#include <linux/interrupt.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mailbox_client.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

#include <soc/qcom/rpmh.h>

#include "rpmh-internal.h"

#define RPMH_MAX_MBOXES			2
#define RPMH_TIMEOUT_MS			10000
#define RPMH_MAX_REQ_IN_BATCH		10

#define DEFINE_RPMH_MSG_ONSTACK(rc, s, q, name)		\
	struct rpmh_request name = {			\
		.msg = {				\
			.state = s,			\
			.cmds = name.cmd,		\
			.num_cmds = 0,			\
			.wait_for_compl = true,		\
		},					\
		.cmd = { { 0 } },			\
		.completion = q,			\
		.rc = rc,				\
		.free = NULL,				\
		.wait_count = NULL,			\
	}

/**
 * struct cache_req: the request object for caching
 *
 * @addr: the address of the resource
 * @sleep_val: the sleep vote
 * @wake_val: the wake vote
 * @list: linked list obj
 */
struct cache_req {
	u32 addr;
	u32 sleep_val;
	u32 wake_val;
	struct list_head list;
};

/**
 * struct rpmh_request: the message to be sent to rpmh-rsc
 *
 * @msg: the request
 * @cmd: the payload that will be part of the @msg
 * @completion: triggered when request is done
 * @err: err return from the controller
 * @free: the request object to be freed at tx_done
 * @wait_count: count of waiters for this completion
 */
struct rpmh_request {
	struct tcs_request msg;
	struct tcs_cmd cmd[MAX_RPMH_PAYLOAD];
	struct completion *completion;
	struct rpmh_client *rc;
	int err;
	struct rpmh_request *free;
	atomic_t *wait_count;
};

/**
 * struct rpmh_ctrlr: our representation of the controller
 *
 * @drv: the controller instance
 * @cache: the list of cached requests
 * @lock: synchronize access to the controller data
 * @dirty: was the cache updated since flush
 * @batch_cache: Cache sleep and wake requests sent as batch
 */
struct rpmh_ctrlr {
	struct rsc_drv *drv;
	struct list_head cache;
	spinlock_t lock;
	bool dirty;
	const struct rpmh_request *batch_cache[2 * RPMH_MAX_REQ_IN_BATCH];
};

/**
 * struct rpmh_client: the client object
 *
 * @dev: the platform device that is the owner
 * @ctrlr: the controller associated with this client.
 */
struct rpmh_client {
	struct device *dev;
	struct rpmh_ctrlr *ctrlr;
};

static struct rpmh_ctrlr rpmh_rsc[RPMH_MAX_MBOXES];
static DEFINE_MUTEX(rpmh_ctrlr_mutex);

void rpmh_tx_done(const struct tcs_request *msg, int r)
{
	struct rpmh_request *rpm_msg = container_of(msg, struct rpmh_request,
						    msg);
	struct completion *compl = rpm_msg->completion;
	atomic_t *wc = rpm_msg->wait_count;

	rpm_msg->err = r;

	if (r)
		dev_err(rpm_msg->rc->dev,
			"RPMH TX fail in msg addr=%#x, err=%d\n",
			rpm_msg->msg.cmds[0].addr, r);

	kfree(rpm_msg->free);

	/* Signal the blocking thread we are done */
	if (!compl)
		return;

	if (wc && !atomic_dec_and_test(wc))
		return;

	complete(compl);
}
EXPORT_SYMBOL(rpmh_tx_done);

/**
 * wait_for_tx_done: Wait until the response is received.
 *
 * @rc: The RPMH client
 * @compl: The completion object
 * @addr: An addr that we sent in that request
 * @data: The data for the address in that request
 */
static int wait_for_tx_done(struct rpmh_client *rc,
			    struct completion *compl, u32 addr, u32 data)
{
	int ret;

	might_sleep();

	ret = wait_for_completion_timeout(compl,
					  msecs_to_jiffies(RPMH_TIMEOUT_MS));
	if (ret)
		dev_dbg(rc->dev,
			"RPMH response received addr=%#x data=%#x\n",
			addr, data);
	else
		dev_err(rc->dev,
			"RPMH response timeout addr=%#x data=%#x\n",
			addr, data);

	return (ret > 0) ? 0 : -ETIMEDOUT;
}

static struct cache_req *__find_req(struct rpmh_client *rc, u32 addr)
{
	struct cache_req *p, *req = NULL;

	list_for_each_entry(p, &rc->ctrlr->cache, list) {
		if (p->addr == addr) {
			req = p;
			break;
		}
	}

	return req;
}

static struct cache_req *cache_rpm_request(struct rpmh_client *rc,
					   enum rpmh_state state,
					   struct tcs_cmd *cmd)
{
	struct cache_req *req;
	struct rpmh_ctrlr *rpm = rc->ctrlr;
	unsigned long flags;

	spin_lock_irqsave(&rpm->lock, flags);
	req = __find_req(rc, cmd->addr);
	if (req)
		goto existing;

	req = kzalloc(sizeof(*req), GFP_ATOMIC);
	if (!req) {
		req = ERR_PTR(-ENOMEM);
		goto unlock;
	}

	req->addr = cmd->addr;
	req->sleep_val = req->wake_val = UINT_MAX;
	INIT_LIST_HEAD(&req->list);
	list_add_tail(&req->list, &rpm->cache);

existing:
	switch (state) {
	case RPMH_ACTIVE_ONLY_STATE:
		if (req->sleep_val != UINT_MAX)
			req->wake_val = cmd->data;
		break;
	case RPMH_WAKE_ONLY_STATE:
		req->wake_val = cmd->data;
		break;
	case RPMH_SLEEP_STATE:
		req->sleep_val = cmd->data;
		break;
	default:
		break;
	};

	rpm->dirty = true;
unlock:
	spin_unlock_irqrestore(&rpm->lock, flags);

	return req;
}

/**
 * __rpmh_write: Cache and send the RPMH request
 *
 * @rc: The RPMH client
 * @state: Active/Sleep request type
 * @rpm_msg: The data that needs to be sent (cmds).
 *
 * Cache the RPMH request and send if the state is ACTIVE_ONLY.
 * SLEEP/WAKE_ONLY requests are not sent to the controller at
 * this time. Use rpmh_flush() to send them to the controller.
 */
static int __rpmh_write(struct rpmh_client *rc, enum rpmh_state state,
			struct rpmh_request *rpm_msg)
{
	int ret = -EINVAL;
	struct cache_req *req;
	int i;

	/* Cache the request in our store and link the payload */
	for (i = 0; i < rpm_msg->msg.num_cmds; i++) {
		req = cache_rpm_request(rc, state, &rpm_msg->msg.cmds[i]);
		if (IS_ERR(req))
			return PTR_ERR(req);
	}

	rpm_msg->msg.state = state;

	if (state == RPMH_ACTIVE_ONLY_STATE) {
		WARN_ON(irqs_disabled());
		ret = rpmh_rsc_send_data(rc->ctrlr->drv, &rpm_msg->msg);
		if (!ret)
			dev_dbg(rc->dev,
				"RPMH request sent addr=%#x, data=%i#x\n",
				rpm_msg->msg.cmds[0].addr,
				rpm_msg->msg.cmds[0].data);
		else
			dev_warn(rc->dev,
				 "Error in RPMH request addr=%#x, data=%#x\n",
				 rpm_msg->msg.cmds[0].addr,
				 rpm_msg->msg.cmds[0].data);
	} else {
		ret = rpmh_rsc_write_ctrl_data(rc->ctrlr->drv, &rpm_msg->msg);
		/* Clean up our call by spoofing tx_done */
		rpmh_tx_done(&rpm_msg->msg, ret);
	}

	return ret;
}

static struct rpmh_request *__get_rpmh_msg_async(struct rpmh_client *rc,
						 enum rpmh_state state,
						 const struct tcs_cmd *cmd,
						 u32 n)
{
	struct rpmh_request *req;

	if (IS_ERR_OR_NULL(rc) || !cmd || !n || n > MAX_RPMH_PAYLOAD)
		return ERR_PTR(-EINVAL);

	req = kzalloc(sizeof(*req), GFP_ATOMIC);
	if (!req)
		return ERR_PTR(-ENOMEM);

	memcpy(req->cmd, cmd, n * sizeof(*cmd));

	req->msg.state = state;
	req->msg.cmds = req->cmd;
	req->msg.num_cmds = n;
	req->free = req;

	return req;
}

/**
 * rpmh_write_async: Write a set of RPMH commands
 *
 * @rc: The RPMh handle got from rpmh_get_client
 * @state: Active/sleep set
 * @cmd: The payload data
 * @n: The number of elements in payload
 *
 * Write a set of RPMH commands, the order of commands is maintained
 * and will be sent as a single shot.
 */
int rpmh_write_async(struct rpmh_client *rc, enum rpmh_state state,
		     const struct tcs_cmd *cmd, u32 n)
{
	struct rpmh_request *rpm_msg;

	rpm_msg = __get_rpmh_msg_async(rc, state, cmd, n);
	if (IS_ERR(rpm_msg))
		return PTR_ERR(rpm_msg);

	return __rpmh_write(rc, state, rpm_msg);
}
EXPORT_SYMBOL(rpmh_write_async);

/**
 * rpmh_write: Write a set of RPMH commands and block until response
 *
 * @rc: The RPMh handle got from rpmh_get_client
 * @state: Active/sleep set
 * @cmd: The payload data
 * @n: The number of elements in @cmd
 *
 * May sleep. Do not call from atomic contexts.
 */
int rpmh_write(struct rpmh_client *rc, enum rpmh_state state,
	       const struct tcs_cmd *cmd, u32 n)
{
	DECLARE_COMPLETION_ONSTACK(compl);
	DEFINE_RPMH_MSG_ONSTACK(rc, state, &compl, rpm_msg);
	int ret;

	if (IS_ERR_OR_NULL(rc) || !cmd || !n || n > MAX_RPMH_PAYLOAD)
		return -EINVAL;

	memcpy(rpm_msg.cmd, cmd, n * sizeof(*cmd));
	rpm_msg.msg.num_cmds = n;

	ret = __rpmh_write(rc, state, &rpm_msg);
	if (ret)
		return ret;

	return wait_for_tx_done(rc, &compl, cmd[0].addr, cmd[0].data);
}
EXPORT_SYMBOL(rpmh_write);

static int cache_batch(struct rpmh_client *rc,
		       struct rpmh_request **rpm_msg, int count)
{
	struct rpmh_ctrlr *rpm = rc->ctrlr;
	unsigned long flags;
	int ret = 0;
	int index = 0;
	int i;

	spin_lock_irqsave(&rpm->lock, flags);
	while (rpm->batch_cache[index])
		index++;
	if (index + count >=  2 * RPMH_MAX_REQ_IN_BATCH) {
		ret = -ENOMEM;
		goto fail;
	}

	for (i = 0; i < count; i++)
		rpm->batch_cache[index + i] = rpm_msg[i];
fail:
	spin_unlock_irqrestore(&rpm->lock, flags);

	return ret;
}

static int flush_batch(struct rpmh_client *rc)
{
	struct rpmh_ctrlr *rpm = rc->ctrlr;
	const struct rpmh_request *rpm_msg;
	unsigned long flags;
	int ret = 0;
	int i;

	/* Send Sleep/Wake requests to the controller, expect no response */
	spin_lock_irqsave(&rpm->lock, flags);
	for (i = 0; rpm->batch_cache[i]; i++) {
		rpm_msg = rpm->batch_cache[i];
		ret = rpmh_rsc_write_ctrl_data(rc->ctrlr->drv, &rpm_msg->msg);
		if (ret)
			break;
	}
	spin_unlock_irqrestore(&rpm->lock, flags);

	return ret;
}

static void invalidate_batch(struct rpmh_client *rc)
{
	struct rpmh_ctrlr *rpm = rc->ctrlr;
	unsigned long flags;
	int index = 0;
	int i;

	spin_lock_irqsave(&rpm->lock, flags);
	while (rpm->batch_cache[index])
		index++;
	for (i = 0; i < index; i++) {
		kfree(rpm->batch_cache[i]->free);
		rpm->batch_cache[i] = NULL;
	}
	spin_unlock_irqrestore(&rpm->lock, flags);
}

/**
 * rpmh_write_batch: Write multiple sets of RPMH commands and wait for the
 * batch to finish.
 *
 * @rc: The RPMh handle got from rpmh_get_client
 * @state: Active/sleep set
 * @cmd: The payload data
 * @n: The array of count of elements in each batch, 0 terminated.
 *
 * Write a request to the mailbox controller without caching. If the request
 * state is ACTIVE, then the requests are treated as completion request
 * and sent to the controller immediately. The function waits until all the
 * commands are complete. If the request was to SLEEP or WAKE_ONLY, then the
 * request is sent as fire-n-forget and no ack is expected.
 *
 * May sleep. Do not call from atomic contexts for ACTIVE_ONLY requests.
 */
int rpmh_write_batch(struct rpmh_client *rc, enum rpmh_state state,
		     const struct tcs_cmd *cmd, u32 *n)
{
	struct rpmh_request *rpm_msg[RPMH_MAX_REQ_IN_BATCH] = { NULL };
	DECLARE_COMPLETION_ONSTACK(compl);
	atomic_t wait_count = ATOMIC_INIT(0);
	int count = 0;
	int ret, i;

	if (IS_ERR_OR_NULL(rc) || !cmd || !n)
		return -EINVAL;

	while (n[count++] > 0)
		;
	count--;
	if (!count || count > RPMH_MAX_REQ_IN_BATCH)
		return -EINVAL;

	for (i = 0; i < count; i++) {
		rpm_msg[i] = __get_rpmh_msg_async(rc, state, cmd, n[i]);
		if (IS_ERR_OR_NULL(rpm_msg[i])) {
			ret = PTR_ERR(rpm_msg[i]);
			for (; i >= 0; i--)
				kfree(rpm_msg[i]->free);
			return ret;
		}
		cmd += n[i];
	}

	if (state != RPMH_ACTIVE_ONLY_STATE)
		return cache_batch(rc, rpm_msg, count);

	atomic_set(&wait_count, count);

	for (i = 0; i < count; i++) {
		rpm_msg[i]->completion = &compl;
		rpm_msg[i]->wait_count = &wait_count;
		ret = rpmh_rsc_send_data(rc->ctrlr->drv, &rpm_msg[i]->msg);
		if (ret) {
			int j;

			pr_err("Error(%d) sending RPMH message addr=%#x\n",
			       ret, rpm_msg[i]->msg.cmds[0].addr);
			for (j = i; j < count; j++)
				rpmh_tx_done(&rpm_msg[j]->msg, ret);
			break;
		}
	}

	return wait_for_tx_done(rc, &compl, cmd[0].addr, cmd[0].data);
}
EXPORT_SYMBOL(rpmh_write_batch);

static int is_req_valid(struct cache_req *req)
{
	return (req->sleep_val != UINT_MAX &&
		req->wake_val != UINT_MAX &&
		req->sleep_val != req->wake_val);
}

static int send_single(struct rpmh_client *rc, enum rpmh_state state,
		      u32 addr, u32 data)
{
	DEFINE_RPMH_MSG_ONSTACK(rc, state, NULL, rpm_msg);

	/* Wake sets are always complete and sleep sets are not */
	rpm_msg.msg.wait_for_compl = (state == RPMH_WAKE_ONLY_STATE);
	rpm_msg.cmd[0].addr = addr;
	rpm_msg.cmd[0].data = data;
	rpm_msg.msg.num_cmds = 1;

	return rpmh_rsc_write_ctrl_data(rc->ctrlr->drv, &rpm_msg.msg);
}

/**
 * rpmh_flush: Flushes the buffered active and sleep sets to TCS
 *
 * @rc: The RPMh handle got from rpmh_get_client
 *
 * Return: -EBUSY if the controller is busy, probably waiting on a response
 * to a RPMH request sent earlier.
 *
 * This function is generally called from the sleep code from the last CPU
 * that is powering down the entire system. Since no other RPMH API would be
 * executing at this time, it is safe to run lockless.
 */
int rpmh_flush(struct rpmh_client *rc)
{
	struct cache_req *p;
	struct rpmh_ctrlr *rpm = rc->ctrlr;
	int ret;

	if (IS_ERR_OR_NULL(rc))
		return -EINVAL;

	if (!rpm->dirty) {
		pr_debug("Skipping flush, TCS has latest data.\n");
		return 0;
	}

	/* First flush the cached batch requests */
	ret = flush_batch(rc);
	if (ret)
		return ret;

	/*
	 * Nobody else should be calling this function other than system PM,,
	 * hence we can run without locks.
	 */
	list_for_each_entry(p, &rc->ctrlr->cache, list) {
		if (!is_req_valid(p)) {
			pr_debug("%s: skipping RPMH req: a:%#x s:%#x w:%#x",
				 __func__, p->addr, p->sleep_val, p->wake_val);
			continue;
		}
		ret = send_single(rc, RPMH_SLEEP_STATE, p->addr, p->sleep_val);
		if (ret)
			return ret;
		ret = send_single(rc, RPMH_WAKE_ONLY_STATE,
				  p->addr, p->wake_val);
		if (ret)
			return ret;
	}

	rpm->dirty = false;

	return 0;
}
EXPORT_SYMBOL(rpmh_flush);

/**
 * rpmh_invalidate: Invalidate all sleep and active sets
 * sets.
 *
 * @rc: The RPMh handle got from rpmh_get_client
 *
 * Invalidate the sleep and active values in the TCS blocks.
 */
int rpmh_invalidate(struct rpmh_client *rc)
{
	struct rpmh_ctrlr *rpm = rc->ctrlr;
	int ret;

	if (IS_ERR_OR_NULL(rc))
		return -EINVAL;

	invalidate_batch(rc);

	rpm->dirty = true;

	do {
		ret = rpmh_rsc_invalidate(rc->ctrlr->drv);
	} while (ret == -EAGAIN);

	return ret;
}
EXPORT_SYMBOL(rpmh_invalidate);

static struct rpmh_ctrlr *get_rpmh_ctrlr(struct platform_device *pdev)
{
	int i;
	struct rsc_drv *drv = dev_get_drvdata(pdev->dev.parent);
	struct rpmh_ctrlr *ctrlr = ERR_PTR(-EINVAL);

	if (!drv)
		return ctrlr;

	mutex_lock(&rpmh_ctrlr_mutex);
	for (i = 0; i < RPMH_MAX_MBOXES; i++) {
		if (rpmh_rsc[i].drv == drv) {
			ctrlr = &rpmh_rsc[i];
			goto unlock;
		}
	}

	for (i = 0; i < RPMH_MAX_MBOXES; i++) {
		if (rpmh_rsc[i].drv == NULL) {
			ctrlr = &rpmh_rsc[i];
			ctrlr->drv = drv;
			spin_lock_init(&ctrlr->lock);
			INIT_LIST_HEAD(&ctrlr->cache);
			break;
		}
	}
	WARN_ON(i == RPMH_MAX_MBOXES);
unlock:
	mutex_unlock(&rpmh_ctrlr_mutex);
	return ctrlr;
}

/**
 * rpmh_get_client: Get the RPMh handle
 *
 * @pdev: the platform device which needs to communicate with RPM
 * accelerators
 * May sleep.
 */
struct rpmh_client *rpmh_get_client(struct platform_device *pdev)
{
	struct rpmh_client *rc;

	rc = kzalloc(sizeof(*rc), GFP_KERNEL);
	if (!rc)
		return ERR_PTR(-ENOMEM);

	rc->dev = &pdev->dev;
	rc->ctrlr = get_rpmh_ctrlr(pdev);
	if (IS_ERR(rc->ctrlr)) {
		kfree(rc);
		return ERR_PTR(-EINVAL);
	}

	return rc;
}
EXPORT_SYMBOL(rpmh_get_client);

/**
 * rpmh_release: Release the RPMH client
 *
 * @rc: The RPMh handle to be freed.
 */
void rpmh_release(struct rpmh_client *rc)
{
	kfree(rc);
}
EXPORT_SYMBOL(rpmh_release);
