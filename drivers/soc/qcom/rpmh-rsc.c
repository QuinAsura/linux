// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 */

#define pr_fmt(fmt) "%s " fmt, KBUILD_MODNAME

#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <soc/qcom/tcs.h>
#include <dt-bindings/soc/qcom,rpmh-rsc.h>

#include "rpmh-internal.h"

#define CREATE_TRACE_POINTS
#include "trace-rpmh.h"

#define RSC_DRV_TCS_OFFSET		672
#define RSC_DRV_CMD_OFFSET		20

/* DRV Configuration Information Register */
#define DRV_PRNT_CHLD_CONFIG		0x0C
#define DRV_NUM_TCS_MASK		0x3F
#define DRV_NUM_TCS_SHIFT		6
#define DRV_NCPT_MASK			0x1F
#define DRV_NCPT_SHIFT			27

/* Register offsets */
#define RSC_DRV_IRQ_ENABLE		0x00
#define RSC_DRV_IRQ_STATUS		0x04
#define RSC_DRV_IRQ_CLEAR		0x08
#define RSC_DRV_CMD_WAIT_FOR_CMPL	0x10
#define RSC_DRV_CONTROL			0x14
#define RSC_DRV_STATUS			0x18
#define RSC_DRV_CMD_ENABLE		0x1C
#define RSC_DRV_CMD_MSGID		0x30
#define RSC_DRV_CMD_ADDR		0x34
#define RSC_DRV_CMD_DATA		0x38
#define RSC_DRV_CMD_STATUS		0x3C
#define RSC_DRV_CMD_RESP_DATA		0x40

#define TCS_AMC_MODE_ENABLE		BIT(16)
#define TCS_AMC_MODE_TRIGGER		BIT(24)

/* TCS CMD register bit mask */
#define CMD_MSGID_LEN			8
#define CMD_MSGID_RESP_REQ		BIT(8)
#define CMD_MSGID_WRITE			BIT(16)
#define CMD_STATUS_ISSUED		BIT(8)
#define CMD_STATUS_COMPL		BIT(16)

static struct tcs_group *get_tcs_from_index(struct rsc_drv *drv, int m)
{
	struct tcs_group *tcs;
	int i;

	for (i = 0; i < drv->num_tcs; i++) {
		tcs = &drv->tcs[i];
		if (tcs->mask & BIT(m))
			return tcs;
	}

	WARN(i == drv->num_tcs, "Incorrect TCS index %d", m);

	return NULL;
}

static struct tcs_response *setup_response(struct rsc_drv *drv,
					   const struct tcs_request *msg, int m)
{
	struct tcs_response *resp;
	struct tcs_group *tcs;

	resp = kzalloc(sizeof(*resp), GFP_ATOMIC);
	if (!resp)
		return ERR_PTR(-ENOMEM);

	resp->drv = drv;
	resp->msg = msg;
	resp->err = 0;

	tcs = get_tcs_from_index(drv, m);
	if (!tcs)
		return ERR_PTR(-EINVAL);

	assert_spin_locked(&tcs->lock);
	tcs->responses[m - tcs->offset] = resp;

	return resp;
}

static void free_response(struct tcs_response *resp)
{
	kfree(resp);
}

static struct tcs_response *get_response(struct rsc_drv *drv, u32 m)
{
	struct tcs_group *tcs = get_tcs_from_index(drv, m);

	return tcs->responses[m - tcs->offset];
}

static u32 read_tcs_reg(struct rsc_drv *drv, int reg, int m, int n)
{
	return readl_relaxed(drv->tcs_base + reg + RSC_DRV_TCS_OFFSET * m +
			     RSC_DRV_CMD_OFFSET * n);
}

static void write_tcs_reg(struct rsc_drv *drv, int reg, int m, int n, u32 data)
{
	writel_relaxed(data, drv->tcs_base + reg + RSC_DRV_TCS_OFFSET * m +
		       RSC_DRV_CMD_OFFSET * n);
}

static void write_tcs_reg_sync(struct rsc_drv *drv, int reg, int m, int n,
			       u32 data)
{
	write_tcs_reg(drv, reg, m, n, data);
	for (;;) {
		if (data == read_tcs_reg(drv, reg, m, n))
			break;
		udelay(1);
	}
}

static bool tcs_is_free(struct rsc_drv *drv, int m)
{
	return !test_bit(m, drv->tcs_in_use) &&
	       read_tcs_reg(drv, RSC_DRV_STATUS, m, 0);
}

static struct tcs_group *get_tcs_of_type(struct rsc_drv *drv, int type)
{
	int i;
	struct tcs_group *tcs;

	for (i = 0; i < TCS_TYPE_NR; i++) {
		if (type == drv->tcs[i].type)
			break;
	}

	if (i == TCS_TYPE_NR)
		return ERR_PTR(-EINVAL);

	tcs = &drv->tcs[i];
	if (!tcs->num_tcs)
		return ERR_PTR(-EINVAL);

	return tcs;
}

static int __tcs_invalidate(struct rsc_drv *drv, int type)
{
	int m;
	struct tcs_group *tcs;

	tcs = get_tcs_of_type(drv, type);
	if (IS_ERR(tcs))
		return PTR_ERR(tcs);

	spin_lock(&tcs->lock);
	if (bitmap_empty(tcs->slots, MAX_TCS_SLOTS)) {
		spin_unlock(&tcs->lock);
		return 0;
	}

	for (m = tcs->offset; m < tcs->offset + tcs->num_tcs; m++) {
		if (!tcs_is_free(drv, m)) {
			spin_unlock(&tcs->lock);
			return -EAGAIN;
		}
		write_tcs_reg_sync(drv, RSC_DRV_CMD_ENABLE, m, 0, 0);
		bitmap_zero(tcs->slots, MAX_TCS_SLOTS);
	}
	spin_unlock(&tcs->lock);

	return 0;
}

/**
 * rpmh_rsc_invalidate - Invalidate sleep and wake TCSes
 *
 * @drv: the mailbox controller
 */
int rpmh_rsc_invalidate(struct rsc_drv *drv)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&drv->drv_lock, flags);
	ret = __tcs_invalidate(drv, SLEEP_TCS);
	if (!ret)
		ret = __tcs_invalidate(drv, WAKE_TCS);
	spin_unlock_irqrestore(&drv->drv_lock, flags);

	return ret;
}
EXPORT_SYMBOL(rpmh_rsc_invalidate);

static struct tcs_group *get_tcs_for_msg(struct rsc_drv *drv,
					 const struct tcs_request *msg)
{
	int type;
	struct tcs_group *tcs;

	switch (msg->state) {
	case RPMH_ACTIVE_ONLY_STATE:
		type = ACTIVE_TCS;
		break;
	case RPMH_WAKE_ONLY_STATE:
		type = WAKE_TCS;
		break;
	case RPMH_SLEEP_STATE:
		type = SLEEP_TCS;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	/*
	 * If we are making an active request on a RSC that does not have a
	 * dedicated TCS for active state use, then re-purpose a wake TCS to
	 * send active votes.
	 * NOTE: The driver must be aware that this RSC does not have a
	 * dedicated AMC, and therefore would invalidate the sleep and wake
	 * TCSes before making an active state request.
	 */
	tcs = get_tcs_of_type(drv, type);
	if (msg->state == RPMH_ACTIVE_ONLY_STATE && IS_ERR(tcs)) {
		tcs = get_tcs_of_type(drv, WAKE_TCS);
		if (!IS_ERR(tcs))
			rpmh_rsc_invalidate(drv);
	}

	return tcs;
}

static void send_tcs_response(struct tcs_response *resp)
{
	struct rsc_drv *drv;
	unsigned long flags;

	if (!resp)
		return;

	drv = resp->drv;
	spin_lock_irqsave(&drv->drv_lock, flags);
	INIT_LIST_HEAD(&resp->list);
	list_add_tail(&resp->list, &drv->response_pending);
	spin_unlock_irqrestore(&drv->drv_lock, flags);

	tasklet_schedule(&drv->tasklet);
}

/**
 * tcs_irq_handler: TX Done interrupt handler
 */
static irqreturn_t tcs_irq_handler(int irq, void *p)
{
	struct rsc_drv *drv = p;
	int m, i;
	u32 irq_status, sts;
	struct tcs_response *resp;
	struct tcs_cmd *cmd;

	irq_status = read_tcs_reg(drv, RSC_DRV_IRQ_STATUS, 0, 0);

	for (m = 0; m < drv->num_tcs; m++) {
		if (!(irq_status & (u32)BIT(m)))
			continue;

		resp = get_response(drv, m);
		if (WARN_ON(!resp))
			goto skip_resp;

		resp->err = 0;
		for (i = 0; i < resp->msg->num_cmds; i++) {
			cmd = &resp->msg->cmds[i];
			sts = read_tcs_reg(drv, RSC_DRV_CMD_STATUS, m, i);
			if (!(sts & CMD_STATUS_ISSUED) ||
			   ((resp->msg->wait_for_compl || cmd->wait) &&
			   !(sts & CMD_STATUS_COMPL))) {
				resp->err = -EIO;
				break;
			}
		}
skip_resp:
		/* Reclaim the TCS */
		write_tcs_reg(drv, RSC_DRV_CMD_ENABLE, m, 0, 0);
		write_tcs_reg(drv, RSC_DRV_IRQ_CLEAR, 0, 0, BIT(m));
		trace_rpmh_notify_irq(drv, resp);
		clear_bit(m, drv->tcs_in_use);
		send_tcs_response(resp);
	}

	return IRQ_HANDLED;
}

/**
 * tcs_notify_tx_done: TX Done for requests that got a response
 *
 * @data: the tasklet argument
 *
 * Tasklet function to notify MBOX that we are done with the request.
 * Handles all pending reponses whenever run.
 */
static void tcs_notify_tx_done(unsigned long data)
{
	struct rsc_drv *drv = (struct rsc_drv *)data;
	struct tcs_response *resp;
	unsigned long flags;
	const struct tcs_request *msg;
	int err;

	for (;;) {
		spin_lock_irqsave(&drv->drv_lock, flags);
		resp = list_first_entry_or_null(&drv->response_pending,
						struct tcs_response, list);
		if (!resp) {
			spin_unlock_irqrestore(&drv->drv_lock, flags);
			break;
		}
		list_del(&resp->list);
		spin_unlock_irqrestore(&drv->drv_lock, flags);
		trace_rpmh_notify_tx_done(drv, resp);
		msg = resp->msg;
		err = resp->err;
		free_response(resp);
		rpmh_tx_done(msg, err);
	}
}

static void __tcs_buffer_write(struct rsc_drv *drv, int m, int n,
			       const struct tcs_request *msg)
{
	u32 msgid, cmd_msgid;
	u32 cmd_enable = 0;
	u32 cmd_complete;
	struct tcs_cmd *cmd;
	int i, j;

	cmd_msgid = CMD_MSGID_LEN;
	cmd_msgid |= msg->wait_for_compl ? CMD_MSGID_RESP_REQ : 0;
	cmd_msgid |= CMD_MSGID_WRITE;

	cmd_complete = read_tcs_reg(drv, RSC_DRV_CMD_WAIT_FOR_CMPL, m, 0);

	for (i = 0, j = n; i < msg->num_cmds; i++, j++) {
		cmd = &msg->cmds[i];
		cmd_enable |= BIT(j);
		cmd_complete |= cmd->wait << j;
		msgid = cmd_msgid;
		msgid |= cmd->wait ? CMD_MSGID_RESP_REQ : 0;
		write_tcs_reg(drv, RSC_DRV_CMD_MSGID, m, j, msgid);
		write_tcs_reg(drv, RSC_DRV_CMD_ADDR, m, j, cmd->addr);
		write_tcs_reg(drv, RSC_DRV_CMD_DATA, m, j, cmd->data);
		trace_rpmh_send_msg(drv, m, j, msgid, cmd);
	}

	write_tcs_reg(drv, RSC_DRV_CMD_WAIT_FOR_CMPL, m, 0, cmd_complete);
	cmd_enable |= read_tcs_reg(drv, RSC_DRV_CMD_ENABLE, m, 0);
	write_tcs_reg(drv, RSC_DRV_CMD_ENABLE, m, 0, cmd_enable);
}

static void __tcs_trigger(struct rsc_drv *drv, int m)
{
	u32 enable;

	/*
	 * HW req: Clear the DRV_CONTROL and enable TCS again
	 * While clearing ensure that the AMC mode trigger is cleared
	 * and then the mode enable is cleared.
	 */
	enable = read_tcs_reg(drv, RSC_DRV_CONTROL, m, 0);
	enable &= ~TCS_AMC_MODE_TRIGGER;
	write_tcs_reg_sync(drv, RSC_DRV_CONTROL, m, 0, enable);
	enable &= ~TCS_AMC_MODE_ENABLE;
	write_tcs_reg_sync(drv, RSC_DRV_CONTROL, m, 0, enable);

	/* Enable the AMC mode on the TCS and then trigger the TCS */
	enable = TCS_AMC_MODE_ENABLE;
	write_tcs_reg_sync(drv, RSC_DRV_CONTROL, m, 0, enable);
	enable |= TCS_AMC_MODE_TRIGGER;
	write_tcs_reg_sync(drv, RSC_DRV_CONTROL, m, 0, enable);
}

static int check_for_req_inflight(struct rsc_drv *drv, struct tcs_group *tcs,
				  const struct tcs_request *msg)
{
	unsigned long curr_enabled;
	u32 addr;
	int i, j, k;
	int m = tcs->offset;

	for (i = 0; i < tcs->num_tcs; i++, m++) {
		if (tcs_is_free(drv, m))
			continue;

		curr_enabled = read_tcs_reg(drv, RSC_DRV_CMD_ENABLE, m, 0);

		for_each_set_bit(j, &curr_enabled, MAX_CMDS_PER_TCS) {
			addr = read_tcs_reg(drv, RSC_DRV_CMD_ADDR, m, j);
			for (k = 0; k < msg->num_cmds; k++) {
				if (addr == msg->cmds[k].addr)
					return -EBUSY;
			}
		}
	}

	return 0;
}

static int find_free_tcs(struct tcs_group *tcs)
{
	int m;

	for (m = 0; m < tcs->num_tcs; m++) {
		if (tcs_is_free(tcs->drv, tcs->offset + m))
			return tcs->offset + m;
	}

	return -EBUSY;
}

static int tcs_mbox_write(struct rsc_drv *drv, const struct tcs_request *msg)
{
	struct tcs_group *tcs;
	int m;
	struct tcs_response *resp = NULL;
	unsigned long flags;
	int ret;

	tcs = get_tcs_for_msg(drv, msg);
	if (IS_ERR(tcs))
		return PTR_ERR(tcs);

	spin_lock_irqsave(&tcs->lock, flags);
	m = find_free_tcs(tcs);
	if (m < 0) {
		ret = m;
		goto done_write;
	}

	/*
	 * The h/w does not like if we send a request to the same address,
	 * when one is already in-flight or being processed.
	 */
	ret = check_for_req_inflight(drv, tcs, msg);
	if (ret)
		goto done_write;

	resp = setup_response(drv, msg, m);
	if (IS_ERR(resp)) {
		ret = PTR_ERR(resp);
		goto done_write;
	}

	set_bit(m, drv->tcs_in_use);
	__tcs_buffer_write(drv, m, 0, msg);
	__tcs_trigger(drv, m);

done_write:
	spin_unlock_irqrestore(&tcs->lock, flags);
	return ret;
}

/**
 * rpmh_rsc_send_data: Validate the incoming message and write to the
 * appropriate TCS block.
 *
 * @drv: the controller
 * @msg: the data to be sent
 *
 * Return: 0 on success, -EINVAL on error.
 * Note: This call blocks until a valid data is written to the TCS.
 */
int rpmh_rsc_send_data(struct rsc_drv *drv, const struct tcs_request *msg)
{
	int ret;

	if (!msg || !msg->cmds || !msg->num_cmds ||
	    msg->num_cmds > MAX_RPMH_PAYLOAD)
		return -EINVAL;

	do {
		ret = tcs_mbox_write(drv, msg);
		if (ret == -EBUSY) {
			pr_info_ratelimited("TCS Busy, retrying RPMH message send: addr=%#x\n",
					    msg->cmds[0].addr);
			udelay(10);
		}
	} while (ret == -EBUSY);

	return ret;
}
EXPORT_SYMBOL(rpmh_rsc_send_data);

static int find_match(const struct tcs_group *tcs, const struct tcs_cmd *cmd,
		      int len)
{
	int i, j;

	/* Check for already cached commands */
	for_each_set_bit(i, tcs->slots, MAX_TCS_SLOTS) {
		for (j = 0; j < len; j++) {
			if (tcs->cmd_cache[i] != cmd[0].addr) {
				if (j == 0)
					break;
				WARN(tcs->cmd_cache[i + j] != cmd[j].addr,
				     "Message does not match previous sequence.\n");
				return -EINVAL;
			} else if (j == len - 1) {
				return i;
			}
		}
	}

	return -ENODATA;
}

static int find_slots(struct tcs_group *tcs, const struct tcs_request *msg,
		      int *m, int *n)
{
	int slot, offset;
	int i = 0;

	/* Find if we already have the msg in our TCS */
	slot = find_match(tcs, msg->cmds, msg->num_cmds);
	if (slot >= 0)
		goto copy_data;

	/* Do over, until we can fit the full payload in a TCS */
	do {
		slot = bitmap_find_next_zero_area(tcs->slots, MAX_TCS_SLOTS,
						  i, msg->num_cmds, 0);
		if (slot == MAX_TCS_SLOTS)
			return -ENOMEM;
		i += tcs->ncpt;
	} while (slot + msg->num_cmds - 1 >= i);

copy_data:
	bitmap_set(tcs->slots, slot, msg->num_cmds);
	/* Copy the addresses of the resources over to the slots */
	for (i = 0; i < msg->num_cmds; i++)
		tcs->cmd_cache[slot + i] = msg->cmds[i].addr;

	offset = slot / tcs->ncpt;
	*m = offset + tcs->offset;
	*n = slot % tcs->ncpt;

	return 0;
}

static int tcs_ctrl_write(struct rsc_drv *drv, const struct tcs_request *msg)
{
	struct tcs_group *tcs;
	int m = 0, n = 0;
	unsigned long flags;
	int ret;

	tcs = get_tcs_for_msg(drv, msg);
	if (IS_ERR(tcs))
		return PTR_ERR(tcs);

	spin_lock_irqsave(&tcs->lock, flags);
	/* find the m-th TCS and the n-th position in the TCS to write to */
	ret = find_slots(tcs, msg, &m, &n);
	if (!ret)
		__tcs_buffer_write(drv, m, n, msg);
	spin_unlock_irqrestore(&tcs->lock, flags);

	return ret;
}

/**
 * rpmh_rsc_write_ctrl_data: Write request to the controller
 *
 * @drv: the controller
 * @msg: the data to be written to the controller
 *
 * There is no response returned for writing the request to the controller.
 */
int rpmh_rsc_write_ctrl_data(struct rsc_drv *drv, const struct tcs_request *msg)
{
	if (!msg || !msg->cmds || !msg->num_cmds ||
	    msg->num_cmds > MAX_RPMH_PAYLOAD) {
		pr_err("Payload error\n");
		return -EINVAL;
	}

	/* Data sent to this API will not be sent immediately */
	if (msg->state == RPMH_ACTIVE_ONLY_STATE)
		return -EINVAL;

	return tcs_ctrl_write(drv, msg);
}
EXPORT_SYMBOL(rpmh_rsc_write_ctrl_data);

static int rpmh_probe_tcs_config(struct platform_device *pdev,
				 struct rsc_drv *drv)
{
	struct tcs_type_config {
		u32 type;
		u32 n;
	} tcs_cfg[TCS_TYPE_NR] = { { 0 } };
	struct device_node *dn = pdev->dev.of_node;
	u32 config, max_tcs, ncpt;
	int i, ret, n, st = 0;
	struct tcs_group *tcs;
	struct resource *res;
	void __iomem *base;

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "drv");
	base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(base))
		return PTR_ERR(base);

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "tcs");
	drv->tcs_base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(drv->tcs_base))
		return PTR_ERR(drv->tcs_base);

	config = readl_relaxed(base + DRV_PRNT_CHLD_CONFIG);

	max_tcs = config;
	max_tcs &= DRV_NUM_TCS_MASK << (DRV_NUM_TCS_SHIFT * drv->id);
	max_tcs = max_tcs >> (DRV_NUM_TCS_SHIFT * drv->id);

	ncpt = config & (DRV_NCPT_MASK << DRV_NCPT_SHIFT);
	ncpt = ncpt >> DRV_NCPT_SHIFT;

	n = of_property_count_u32_elems(dn, "qcom,tcs-config");
	if (n != 2 * TCS_TYPE_NR)
		return -EINVAL;

	for (i = 0; i < TCS_TYPE_NR; i++) {
		ret = of_property_read_u32_index(dn, "qcom,tcs-config",
						 i * 2, &tcs_cfg[i].type);
		if (ret)
			return ret;
		if (tcs_cfg[i].type >= TCS_TYPE_NR)
			return -EINVAL;

		ret = of_property_read_u32_index(dn, "qcom,tcs-config",
						 i * 2 + 1, &tcs_cfg[i].n);
		if (ret)
			return ret;
		if (tcs_cfg[i].n > MAX_TCS_PER_TYPE)
			return -EINVAL;
	}

	for (i = 0; i < TCS_TYPE_NR; i++) {
		tcs = &drv->tcs[tcs_cfg[i].type];
		if (tcs->drv)
			return -EINVAL;
		tcs->drv = drv;
		tcs->type = tcs_cfg[i].type;
		tcs->num_tcs = tcs_cfg[i].n;
		tcs->ncpt = ncpt;
		spin_lock_init(&tcs->lock);

		if (!tcs->num_tcs || tcs->type == CONTROL_TCS)
			continue;

		if (st + tcs->num_tcs > max_tcs ||
		    st + tcs->num_tcs >= BITS_PER_BYTE * sizeof(tcs->mask))
			return -EINVAL;

		tcs->mask = ((1 << tcs->num_tcs) - 1) << st;
		tcs->offset = st;
		st += tcs->num_tcs;

		/*
		 * Allocate memory to cache sleep and wake requests to
		 * avoid reading TCS register memory.
		 */
		if (tcs->type == ACTIVE_TCS)
			continue;

		tcs->cmd_cache = devm_kcalloc(&pdev->dev,
					      tcs->num_tcs * ncpt, sizeof(u32),
					      GFP_KERNEL);
		if (!tcs->cmd_cache)
			return -ENOMEM;
	}

	drv->num_tcs = st;

	return 0;
}

static int rpmh_rsc_probe(struct platform_device *pdev)
{
	struct device_node *dn = pdev->dev.of_node;
	struct rsc_drv *drv;
	int ret, irq;

	drv = devm_kzalloc(&pdev->dev, sizeof(*drv), GFP_KERNEL);
	if (!drv)
		return -ENOMEM;

	ret = of_property_read_u32(dn, "qcom,drv-id", &drv->id);
	if (ret)
		return ret;

	drv->name = of_get_property(dn, "label", NULL);
	if (!drv->name)
		drv->name = dev_name(&pdev->dev);

	ret = rpmh_probe_tcs_config(pdev, drv);
	if (ret)
		return ret;

	INIT_LIST_HEAD(&drv->response_pending);
	spin_lock_init(&drv->drv_lock);
	tasklet_init(&drv->tasklet, tcs_notify_tx_done, (unsigned long)drv);
	bitmap_zero(drv->tcs_in_use, MAX_TCS_NR);

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	ret = devm_request_irq(&pdev->dev, irq, tcs_irq_handler,
			       IRQF_TRIGGER_HIGH | IRQF_NO_SUSPEND,
			       drv->name, drv);
	if (ret)
		return ret;

	/* Enable the active TCS to send requests immediately */
	write_tcs_reg(drv, RSC_DRV_IRQ_ENABLE, 0, 0, drv->tcs[ACTIVE_TCS].mask);

	dev_set_drvdata(&pdev->dev, drv);

	return devm_of_platform_populate(&pdev->dev);
}

static const struct of_device_id rpmh_drv_match[] = {
	{ .compatible = "qcom,rpmh-rsc", },
	{ }
};

static struct platform_driver rpmh_driver = {
	.probe = rpmh_rsc_probe,
	.driver = {
		  .name = "rpmh",
		  .of_match_table = rpmh_drv_match,
	},
};

static int __init rpmh_driver_init(void)
{
	return platform_driver_register(&rpmh_driver);
}
arch_initcall(rpmh_driver_init);
