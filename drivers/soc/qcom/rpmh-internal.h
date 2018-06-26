/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 */


#ifndef __RPM_INTERNAL_H__
#define __RPM_INTERNAL_H__

#include <linux/bitmap.h>
#include <soc/qcom/tcs.h>

#define TCS_TYPE_NR			4
#define MAX_CMDS_PER_TCS		16
#define MAX_TCS_PER_TYPE		3
#define MAX_TCS_NR			(MAX_TCS_PER_TYPE * TCS_TYPE_NR)
#define MAX_TCS_SLOTS			(MAX_CMDS_PER_TCS * MAX_TCS_PER_TYPE)

struct rsc_drv;

/**
 * struct tcs_response: Response object for a request
 *
 * @drv:   the controller
 * @msg:   the request for this response
 * @m:     the tcs identifier
 * @err:   error reported in the response
 * @list:  element in list of pending response objects
 */
struct tcs_response {
	struct rsc_drv *drv;
	const struct tcs_request *msg;
	int err;
	struct list_head list;
};

/**
 * struct tcs_group: group of Trigger Command Sets for a request state
 *
 * @drv:       the controller
 * @type:      type of the TCS in this group - active, sleep, wake
 * @mask:      mask of the TCSes relative to all the TCSes in the RSC
 * @offset:    start of the TCS group relative to the TCSes in the RSC
 * @num_tcs:   number of TCSes in this type
 * @ncpt:      number of commands in each TCS
 * @lock:      lock for synchronizing this TCS writes
 * @responses: response objects for requests sent from each TCS
 * @cmd_cache: flattened cache of cmds in sleep/wake TCS
 * @slots:     indicates which of @cmd_addr are occupied
 */
struct tcs_group {
	struct rsc_drv *drv;
	int type;
	u32 mask;
	u32 offset;
	int num_tcs;
	int ncpt;
	spinlock_t lock;
	struct tcs_response *responses[MAX_TCS_PER_TYPE];
	u32 *cmd_cache;
	DECLARE_BITMAP(slots, MAX_TCS_SLOTS);
};

/**
 * struct rsc_drv: the Resource State Coordinator controller
 *
 * @name:       controller identifier
 * @tcs_base:   start address of the TCS registers in this controller
 * @id:         instance id in the controller (Direct Resource Voter)
 * @num_tcs:    number of TCSes in this DRV
 * @tasklet:    handle responses, off-load work from IRQ handler
 * @response_pending:
 *              list of responses that needs to be sent to caller
 * @tcs:        TCS groups
 * @tcs_in_use: s/w state of the TCS
 * @drv_lock:   synchronize state of the controller
 */
struct rsc_drv {
	const char *name;
	void __iomem *tcs_base;
	int id;
	int num_tcs;
	struct tasklet_struct tasklet;
	struct list_head response_pending;
	struct tcs_group tcs[TCS_TYPE_NR];
	DECLARE_BITMAP(tcs_in_use, MAX_TCS_NR);
	spinlock_t drv_lock;
};


int rpmh_rsc_send_data(struct rsc_drv *drv, const struct tcs_request *msg);
int rpmh_rsc_write_ctrl_data(struct rsc_drv *drv,
			     const struct tcs_request *msg);
int rpmh_rsc_invalidate(struct rsc_drv *drv);

void rpmh_tx_done(const struct tcs_request *msg, int r);

#endif /* __RPM_INTERNAL_H__ */
