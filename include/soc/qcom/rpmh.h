/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 */

#ifndef __SOC_QCOM_RPMH_H__
#define __SOC_QCOM_RPMH_H__

#include <soc/qcom/tcs.h>
#include <linux/platform_device.h>

struct rpmh_client;

#if IS_ENABLED(CONFIG_QCOM_RPMH)
int rpmh_write(struct rpmh_client *rc, enum rpmh_state state,
	       const struct tcs_cmd *cmd, u32 n);

int rpmh_write_async(struct rpmh_client *rc, enum rpmh_state state,
		     const struct tcs_cmd *cmd, u32 n);

int rpmh_write_batch(struct rpmh_client *rc, enum rpmh_state state,
		     const struct tcs_cmd *cmd, u32 *n);

struct rpmh_client *rpmh_get_client(struct platform_device *pdev);

int rpmh_flush(struct rpmh_client *rc);

int rpmh_invalidate(struct rpmh_client *rc);

void rpmh_release(struct rpmh_client *rc);

#else

static inline int rpmh_write(struct rpmh_client *rc, enum rpmh_state state,
			     const struct tcs_cmd *cmd, u32 n)
{ return -ENODEV; }

static inline struct rpmh_client *rpmh_get_client(struct platform_device *pdev)
{ return ERR_PTR(-ENODEV); }

static inline int rpmh_write_async(struct rpmh_client *rc,
				   enum rpmh_state state,
				   const struct tcs_cmd *cmd, u32 n)
{ return -ENODEV; }

static inline int rpmh_write_batch(struct rpmh_client *rc,
				   enum rpmh_state state,
				   const struct tcs_cmd *cmd, u32 *n)
{ return -ENODEV; }

static inline int rpmh_flush(struct rpmh_client *rc)
{ return -ENODEV; }

static inline int rpmh_invalidate(struct rpmh_client *rc)
{ return -ENODEV; }

static inline void rpmh_release(struct rpmh_client *rc) { }
#endif /* CONFIG_QCOM_RPMH */

#endif /* __SOC_QCOM_RPMH_H__ */
