// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2017-2018, The Linux Foundation. All rights reserved.
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
//#include <linux/regmap.h>
#include <soc/qcom/cmd-db.h>
#include <soc/qcom/rpmh.h>

#include <dt-bindings/clock/qcom,rpmh.h>

#include "common.h"
//#include "clk-regmap.h"

#define CLK_RPMH_ARC_EN_OFFSET 0
#define CLK_RPMH_VRM_EN_OFFSET 4
#define CLK_RPMH_VRM_OFF_VAL 0
#define CLK_RPMH_VRM_ON_VAL 1
#define CLK_RPMH_APPS_RSC_AO_STATE_MASK (BIT(RPMH_WAKE_ONLY_STATE) | \
					 BIT(RPMH_ACTIVE_ONLY_STATE))
#define CLK_RPMH_APPS_RSC_STATE_MASK (BIT(RPMH_WAKE_ONLY_STATE) | \
				      BIT(RPMH_ACTIVE_ONLY_STATE) | \
				      BIT(RPMH_SLEEP_STATE))
struct clk_rpmh {
	struct clk_hw hw;
	const char *res_name;
	u32 res_addr;
	u32 res_en_offset;
	u32 res_on_val;
	u32 res_off_val;
	u32 state;
	u32 aggr_state;
	u32 last_sent_aggr_state;
	u32 valid_state_mask;
	struct rpmh_client *rpmh_client;
	unsigned long rate;
	struct clk_rpmh *peer;
};

struct rpmh_cc {
	struct clk_onecell_data data;
	struct clk *clks[];
};

struct clk_rpmh_desc {
	struct clk_hw **clks;
	size_t num_clks;
};

static DEFINE_MUTEX(rpmh_clk_lock);

#define __DEFINE_CLK_RPMH(_platform, _name, _name_active, _res_name, \
			  _res_en_offset, _res_on, _res_off, _rate, \
			  _state_mask, _state_on_mask)			      \
	static struct clk_rpmh _platform##_##_name_active;		      \
	static struct clk_rpmh _platform##_##_name = {			      \
		.res_name = _res_name,					      \
		.res_en_offset = _res_en_offset,			      \
		.res_on_val = _res_on,					      \
		.res_off_val = _res_off,				      \
		.rate = _rate,						      \
		.peer = &_platform##_##_name_active,			      \
		.valid_state_mask = _state_mask,			      \
		.hw.init = &(struct clk_init_data){			      \
			.ops = &clk_rpmh_ops,			              \
			.name = #_name,					      \
		},							      \
	};								      \
	static struct clk_rpmh _platform##_##_name_active = {		      \
		.res_name = _res_name,					      \
		.res_en_offset = _res_en_offset,			      \
		.res_on_val = _res_on,					      \
		.res_off_val = _res_off,				      \
		.rate = _rate,						      \
		.peer = &_platform##_##_name,				      \
		.valid_state_mask = _state_on_mask,			      \
		.hw.init = &(struct clk_init_data){			      \
			.ops = &clk_rpmh_ops,				      \
			.name = #_name_active,				      \
		},							      \
	}

#define DEFINE_CLK_RPMH_ARC(_platform, _name, _name_active, _res_name, \
			    _res_on, _res_off, _rate, _state_mask, \
			    _state_on_mask)				\
	__DEFINE_CLK_RPMH(_platform, _name, _name_active, _res_name,	\
			  CLK_RPMH_ARC_EN_OFFSET, _res_on, _res_off, \
			  _rate, _state_mask, _state_on_mask)

#define DEFINE_CLK_RPMH_VRM(_platform, _name, _name_active, _res_name,	\
			    _rate, _state_mask, _state_on_mask) \
	__DEFINE_CLK_RPMH(_platform, _name, _name_active, _res_name,	\
			  CLK_RPMH_VRM_EN_OFFSET, CLK_RPMH_VRM_ON_VAL,	\
			  CLK_RPMH_VRM_OFF_VAL, _rate, _state_mask, \
			  _state_on_mask)

static inline struct clk_rpmh *to_clk_rpmh(struct clk_hw *_hw)
{
	return container_of(_hw, struct clk_rpmh, hw);
}

static inline bool has_state_changed(struct clk_rpmh *c, u32 state)
{
	return ((c->last_sent_aggr_state & BIT(state))
		!= (c->aggr_state & BIT(state)));
}

static int clk_rpmh_send_aggregate_command(struct clk_rpmh *c)
{
	struct tcs_cmd cmd = { 0 };
	int ret = 0;

	cmd.addr = c->res_addr + c->res_en_offset;

	if (has_state_changed(c, RPMH_SLEEP_STATE)) {
		cmd.data = (c->aggr_state & BIT(RPMH_SLEEP_STATE))
				? c->res_on_val : c->res_off_val;
		ret = rpmh_write_async(c->rpmh_client, RPMH_SLEEP_STATE,
				       &cmd, 1);
		if (ret) {
			pr_err("%s: rpmh_write_async(%s, state=%d) failed (%d)\n",
			       __func__, c->res_name, RPMH_SLEEP_STATE, ret);
			return ret;
		}
	}

	if (has_state_changed(c, RPMH_WAKE_ONLY_STATE)) {
		cmd.data = (c->aggr_state & BIT(RPMH_WAKE_ONLY_STATE))
				? c->res_on_val : c->res_off_val;
		ret = rpmh_write_async(c->rpmh_client,
				       RPMH_WAKE_ONLY_STATE, &cmd, 1);
		if (ret) {
			pr_err("%s: rpmh_write_async(%s, state=%d) failed (%d)\n",
			       __func__, c->res_name, RPMH_WAKE_ONLY_STATE,
				 ret);
			return ret;
		}
	}

	if (has_state_changed(c, RPMH_ACTIVE_ONLY_STATE)) {
		cmd.data = (c->aggr_state & BIT(RPMH_ACTIVE_ONLY_STATE))
				? c->res_on_val : c->res_off_val;
		ret = rpmh_write(c->rpmh_client, RPMH_ACTIVE_ONLY_STATE,
				 &cmd, 1);
		if (ret) {
			pr_err("%s: rpmh_write(%s, state=%d) failed (%d)\n",
			       __func__, c->res_name, RPMH_ACTIVE_ONLY_STATE,
				 ret);
			return ret;
		}
	}

	c->last_sent_aggr_state = c->aggr_state;
	c->peer->last_sent_aggr_state =  c->last_sent_aggr_state;

	return 0;
}

static int clk_rpmh_aggregate_state_send_command(struct clk_rpmh *c,
						bool enable)
{
	int ret;

	/* Update state and aggregate state values based on enable value. */
	c->state = enable ? c->valid_state_mask : 0;
	c->aggr_state = c->state | c->peer->state;
	c->peer->aggr_state = c->aggr_state;

	ret = clk_rpmh_send_aggregate_command(c);
	if (ret && enable) {
		c->state = 0;
	} else if (ret) {
		c->state = c->valid_state_mask;
		WARN(1, "clk: %s failed to disable\n", c->res_name);
	}

	return ret;
}

static int clk_rpmh_prepare(struct clk_hw *hw)
{
	struct clk_rpmh *c = to_clk_rpmh(hw);
	int ret = 0;

	mutex_lock(&rpmh_clk_lock);

	if (c->state)
		goto out;

	ret = clk_rpmh_aggregate_state_send_command(c, true);
out:
	mutex_unlock(&rpmh_clk_lock);
	return ret;
};

static void clk_rpmh_unprepare(struct clk_hw *hw)
{
	struct clk_rpmh *c = to_clk_rpmh(hw);

	mutex_lock(&rpmh_clk_lock);

	if (!c->state)
		goto out;

	clk_rpmh_aggregate_state_send_command(c, false);
out:
	mutex_unlock(&rpmh_clk_lock);
	return;
};

static unsigned long clk_rpmh_recalc_rate(struct clk_hw *hw,
					  unsigned long parent_rate)
{
	struct clk_rpmh *r = to_clk_rpmh(hw);

	/*
	 * RPMh clocks have a fixed rate. Return static rate set
	 * at init time.
	 */
	return r->rate;
}

static const struct clk_ops clk_rpmh_ops = {
	.prepare	= clk_rpmh_prepare,
	.unprepare	= clk_rpmh_unprepare,
	.recalc_rate	= clk_rpmh_recalc_rate,
};

/* Resource name must match resource id present in cmd-db. */
DEFINE_CLK_RPMH_ARC(sdm845, bi_tcxo, bi_tcxo_ao, "xo.lvl", 0x3, 0x0,
		    19200000, CLK_RPMH_APPS_RSC_STATE_MASK,
		    CLK_RPMH_APPS_RSC_AO_STATE_MASK);
DEFINE_CLK_RPMH_VRM(sdm845, ln_bb_clk2, ln_bb_clk2_ao, "lnbclka2",
		    19200000, CLK_RPMH_APPS_RSC_STATE_MASK,
		    CLK_RPMH_APPS_RSC_AO_STATE_MASK);
DEFINE_CLK_RPMH_VRM(sdm845, ln_bb_clk3, ln_bb_clk3_ao, "lnbclka3",
		    19200000, CLK_RPMH_APPS_RSC_STATE_MASK,
		    CLK_RPMH_APPS_RSC_AO_STATE_MASK);
DEFINE_CLK_RPMH_VRM(sdm845, rf_clk1, rf_clk1_ao, "rfclka1",
		    38400000, CLK_RPMH_APPS_RSC_STATE_MASK,
		    CLK_RPMH_APPS_RSC_AO_STATE_MASK);
DEFINE_CLK_RPMH_VRM(sdm845, rf_clk2, rf_clk2_ao, "rfclka2",
		    38400000, CLK_RPMH_APPS_RSC_STATE_MASK,
		    CLK_RPMH_APPS_RSC_AO_STATE_MASK);
DEFINE_CLK_RPMH_VRM(sdm845, rf_clk3, rf_clk3_ao, "rfclka3",
		    38400000, CLK_RPMH_APPS_RSC_STATE_MASK,
		    CLK_RPMH_APPS_RSC_AO_STATE_MASK);

static struct clk_hw *sdm845_rpmh_clocks[] = {
//	[RPMH_CXO_CLK]		= &sdm845_bi_tcxo.hw,
//	[RPMH_CXO_CLK_A]	= &sdm845_bi_tcxo_ao.hw,
	[RPMH_LN_BB_CLK2]	= &sdm845_ln_bb_clk2.hw,
	[RPMH_LN_BB_CLK2_A]	= &sdm845_ln_bb_clk2_ao.hw,
	[RPMH_LN_BB_CLK3]	= &sdm845_ln_bb_clk3.hw,
	[RPMH_LN_BB_CLK3_A]	= &sdm845_ln_bb_clk3_ao.hw,
	[RPMH_RF_CLK1]		= &sdm845_rf_clk1.hw,
	[RPMH_RF_CLK1_A]	= &sdm845_rf_clk1_ao.hw,
	[RPMH_RF_CLK2]		= &sdm845_rf_clk2.hw,
	[RPMH_RF_CLK2_A]	= &sdm845_rf_clk2_ao.hw,
	[RPMH_RF_CLK3]		= &sdm845_rf_clk3.hw,
	[RPMH_RF_CLK3_A]	= &sdm845_rf_clk3_ao.hw,
};

static const struct clk_rpmh_desc clk_rpmh_sdm845 = {
	.clks = sdm845_rpmh_clocks,
	.num_clks = ARRAY_SIZE(sdm845_rpmh_clocks),
};

static const struct of_device_id clk_rpmh_match_table[] = {
	{ .compatible = "qcom,rpmh-clk-sdm845", .data = &clk_rpmh_sdm845},
	{ }
};
MODULE_DEVICE_TABLE(of, clk_rpmh_match_table);

static int clk_rpmh_probe(struct platform_device *pdev)
{
	struct clk **clks;
	struct clk *clk;
	struct rpmh_cc *rcc;
	struct clk_onecell_data *data;
	int ret;
	size_t num_clks, i;
	struct clk_hw **hw_clks;
	struct clk_rpmh *rpmh_clk;
	const struct clk_rpmh_desc *desc;
	struct rpmh_client *rpmh_client = NULL;

	desc = of_device_get_match_data(&pdev->dev);
	if (!desc) {
		ret = -EINVAL;
		goto err;
	}

	ret = cmd_db_ready();
	if (ret) {
		if (ret != -EPROBE_DEFER) {
			dev_err(&pdev->dev, "Command DB not available (%d)\n",
				ret);
			goto err;
		}
		return ret;
	}

	rpmh_client = rpmh_get_client(pdev);
	if (IS_ERR(rpmh_client)) {
		ret = PTR_ERR(rpmh_client);
		if (ret != -EPROBE_DEFER)
			dev_err(&pdev->dev, "failed to request RPMh client, ret=%d\n",
				ret);
		return ret;
	}

	hw_clks = desc->clks;
	num_clks = desc->num_clks;

	rcc = devm_kzalloc(&pdev->dev, sizeof(*rcc) + sizeof(*clks) * num_clks,
			   GFP_KERNEL);
	if (!rcc) {
		ret = -ENOMEM;
		goto err;
	}

	clks = rcc->clks;
	data = &rcc->data;
	data->clks = clks;
	data->clk_num = num_clks;

	for (i = 0; i < num_clks; i++) {
		if (!hw_clks[i])
			continue;

		rpmh_clk = to_clk_rpmh(hw_clks[i]);
		rpmh_clk->res_addr = cmd_db_read_addr(rpmh_clk->res_name);
		if (!rpmh_clk->res_addr) {
			dev_err(&pdev->dev, "missing RPMh resource address for %s\n",
				rpmh_clk->res_name);
			ret = -ENODEV;
			goto err;
		}

		rpmh_clk->rpmh_client = rpmh_client;

		clk = devm_clk_register(&pdev->dev, hw_clks[i]);
		if (IS_ERR(clk)) {
			dev_err(&pdev->dev, "failed to register %s\n", hw_clks[i]->init->name);
			ret = PTR_ERR(clk);
			goto err;
		}

		clks[i] = clk;
	}

	ret = of_clk_add_provider(pdev->dev.of_node, of_clk_src_onecell_get,
				  data);
	if (ret) {
		dev_err(&pdev->dev, "failed to add clock provider\n");
		goto err;
	}

	dev_info(&pdev->dev, "Registered RPMh clocks\n");
	return ret;

err:
	if (rpmh_client)
		rpmh_release(rpmh_client);

	dev_err(&pdev->dev, "Error registering RPMh Clock driver (%d)\n", ret);
	return ret;
}

static struct platform_driver clk_rpmh_driver = {
	.probe		= clk_rpmh_probe,
	.driver		= {
		.name	= "clk-rpmh",
		.of_match_table = clk_rpmh_match_table,
	},
};

static int __init clk_rpmh_init(void)
{
	return platform_driver_register(&clk_rpmh_driver);
}
subsys_initcall(clk_rpmh_init);

static void __exit clk_rpmh_exit(void)
{
	platform_driver_unregister(&clk_rpmh_driver);
}
module_exit(clk_rpmh_exit);

MODULE_DESCRIPTION("QTI RPMh Clock Driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:clk-rpmh");
