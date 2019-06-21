// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019, The Linux Foundation. All rights reserved.
 *
 */

#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/init.h>
#include <linux/interconnect.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/slab.h>

#include "osm-l3.h"

#define LUT_MAX_ENTRIES			40U
#define LUT_SRC				GENMASK(31, 30)
#define LUT_L_VAL			GENMASK(7, 0)
#define LUT_ROW_SIZE			32
#define CLK_HW_DIV			2

/* Register offsets */
#define REG_ENABLE			0x0
#define REG_FREQ_LUT			0x110
#define REG_PERF_STATE			0x920

static struct qcom_osm_l3 {
	u32 lut_tables[LUT_MAX_ENTRIES];
	void __iomem *base;
	unsigned int max_state;
} osm_l3;

int qcom_icc_osm_l3_request(u32 avg_bw, u32 peak_bw, u16 buswidth)
{
	unsigned int index;
	u64 bw = max(avg_bw, peak_bw);
	u64 freq;

	/* Convert bw to freq domain */
	freq = (bw * 1024 * 1024) / (buswidth * 1000);

	for (index = 0; index < osm_l3.max_state; index++) {
		if (osm_l3.lut_tables[index] >= freq)
			break;
	}

	index = max(index, osm_l3.max_state - 1);
	writel_relaxed(index, osm_l3.base + REG_PERF_STATE);
	return 0;
}
EXPORT_SYMBOL_GPL(qcom_icc_osm_l3_request);

/**
 * qcom_osm_l3_init() - initializer of OSM L3 Hardware
 * @pdev:	platform_device reference for acquiring resources
 *
 * Return: 0 on success, negative errno on failure
 */
int qcom_osm_l3_init(struct platform_device *pdev)
{
	u32 data, src, lval, i, prev_freq = 0, freq;
	static unsigned long hw_rate, xo_rate;
	struct resource *res;
	struct clk *clk;

	clk = clk_get(&pdev->dev, "xo");
	if (IS_ERR(clk))
		return PTR_ERR(clk);

	xo_rate = clk_get_rate(clk);
	clk_put(clk);

	clk = clk_get(&pdev->dev, "alternate");
	if (IS_ERR(clk))
		return PTR_ERR(clk);

	hw_rate = clk_get_rate(clk) / CLK_HW_DIV;
	clk_put(clk);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;

	osm_l3.base = devm_ioremap(&pdev->dev, res->start, resource_size(res));
	if (!osm_l3.base)
		return -ENOMEM;

	/* HW should be in enabled state to proceed */
	if (!(readl_relaxed(osm_l3.base + REG_ENABLE) & 0x1)) {
		dev_err(&pdev->dev, "OSM L3 hardware not enabled\n");
		return -ENODEV;
	}

	for (i = 0; i < LUT_MAX_ENTRIES; i++) {
		data = readl_relaxed(osm_l3.base + REG_FREQ_LUT +
				     i * LUT_ROW_SIZE);
		src = FIELD_GET(LUT_SRC, data);
		lval = FIELD_GET(LUT_L_VAL, data);
		if (src)
			freq = xo_rate * lval;
		else
			freq = hw_rate;

		/*
		 * Two of the same frequencies with the same core counts means
		 * end of table
		 */
		if (i > 0 && prev_freq == freq)
			break;

		osm_l3.lut_tables[i] = freq;
		prev_freq = freq;
	}
	osm_l3.max_state = i;

	dev_dbg(&pdev->dev, "QCOM OSM L3 initialised\n");

	return 0;
}
EXPORT_SYMBOL_GPL(qcom_osm_l3_init);

MODULE_DESCRIPTION("Qualcomm OSM L3 interconnect driver");
MODULE_LICENSE("GPL v2");
