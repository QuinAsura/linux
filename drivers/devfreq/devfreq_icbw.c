// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
 */

#include <linux/devfreq.h>
#include <linux/interconnect.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>

struct icbw_data {
	struct devfreq *df;
	struct icc_path *path;
	u32 cur_ab;
	u32 cur_pb;
};

static int icbw_target(struct device *dev, unsigned long *freq, u32 flags)
{
	struct dev_pm_opp *opp;
	struct icbw_data *data = dev_get_drvdata(dev);
	u32 new_pb, new_ab;
	int ret;

	opp = devfreq_recommended_opp(dev, freq, flags);
	if (IS_ERR(opp))
		return PTR_ERR(opp);

	/* Get avg and peak bandwidth */
	new_ab = dev_pm_opp_get_avg_bw(opp);
	new_pb = dev_pm_opp_get_peak_bw(opp);
	dev_pm_opp_put(opp);

	if (data->cur_pb == new_pb && data->cur_ab == new_ab)
		return 0;

	dev_dbg(dev, "BW icc: AB: %u PB: %u\n", new_ab, new_pb);

	ret = icc_set_bw(data->path, new_ab, new_pb);
	if (ret) {
		dev_err(dev, "bandwidth request failed (%d)\n", ret);
	} else {
		data->cur_pb = new_pb;
		data->cur_ab = new_ab;
	}

	return ret;
}

static int devfreq_icbw_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct devfreq_dev_profile *profile;
	struct devfreq_passive_data *passive_data;
	struct icbw_data *data;
	int ret;

	data = devm_kzalloc(dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	dev_set_drvdata(dev, data);

	passive_data = devm_kzalloc(dev, sizeof(*passive_data), GFP_KERNEL);
	if (!passive_data)
		return -ENOMEM;

	passive_data->cpufreq_type = true;

	profile = devm_kzalloc(dev, sizeof(*profile), GFP_KERNEL);
	if (!profile)
		return -ENOMEM;

	profile->target = icbw_target;

	data->path = of_icc_get(dev, NULL);
	if (IS_ERR(data->path)) {
		dev_err(dev, "Unable to register interconnect path\n");
		return PTR_ERR(data->path);
	}

	ret = dev_pm_opp_of_add_table(dev);
	if (ret) {
		dev_err(dev, "Couldn't find OPP table\n");
		goto err_icc;
	}

	data->df = devfreq_add_device(dev, profile,
				      DEVFREQ_GOV_PASSIVE, passive_data);
	if (IS_ERR(data->df)) {
		ret = PTR_ERR(data->df);
		goto err_opp_table;
	}

	return 0;

err_opp_table:
	dev_pm_opp_of_remove_table(dev);
err_icc:
	icc_put(data->path);
	return ret;
}

static int devfreq_icbw_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct icbw_data *data = dev_get_drvdata(dev);

	devfreq_remove_device(data->df);
	icc_put(data->path);
	return 0;
}

static const struct of_device_id icbw_match_table[] = {
	{ .compatible = "devfreq-icbw" },
	{}
};
MODULE_DEVICE_TABLE(of, icbw_match_table);

static struct platform_driver icbw_driver = {
	.probe = devfreq_icbw_probe,
	.remove = devfreq_icbw_remove,
	.driver = {
		.name = "devfreq-icbw",
		.of_match_table = icbw_match_table,
	},
};
module_platform_driver(icbw_driver);

MODULE_DESCRIPTION("Interconnect bandwidth voting driver");
MODULE_LICENSE("GPL v2");
