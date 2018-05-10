// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018, The Linux Foundation. All rights reserved. */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/bitops.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/of_regulator.h>
#include <soc/qcom/cmd-db.h>
#include <soc/qcom/rpmh.h>
#include <dt-bindings/regulator/qcom,rpmh-regulator.h>

/**
 * enum rpmh_regulator_type - supported RPMh accelerator types
 * %RPMH_REGULATOR_TYPE_VRM:	RPMh VRM accelerator which supports voting on
 *				enable, voltage, mode, and headroom voltage of
 *				LDO, SMPS, VS, and BOB type PMIC regulators.
 * %RPMH_REGULATOR_TYPE_XOB:	RPMh XOB accelerator which supports voting on
 *				the enable state of PMIC regulators.
 */
enum rpmh_regulator_type {
	RPMH_REGULATOR_TYPE_VRM,
	RPMH_REGULATOR_TYPE_XOB,
};

/* Min and max limits of VRM resource request parameters */
#define RPMH_VRM_MIN_UV			0
#define RPMH_VRM_MAX_UV			8191000

#define RPMH_VRM_HEADROOM_MIN_UV	0
#define RPMH_VRM_HEADROOM_MAX_UV	511000

#define RPMH_VRM_MODE_MIN		0
#define RPMH_VRM_MODE_MAX		7

/* Register offsets: */
#define RPMH_REGULATOR_REG_VRM_VOLTAGE		0x0
#define RPMH_REGULATOR_REG_ENABLE		0x4
#define RPMH_REGULATOR_REG_VRM_MODE		0x8
#define RPMH_REGULATOR_REG_VRM_HEADROOM		0xC

/* Enable register values: */
#define RPMH_REGULATOR_DISABLE			0x0
#define RPMH_REGULATOR_ENABLE			0x1

/* Number of unique hardware modes supported: */
#define RPMH_REGULATOR_MODE_COUNT		5

/**
 * struct rpmh_regulator_mode - RPMh VRM mode attributes
 * @pmic_mode:			Raw PMIC mode value written into VRM mode voting
 *				register (i.e. RPMH_REGULATOR_MODE_*)
 * @framework_mode:		Regulator framework mode value
 *				(i.e. REGULATOR_MODE_*)
 * @min_load_ua:		The minimum load current in microamps which
 *				would utilize this mode
 *
 * Software selects the lowest mode for which aggr_load_ua >= min_load_ua.
 */
struct rpmh_regulator_mode {
	u32				pmic_mode;
	u32				framework_mode;
	int				min_load_ua;
};

/**
 * struct rpmh_vreg_hw_data - RPMh regulator hardware configurations
 * @mode_map:			Array of size RPMH_REGULATOR_MODE_COUNT which
 *				maps RPMH_REGULATOR_MODE_* indices into PMIC
 *				mode and regulator framework mode that are
 *				supported by this PMIC regulator type
 * @voltage_range:		The single range of voltages supported by this
 *				PMIC regulator type
 * @n_voltages:			The number of unique voltage set points defined
 *				by voltage_range
 * @of_map_mode:		Maps an RPMH_REGULATOR_MODE_* mode value defined
 *				in device tree to a regulator framework mode
 */
struct rpmh_vreg_hw_data {
	const struct rpmh_regulator_mode	*mode_map;
	const struct regulator_linear_range	*voltage_range;
	int					n_voltages;
	unsigned int			      (*of_map_mode)(unsigned int mode);
};

struct rpmh_pmic;

/**
 * struct rpmh_vreg - individual rpmh regulator data structure encapsulating a
 *		single regulator device
 * @of_node:			Device tree node pointer of the regulator
 * @pmic:			Pointer to the PMIC containing the regulator
 * @resource_name:		Name of the RPMh regulator resource which is
 *				mapped to an RPMh accelerator address via
 *				command DB.  This name must match to one that is
 *				defined by the bootloader.
 * @addr:			Base address of the regulator resource within
 *				an RPMh accelerator
 * @rdesc:			Regulator descriptor
 * @rdev:			Regulator device pointer returned by
 *				devm_regulator_register()
 * @hw_data:			PMIC regulator configuration data for this RPMh
 *				regulator
 * @regulator_type:		RPMh accelerator type for this regulator
 *				resource
 * @always_wait_for_ack:	Boolean flag indicating if a request must always
 *				wait for an ACK from RPMh before continuing even
 *				if it corresponds to a strictly lower power
 *				state (e.g. enabled --> disabled).
 * @mode_map:			An array of modes which may be configured at
 *				runtime by setting the load current
 * @mode_count:			The number of entries in the mode_map array.
 * @enabled:			Boolean indicating if the regulator is enabled
 *				or not
 * @voltage:			RPMh VRM regulator voltage in microvolts
 * @mode:			RPMh VRM regulator current framework mode
 * @headroom_voltage:		RPMh VRM regulator minimum headroom voltage
 *				required
 */
struct rpmh_vreg {
	struct device_node		*of_node;
	struct rpmh_pmic		*pmic;
	const char			*resource_name;
	u32				addr;
	struct regulator_desc		rdesc;
	struct regulator_dev		*rdev;
	const struct rpmh_vreg_hw_data	*hw_data;
	enum rpmh_regulator_type	regulator_type;
	bool				always_wait_for_ack;
	struct rpmh_regulator_mode	*mode_map;
	int				mode_count;

	bool				enabled;
	int				voltage;
	unsigned int			mode;
	int				headroom_voltage;
};

/**
 * struct rpmh_vreg_init_data - initialization data for an RPMh regulator
 * @name:			Name for the regulator which also corresponds
 *				to the device tree subnode name of the regulator
 * @resource_name_base:		RPMh regulator resource name prefix.  E.g.
 *				"ldo" for RPMh resource "ldoa1".
 * @supply_name:		Parent supply regulator name
 * @id:				Regulator number within the PMIC
 * @regulator_type:		RPMh accelerator type used to manage this
 *				regulator
 * @hw_data:			Configuration data for this PMIC regulator type
 */
struct rpmh_vreg_init_data {
	const char			*name;
	const char			*resource_name_base;
	const char			*supply_name;
	int				id;
	enum rpmh_regulator_type	regulator_type;
	const struct rpmh_vreg_hw_data	*hw_data;
};

/**
 * struct rpmh_pmic_init_data - initialization data for a PMIC
 * @name:			PMIC name
 * @vreg_data:			Array of data for each regulator in the PMIC
 * @count:			Number of entries in vreg_data
 */
struct rpmh_pmic_init_data {
	const char				*name;
	const struct rpmh_vreg_init_data	*vreg_data;
	int					count;
};

/**
 * struct rpmh_pmic - top level data structure of all regulators found on a PMIC
 * @dev:			Device pointer of the PMIC device for the
 *				regulators
 * @rpmh_client:		Handle used for rpmh communications
 * @vreg:			Array of rpmh regulator structs representing the
 *				individual regulators found on this PMIC chip
 *				which are configured via device tree.
 * @vreg_count:			The number of entries in the vreg array.
 * @pmic_id:			Letter used to identify this PMIC within the
 *				system.  This is dictated by boot loader
 *				specifications on a given target.
 * @init_data:			Pointer to the matched PMIC initialization data
 */
struct rpmh_pmic {
	struct device				*dev;
	struct rpmh_client			*rpmh_client;
	struct rpmh_vreg			*vreg;
	int					vreg_count;
	const char				*pmic_id;
	const struct rpmh_pmic_init_data	*init_data;
};

#define vreg_err(vreg, message, ...) \
	pr_err("%s %s: " message, (vreg)->pmic->init_data->name, \
		(vreg)->rdesc.name, ##__VA_ARGS__)
#define vreg_info(vreg, message, ...) \
	pr_info("%s %s: " message, (vreg)->pmic->init_data->name, \
		(vreg)->rdesc.name, ##__VA_ARGS__)
#define vreg_debug(vreg, message, ...) \
	pr_debug("%s %s: " message, (vreg)->pmic->init_data->name, \
		(vreg)->rdesc.name, ##__VA_ARGS__)

/**
 * rpmh_regulator_send_request() - send the request to RPMh
 * @vreg:		Pointer to the RPMh regulator
 * @cmd:		RPMh commands to send
 * @count:		Size of cmd array
 * @wait_for_ack:	Boolean indicating if execution must wait until the
 *			request has been acknowledged as complete
 *
 * Return: 0 on success, errno on failure
 */
static int rpmh_regulator_send_request(struct rpmh_vreg *vreg,
			struct tcs_cmd *cmd, int count, bool wait_for_ack)
{
	int ret;

	if (wait_for_ack || vreg->always_wait_for_ack)
		ret = rpmh_write(vreg->pmic->rpmh_client,
				RPMH_ACTIVE_ONLY_STATE, cmd, count);
	else
		ret = rpmh_write_async(vreg->pmic->rpmh_client,
				RPMH_ACTIVE_ONLY_STATE, cmd, count);
	if (ret < 0)
		vreg_err(vreg, "rpmh_write() failed, ret=%d\n", ret);

	return ret;
}

static int rpmh_regulator_is_enabled(struct regulator_dev *rdev)
{
	struct rpmh_vreg *vreg = rdev_get_drvdata(rdev);

	return vreg->enabled;
}

static int rpmh_regulator_enable(struct regulator_dev *rdev)
{
	struct rpmh_vreg *vreg = rdev_get_drvdata(rdev);
	struct tcs_cmd cmd = {
		.addr = vreg->addr + RPMH_REGULATOR_REG_ENABLE,
		.data = RPMH_REGULATOR_ENABLE,
	};
	int ret;

	if (vreg->enabled)
		return 0;

	ret = rpmh_regulator_send_request(vreg, &cmd, 1, true);
	if (ret < 0) {
		vreg_err(vreg, "enable failed, ret=%d\n", ret);
		return ret;
	}

	vreg->enabled = true;

	return 0;
}

static int rpmh_regulator_disable(struct regulator_dev *rdev)
{
	struct rpmh_vreg *vreg = rdev_get_drvdata(rdev);
	struct tcs_cmd cmd = {
		.addr = vreg->addr + RPMH_REGULATOR_REG_ENABLE,
		.data = RPMH_REGULATOR_DISABLE,
	};
	int ret;

	if (!vreg->enabled)
		return 0;

	ret = rpmh_regulator_send_request(vreg, &cmd, 1, false);
	if (ret < 0) {
		vreg_err(vreg, "disable failed, ret=%d\n", ret);
		return ret;
	}

	vreg->enabled = false;

	return 0;
}

static int rpmh_regulator_vrm_set_voltage(struct regulator_dev *rdev,
				int min_uv, int max_uv, unsigned int *selector)
{
	struct rpmh_vreg *vreg = rdev_get_drvdata(rdev);
	struct tcs_cmd cmd = {
		.addr = vreg->addr + RPMH_REGULATOR_REG_VRM_VOLTAGE,
	};
	const struct regulator_linear_range *range;
	int mv, uv, ret;
	bool wait_for_ack;

	mv = DIV_ROUND_UP(min_uv, 1000);
	uv = mv * 1000;
	if (uv > max_uv) {
		vreg_err(vreg, "no set points available in range %d-%d uV\n",
			min_uv, max_uv);
		return -EINVAL;
	}

	range = vreg->hw_data->voltage_range;
	*selector = DIV_ROUND_UP(uv - range->min_uV, range->uV_step);

	if (uv == vreg->voltage)
		return 0;

	wait_for_ack = uv > vreg->voltage || max_uv < vreg->voltage;
	cmd.data = mv;

	ret = rpmh_regulator_send_request(vreg, &cmd, 1, wait_for_ack);
	if (ret < 0) {
		vreg_err(vreg, "set voltage=%d uV failed, ret=%d\n", uv, ret);
		return ret;
	}

	vreg->voltage = uv;

	return 0;
}

static int rpmh_regulator_vrm_get_voltage(struct regulator_dev *rdev)
{
	struct rpmh_vreg *vreg = rdev_get_drvdata(rdev);

	return vreg->voltage;
}

static int rpmh_regulator_vrm_set_mode(struct regulator_dev *rdev,
					unsigned int mode)
{
	struct rpmh_vreg *vreg = rdev_get_drvdata(rdev);
	struct tcs_cmd cmd = {
		.addr = vreg->addr + RPMH_REGULATOR_REG_VRM_MODE,
	};
	int i, ret;

	if (mode == vreg->mode)
		return 0;

	for (i = 0; i < RPMH_REGULATOR_MODE_COUNT; i++)
		if (vreg->hw_data->mode_map[i].framework_mode == mode)
			break;
	if (i >= RPMH_REGULATOR_MODE_COUNT) {
		vreg_err(vreg, "invalid mode=%u\n", mode);
		return -EINVAL;
	}

	cmd.data = vreg->hw_data->mode_map[i].pmic_mode;

	ret = rpmh_regulator_send_request(vreg, &cmd, 1,
					  mode < vreg->mode || !vreg->mode);
	if (ret < 0) {
		vreg_err(vreg, "set mode=%u failed, ret=%d\n", cmd.data, ret);
		return ret;
	}

	vreg->mode = mode;

	return ret;
}

static unsigned int rpmh_regulator_vrm_get_mode(struct regulator_dev *rdev)
{
	struct rpmh_vreg *vreg = rdev_get_drvdata(rdev);

	return vreg->mode;
}

/**
 * rpmh_regulator_vrm_set_load() - set the PMIC mode based upon the maximum load
 *		required from the VRM rpmh-regulator
 * @rdev:		Regulator device pointer for the rpmh-regulator
 * @load_ua:		Maximum current required from all consumers in microamps
 *
 * This function is passed as a callback function into the regulator ops that
 * are registered for each VRM rpmh-regulator device.
 *
 * This function sets the mode of the regulator to that which has the highest
 * min support load less than or equal to load_ua.  Example:
 *	mode_count = 3
 *	mode_map[].min_load_ua = 0, 100000, 6000000
 *
 *	load_ua = 10000   --> i = 0
 *	load_ua = 250000  --> i = 1
 *	load_ua = 7000000 --> i = 2
 *
 * Return: 0 on success, errno on failure
 */
static int rpmh_regulator_vrm_set_load(struct regulator_dev *rdev, int load_ua)
{
	struct rpmh_vreg *vreg = rdev_get_drvdata(rdev);
	int i;

	/* No need to check element 0 as it will be the default. */
	for (i = vreg->mode_count - 1; i > 0; i--)
		if (vreg->mode_map[i].min_load_ua <= load_ua)
			break;

	return rpmh_regulator_vrm_set_mode(rdev,
					   vreg->mode_map[i].framework_mode);
}

static const struct regulator_ops rpmh_regulator_vrm_ops = {
	.enable			= rpmh_regulator_enable,
	.disable		= rpmh_regulator_disable,
	.is_enabled		= rpmh_regulator_is_enabled,
	.set_voltage		= rpmh_regulator_vrm_set_voltage,
	.get_voltage		= rpmh_regulator_vrm_get_voltage,
	.list_voltage		= regulator_list_voltage_linear_range,
	.set_mode		= rpmh_regulator_vrm_set_mode,
	.get_mode		= rpmh_regulator_vrm_get_mode,
	.set_load		= rpmh_regulator_vrm_set_load,
};

static const struct regulator_ops rpmh_regulator_xob_ops = {
	.enable			= rpmh_regulator_enable,
	.disable		= rpmh_regulator_disable,
	.is_enabled		= rpmh_regulator_is_enabled,
};

static const struct regulator_ops *rpmh_regulator_ops[] = {
	[RPMH_REGULATOR_TYPE_VRM]	= &rpmh_regulator_vrm_ops,
	[RPMH_REGULATOR_TYPE_XOB]	= &rpmh_regulator_xob_ops,
};

/**
 * rpmh_regulator_parse_vrm_modes() - parse the supported mode configurations
 *		for a VRM RPMh resource from device tree
 * vreg:		Pointer to the rpmh regulator resource
 *
 * This function initializes the mode[] array of vreg based upon the values
 * of optional device tree properties.
 *
 * Return: 0 on success, errno on failure
 */
static int rpmh_regulator_parse_vrm_modes(struct rpmh_vreg *vreg)
{
	struct device_node *node = vreg->of_node;
	const struct rpmh_regulator_mode *map;
	const char *prop;
	int i, len, ret;
	u32 *buf;

	map = vreg->hw_data->mode_map;
	if (!map)
		return 0;

	/* qcom,allowed-modes is optional */
	prop = "qcom,allowed-modes";
	len = of_property_count_elems_of_size(node, prop, sizeof(u32));
	if (len < 0)
		return 0;

	vreg->mode_map = devm_kcalloc(vreg->pmic->dev, len,
				sizeof(*vreg->mode_map), GFP_KERNEL);
	if (!vreg->mode_map)
		return -ENOMEM;
	vreg->mode_count = len;

	buf = kcalloc(len, sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = of_property_read_u32_array(node, prop, buf, len);
	if (ret < 0) {
		vreg_err(vreg, "unable to read %s, ret=%d\n",
			prop, ret);
		goto done;
	}

	for (i = 0; i < len; i++) {
		if (buf[i] >= RPMH_REGULATOR_MODE_COUNT
		    || !map[buf[i]].framework_mode) {
			vreg_err(vreg, "element %d of %s = %u is invalid for this regulator\n",
				i, prop, buf[i]);
			ret = -EINVAL;
			goto done;
		}

		vreg->mode_map[i].pmic_mode = map[buf[i]].pmic_mode;
		vreg->mode_map[i].framework_mode = map[buf[i]].framework_mode;

		if (i > 0 && vreg->mode_map[i].pmic_mode
				<= vreg->mode_map[i - 1].pmic_mode) {
			vreg_err(vreg, "%s elements are not in ascending order\n",
				prop);
			ret = -EINVAL;
			goto done;
		}
	}

	prop = "qcom,mode-threshold-currents";
	ret = of_property_read_u32_array(node, prop, buf, len);
	if (ret < 0) {
		vreg_err(vreg, "unable to read %s, ret=%d\n",
			prop, ret);
		goto done;
	}

	for (i = 0; i < len; i++) {
		vreg->mode_map[i].min_load_ua = buf[i];

		if (i > 0 && vreg->mode_map[i].min_load_ua
				<= vreg->mode_map[i - 1].min_load_ua) {
			vreg_err(vreg, "%s elements are not in ascending order\n",
				prop);
			ret = -EINVAL;
			goto done;
		}
	}

done:
	kfree(buf);
	return ret;
}

/**
 * rpmh_regulator_allocate_vreg() - allocate space for the regulators associated
 *		with the PMIC and initialize important pointers for each
 *		regulator
 * @pmic:		Pointer to the RPMh regulator PMIC
 *
 * Return: 0 on success, errno on failure
 */
static int rpmh_regulator_allocate_vreg(struct rpmh_pmic *pmic)
{
	struct device_node *node;
	int i;

	pmic->vreg_count = of_get_available_child_count(pmic->dev->of_node);
	if (pmic->vreg_count == 0) {
		dev_err(pmic->dev, "could not find any regulator subnodes\n");
		return -ENODEV;
	}

	pmic->vreg = devm_kcalloc(pmic->dev, pmic->vreg_count,
			sizeof(*pmic->vreg), GFP_KERNEL);
	if (!pmic->vreg)
		return -ENOMEM;

	i = 0;
	for_each_available_child_of_node(pmic->dev->of_node, node) {
		pmic->vreg[i].of_node = node;
		pmic->vreg[i].pmic = pmic;

		i++;
	}

	return 0;
}

/**
 * rpmh_regulator_load_default_parameters() - initialize the RPMh resource
 *		request for this regulator based on optional device tree
 *		properties
 * @vreg:		Pointer to the RPMh regulator
 *
 * Return: 0 on success, errno on failure
 */
static int rpmh_regulator_load_default_parameters(struct rpmh_vreg *vreg)
{
	struct tcs_cmd cmd[2] = { };
	const char *prop;
	int cmd_count = 0;
	int ret;
	u32 temp;

	if (vreg->regulator_type == RPMH_REGULATOR_TYPE_VRM) {
		prop = "qcom,headroom-voltage";
		ret = of_property_read_u32(vreg->of_node, prop, &temp);
		if (!ret) {
			if (temp < RPMH_VRM_HEADROOM_MIN_UV ||
			    temp > RPMH_VRM_HEADROOM_MAX_UV) {
				vreg_err(vreg, "%s=%u is invalid\n",
					prop, temp);
				return -EINVAL;
			}
			vreg->headroom_voltage = temp;

			cmd[cmd_count].addr
				= vreg->addr + RPMH_REGULATOR_REG_VRM_HEADROOM;
			cmd[cmd_count++].data
				= DIV_ROUND_UP(vreg->headroom_voltage, 1000);
		}

		prop = "qcom,regulator-initial-voltage";
		ret = of_property_read_u32(vreg->of_node, prop, &temp);
		if (!ret) {
			if (temp < RPMH_VRM_MIN_UV || temp > RPMH_VRM_MAX_UV) {
				vreg_err(vreg, "%s=%u is invalid\n",
					prop, temp);
				return -EINVAL;
			}
			vreg->voltage = temp;

			cmd[cmd_count].addr
				= vreg->addr + RPMH_REGULATOR_REG_VRM_VOLTAGE;
			cmd[cmd_count++].data
				= DIV_ROUND_UP(vreg->voltage, 1000);
		}
	}

	if (cmd_count) {
		ret = rpmh_regulator_send_request(vreg, cmd, cmd_count, true);
		if (ret < 0) {
			vreg_err(vreg, "could not send default config, ret=%d\n",
				ret);
			return ret;
		}
	}

	return 0;
}

/**
 * rpmh_regulator_init_vreg() - initialize all abbributes of an rpmh-regulator
 * @vreg:		Pointer to the RPMh regulator
 *
 * Return: 0 on success, errno on failure
 */
static int rpmh_regulator_init_vreg(struct rpmh_vreg *vreg)
{
	struct device *dev = vreg->pmic->dev;
	struct regulator_config reg_config = {};
	const struct rpmh_vreg_init_data *rpmh_data = NULL;
	const char *type_name = NULL;
	enum rpmh_regulator_type type;
	struct regulator_init_data *init_data;
	int ret, i;

	for (i = 0; i < vreg->pmic->init_data->count; i++) {
		if (!strcmp(vreg->pmic->init_data->vreg_data[i].name,
			    vreg->of_node->name)) {
			rpmh_data = &vreg->pmic->init_data->vreg_data[i];
			break;
		}
	}

	if (!rpmh_data) {
		dev_err(dev, "Unknown regulator %s for %s RPMh regulator PMIC\n",
			vreg->of_node->name, vreg->pmic->init_data->name);
		return -EINVAL;
	}

	vreg->resource_name = devm_kasprintf(dev, GFP_KERNEL, "%s%s%d",
			rpmh_data->resource_name_base, vreg->pmic->pmic_id,
			rpmh_data->id);
	if (!vreg->resource_name)
		return -ENOMEM;

	vreg->addr = cmd_db_read_addr(vreg->resource_name);
	if (!vreg->addr) {
		vreg_err(vreg, "could not find RPMh address for resource %s\n",
			vreg->resource_name);
		return -ENODEV;
	}

	vreg->rdesc.name = rpmh_data->name;
	vreg->rdesc.supply_name = rpmh_data->supply_name;
	vreg->regulator_type = rpmh_data->regulator_type;
	vreg->hw_data = rpmh_data->hw_data;

	if (rpmh_data->hw_data->voltage_range) {
		vreg->rdesc.linear_ranges = rpmh_data->hw_data->voltage_range;
		vreg->rdesc.n_linear_ranges = 1;
		vreg->rdesc.n_voltages = rpmh_data->hw_data->n_voltages;
	}

	/* Optional override for the default RPMh accelerator type */
	ret = of_property_read_string(vreg->of_node, "qcom,rpmh-resource-type",
					&type_name);
	if (!ret) {
		if (!strcmp("vrm", type_name)) {
			vreg->regulator_type = RPMH_REGULATOR_TYPE_VRM;
		} else if (!strcmp("xob", type_name)) {
			vreg->regulator_type = RPMH_REGULATOR_TYPE_XOB;
		} else {
			vreg_err(vreg, "Unknown RPMh accelerator type %s\n",
				type_name);
			return -EINVAL;
		}
	}

	type = vreg->regulator_type;

	if (type == RPMH_REGULATOR_TYPE_VRM) {
		ret = rpmh_regulator_parse_vrm_modes(vreg);
		if (ret < 0) {
			vreg_err(vreg, "could not parse vrm mode mapping, ret=%d\n",
				ret);
			return ret;
		}
	}

	vreg->always_wait_for_ack = of_property_read_bool(vreg->of_node,
						"qcom,always-wait-for-ack");

	vreg->rdesc.owner	= THIS_MODULE;
	vreg->rdesc.type	= REGULATOR_VOLTAGE;
	vreg->rdesc.ops		= rpmh_regulator_ops[type];
	vreg->rdesc.of_map_mode	= vreg->hw_data->of_map_mode;

	init_data = of_get_regulator_init_data(dev, vreg->of_node,
						&vreg->rdesc);
	if (!init_data)
		return -ENOMEM;

	if (type == RPMH_REGULATOR_TYPE_XOB && init_data->constraints.min_uV) {
		vreg->rdesc.fixed_uV = init_data->constraints.min_uV;
		init_data->constraints.apply_uV = 0;
		vreg->rdesc.n_voltages = 1;
	}

	if (vreg->hw_data->mode_map) {
		init_data->constraints.valid_ops_mask |= REGULATOR_CHANGE_MODE;
		for (i = 0; i < RPMH_REGULATOR_MODE_COUNT; i++)
			init_data->constraints.valid_modes_mask
				|= vreg->hw_data->mode_map[i].framework_mode;
	}

	reg_config.dev			= dev;
	reg_config.init_data		= init_data;
	reg_config.of_node		= vreg->of_node;
	reg_config.driver_data		= vreg;

	ret = rpmh_regulator_load_default_parameters(vreg);
	if (ret < 0) {
		vreg_err(vreg, "unable to load default parameters, ret=%d\n",
			ret);
		return ret;
	}

	vreg->rdev = devm_regulator_register(dev, &vreg->rdesc, &reg_config);
	if (IS_ERR(vreg->rdev)) {
		ret = PTR_ERR(vreg->rdev);
		vreg->rdev = NULL;
		vreg_err(vreg, "devm_regulator_register() failed, ret=%d\n",
			ret);
		return ret;
	}

	vreg_debug(vreg, "registered RPMh resource %s @ 0x%05X\n",
		vreg->resource_name, vreg->addr);

	return ret;
}

/*
 * Mappings from RPMh generic modes to VRM accelerator modes and regulator
 * framework modes for each regulator type.
 */
static const struct rpmh_regulator_mode
rpmh_regulator_mode_map_pmic4_ldo[RPMH_REGULATOR_MODE_COUNT] = {
	[RPMH_REGULATOR_MODE_RET] = {
		.pmic_mode = 4,
		.framework_mode = REGULATOR_MODE_STANDBY,
	},
	[RPMH_REGULATOR_MODE_LPM] = {
		.pmic_mode = 5,
		.framework_mode = REGULATOR_MODE_IDLE,
	},
	[RPMH_REGULATOR_MODE_HPM] = {
		.pmic_mode = 7,
		.framework_mode = REGULATOR_MODE_FAST,
	},
};

static const struct rpmh_regulator_mode
rpmh_regulator_mode_map_pmic4_smps[RPMH_REGULATOR_MODE_COUNT] = {
	[RPMH_REGULATOR_MODE_RET] = {
		.pmic_mode = 4,
		.framework_mode = REGULATOR_MODE_STANDBY,
	},
	[RPMH_REGULATOR_MODE_LPM] = {
		.pmic_mode = 5,
		.framework_mode = REGULATOR_MODE_IDLE,
	},
	[RPMH_REGULATOR_MODE_AUTO] = {
		.pmic_mode = 6,
		.framework_mode = REGULATOR_MODE_NORMAL,
	},
	[RPMH_REGULATOR_MODE_HPM] = {
		.pmic_mode = 7,
		.framework_mode = REGULATOR_MODE_FAST,
	},
};

static const struct rpmh_regulator_mode
rpmh_regulator_mode_map_pmic4_bob[RPMH_REGULATOR_MODE_COUNT] = {
	[RPMH_REGULATOR_MODE_PASS] = {
		.pmic_mode = 0,
		.framework_mode = REGULATOR_MODE_STANDBY,
	},
	[RPMH_REGULATOR_MODE_LPM] = {
		.pmic_mode = 1,
		.framework_mode = REGULATOR_MODE_IDLE,
	},
	[RPMH_REGULATOR_MODE_AUTO] = {
		.pmic_mode = 2,
		.framework_mode = REGULATOR_MODE_NORMAL,
	},
	[RPMH_REGULATOR_MODE_HPM] = {
		.pmic_mode = 3,
		.framework_mode = REGULATOR_MODE_FAST,
	},
};

static unsigned int rpmh_regulator_vrm_of_map_mode(unsigned int mode,
		const struct rpmh_regulator_mode *mode_map)
{
	if (mode > RPMH_REGULATOR_MODE_COUNT)
		return -EINVAL;
	else if (mode_map[mode].framework_mode == 0)
		return -EINVAL;

	return mode_map[mode].framework_mode;
}

static unsigned int rpmh_regulator_pmic4_ldo_of_map_mode(unsigned int mode)
{
	return rpmh_regulator_vrm_of_map_mode(mode,
					rpmh_regulator_mode_map_pmic4_ldo);
}

static unsigned int rpmh_regulator_pmic4_smps_of_map_mode(unsigned int mode)
{
	return rpmh_regulator_vrm_of_map_mode(mode,
					rpmh_regulator_mode_map_pmic4_smps);
}

static unsigned int rpmh_regulator_pmic4_bob_of_map_mode(unsigned int mode)
{
	return rpmh_regulator_vrm_of_map_mode(mode,
					rpmh_regulator_mode_map_pmic4_bob);
}

static const struct rpmh_vreg_hw_data pmic4_pldo_hw_data = {
	.voltage_range = &(const struct regulator_linear_range)
			REGULATOR_LINEAR_RANGE(1664000, 0, 255, 8000),
	.n_voltages = 256,
	.mode_map = rpmh_regulator_mode_map_pmic4_ldo,
	.of_map_mode = rpmh_regulator_pmic4_ldo_of_map_mode,
};

static const struct rpmh_vreg_hw_data pmic4_pldo_lv_hw_data = {
	.voltage_range = &(const struct regulator_linear_range)
			REGULATOR_LINEAR_RANGE(1256000, 0, 127, 8000),
	.n_voltages = 128,
	.mode_map = rpmh_regulator_mode_map_pmic4_ldo,
	.of_map_mode = rpmh_regulator_pmic4_ldo_of_map_mode,
};

static const struct rpmh_vreg_hw_data pmic4_nldo_hw_data = {
	.voltage_range = &(const struct regulator_linear_range)
			REGULATOR_LINEAR_RANGE(312000, 0, 127, 8000),
	.n_voltages = 128,
	.mode_map = rpmh_regulator_mode_map_pmic4_ldo,
	.of_map_mode = rpmh_regulator_pmic4_ldo_of_map_mode,
};

static const struct rpmh_vreg_hw_data pmic4_hfsmps3_hw_data = {
	.voltage_range = &(const struct regulator_linear_range)
			REGULATOR_LINEAR_RANGE(320000, 0, 215, 8000),
	.n_voltages = 216,
	.mode_map = rpmh_regulator_mode_map_pmic4_smps,
	.of_map_mode = rpmh_regulator_pmic4_smps_of_map_mode,
};

static const struct rpmh_vreg_hw_data pmic4_ftsmps426_hw_data = {
	.voltage_range = &(const struct regulator_linear_range)
			REGULATOR_LINEAR_RANGE(320000, 0, 258, 4000),
	.n_voltages = 259,
	.mode_map = rpmh_regulator_mode_map_pmic4_smps,
	.of_map_mode = rpmh_regulator_pmic4_smps_of_map_mode,
};

static const struct rpmh_vreg_hw_data pmic4_bob_hw_data = {
	.voltage_range = &(const struct regulator_linear_range)
			REGULATOR_LINEAR_RANGE(1824000, 0, 83, 32000),
	.n_voltages = 84,
	.mode_map = rpmh_regulator_mode_map_pmic4_bob,
	.of_map_mode = rpmh_regulator_pmic4_bob_of_map_mode,
};

static const struct rpmh_vreg_hw_data pmic4_lvs_hw_data = {
	/* LVS hardware does not support voltage or mode configuration. */
};

#define RPMH_VREG(_name, _hw_type, _type, _base_name, _id, _supply_name) \
{ \
	.name = #_name, \
	.hw_data = &_hw_type##_hw_data, \
	.regulator_type = RPMH_REGULATOR_TYPE_##_type, \
	.resource_name_base = #_base_name, \
	.id = _id, \
	.supply_name = #_supply_name, \
}

static const struct rpmh_vreg_init_data pm8998_vreg_data[] = {
	RPMH_VREG(smps1,  pmic4_ftsmps426, VRM, smp,  1, vdd_s1),
	RPMH_VREG(smps2,  pmic4_ftsmps426, VRM, smp,  2, vdd_s2),
	RPMH_VREG(smps3,  pmic4_hfsmps3,   VRM, smp,  3, vdd_s3),
	RPMH_VREG(smps4,  pmic4_hfsmps3,   VRM, smp,  4, vdd_s4),
	RPMH_VREG(smps5,  pmic4_hfsmps3,   VRM, smp,  5, vdd_s5),
	RPMH_VREG(smps6,  pmic4_ftsmps426, VRM, smp,  6, vdd_s6),
	RPMH_VREG(smps7,  pmic4_ftsmps426, VRM, smp,  7, vdd_s7),
	RPMH_VREG(smps8,  pmic4_ftsmps426, VRM, smp,  8, vdd_s8),
	RPMH_VREG(smps9,  pmic4_ftsmps426, VRM, smp,  9, vdd_s9),
	RPMH_VREG(smps10, pmic4_ftsmps426, VRM, smp, 10, vdd_s10),
	RPMH_VREG(smps11, pmic4_ftsmps426, VRM, smp, 11, vdd_s11),
	RPMH_VREG(smps12, pmic4_ftsmps426, VRM, smp, 12, vdd_s12),
	RPMH_VREG(smps13, pmic4_ftsmps426, VRM, smp, 13, vdd_s13),
	RPMH_VREG(ldo1,   pmic4_nldo,      VRM, ldo,  1, vdd_l1_l27),
	RPMH_VREG(ldo2,   pmic4_nldo,      VRM, ldo,  2, vdd_l2_l8_l17),
	RPMH_VREG(ldo3,   pmic4_nldo,      VRM, ldo,  3, vdd_l3_l11),
	RPMH_VREG(ldo4,   pmic4_nldo,      VRM, ldo,  4, vdd_l4_l5),
	RPMH_VREG(ldo5,   pmic4_nldo,      VRM, ldo,  5, vdd_l4_l5),
	RPMH_VREG(ldo6,   pmic4_pldo,      VRM, ldo,  6, vdd_l6),
	RPMH_VREG(ldo7,   pmic4_pldo_lv,   VRM, ldo,  7, vdd_l7_l12_l14_l15),
	RPMH_VREG(ldo8,   pmic4_nldo,      VRM, ldo,  8, vdd_l2_l8_l17),
	RPMH_VREG(ldo9,   pmic4_pldo,      VRM, ldo,  9, vdd_l9),
	RPMH_VREG(ldo10,  pmic4_pldo,      VRM, ldo, 10, vdd_l10_l23_l25),
	RPMH_VREG(ldo11,  pmic4_nldo,      VRM, ldo, 11, vdd_l3_l11),
	RPMH_VREG(ldo12,  pmic4_pldo_lv,   VRM, ldo, 12, vdd_l7_l12_l14_l15),
	RPMH_VREG(ldo13,  pmic4_pldo,      VRM, ldo, 13, vdd_l13_l19_l21),
	RPMH_VREG(ldo14,  pmic4_pldo_lv,   VRM, ldo, 14, vdd_l7_l12_l14_l15),
	RPMH_VREG(ldo15,  pmic4_pldo_lv,   VRM, ldo, 15, vdd_l7_l12_l14_l15),
	RPMH_VREG(ldo16,  pmic4_pldo,      VRM, ldo, 16, vdd_l16_l28),
	RPMH_VREG(ldo17,  pmic4_nldo,      VRM, ldo, 17, vdd_l2_l8_l17),
	RPMH_VREG(ldo18,  pmic4_pldo,      VRM, ldo, 18, vdd_l18_l22),
	RPMH_VREG(ldo19,  pmic4_pldo,      VRM, ldo, 19, vdd_l13_l19_l21),
	RPMH_VREG(ldo20,  pmic4_pldo,      VRM, ldo, 20, vdd_l20_l24),
	RPMH_VREG(ldo21,  pmic4_pldo,      VRM, ldo, 21, vdd_l13_l19_l21),
	RPMH_VREG(ldo22,  pmic4_pldo,      VRM, ldo, 22, vdd_l18_l22),
	RPMH_VREG(ldo23,  pmic4_pldo,      VRM, ldo, 23, vdd_l10_l23_l25),
	RPMH_VREG(ldo24,  pmic4_pldo,      VRM, ldo, 24, vdd_l20_l24),
	RPMH_VREG(ldo25,  pmic4_pldo,      VRM, ldo, 25, vdd_l10_l23_l25),
	RPMH_VREG(ldo26,  pmic4_nldo,      VRM, ldo, 26, vdd_l26),
	RPMH_VREG(ldo27,  pmic4_nldo,      VRM, ldo, 27, vdd_l1_l27),
	RPMH_VREG(ldo28,  pmic4_pldo,      VRM, ldo, 28, vdd_l16_l28),
	RPMH_VREG(lvs1,   pmic4_lvs,       XOB, vs,   1, vdd_lvs1_lvs2),
	RPMH_VREG(lvs2,   pmic4_lvs,       XOB, vs,   2, vdd_lvs1_lvs2),
};

static const struct rpmh_vreg_init_data pmi8998_vreg_data[] = {
	RPMH_VREG(bob,    pmic4_bob,       VRM, bob,  1, vdd_bob),
};

static const struct rpmh_vreg_init_data pm8005_vreg_data[] = {
	RPMH_VREG(smps1,  pmic4_ftsmps426, VRM, smp,  1, vdd_s1),
	RPMH_VREG(smps2,  pmic4_ftsmps426, VRM, smp,  2, vdd_s2),
	RPMH_VREG(smps3,  pmic4_ftsmps426, VRM, smp,  3, vdd_s3),
	RPMH_VREG(smps4,  pmic4_ftsmps426, VRM, smp,  4, vdd_s4),
};

static const struct rpmh_pmic_init_data pm8998_pmic_data = {
	.name		= "PM8998",
	.vreg_data	= pm8998_vreg_data,
	.count		= ARRAY_SIZE(pm8998_vreg_data),
};

static const struct rpmh_pmic_init_data pmi8998_pmic_data = {
	.name		= "PMI8998",
	.vreg_data	= pmi8998_vreg_data,
	.count		= ARRAY_SIZE(pmi8998_vreg_data),
};

static const struct rpmh_pmic_init_data pm8005_pmic_data = {
	.name		= "PM8005",
	.vreg_data	= pm8005_vreg_data,
	.count		= ARRAY_SIZE(pm8005_vreg_data),
};

static const struct of_device_id rpmh_regulator_match_table[] = {
	{
		.compatible = "qcom,pm8998-rpmh-regulators",
		.data = &pm8998_pmic_data,
	},
	{
		.compatible = "qcom,pmi8998-rpmh-regulators",
		.data = &pmi8998_pmic_data,
	},
	{
		.compatible = "qcom,pm8005-rpmh-regulators",
		.data = &pm8005_pmic_data,
	},
	{}
};
MODULE_DEVICE_TABLE(of, rpmh_regulator_match_table);

/**
 * rpmh_regulator_probe() - probe an RPMh PMIC and register regulators for each
 *		of the regulator nodes associated with it
 * @pdev:		Pointer to the platform device of the RPMh PMIC
 *
 * Return: 0 on success, errno on failure
 */
static int rpmh_regulator_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const struct of_device_id *match;
	struct rpmh_pmic *pmic;
	struct device_node *node;
	int ret, i;

	node = dev->of_node;

	if (!node) {
		dev_err(dev, "Device tree node is missing\n");
		return -EINVAL;
	}

	ret = cmd_db_ready();
	if (ret < 0) {
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "Command DB not available, ret=%d\n", ret);
		return ret;
	}

	pmic = devm_kzalloc(dev, sizeof(*pmic), GFP_KERNEL);
	if (!pmic)
		return -ENOMEM;

	pmic->dev = dev;
	platform_set_drvdata(pdev, pmic);

	pmic->rpmh_client = rpmh_get_client(pdev);
	if (IS_ERR(pmic->rpmh_client)) {
		ret = PTR_ERR(pmic->rpmh_client);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "failed to request RPMh client, ret=%d\n",
				ret);
		return ret;
	}

	match = of_match_node(rpmh_regulator_match_table, node);
	if (match) {
		pmic->init_data = match->data;
	} else {
		dev_err(dev, "could not find compatible string match\n");
		ret = -ENODEV;
		goto cleanup;
	}

	ret = of_property_read_string(node, "qcom,pmic-id",
				     &pmic->pmic_id);
	if (ret < 0) {
		dev_err(dev, "qcom,pmic-id missing in DT node\n");
		goto cleanup;
	}

	ret = rpmh_regulator_allocate_vreg(pmic);
	if (ret < 0) {
		dev_err(dev, "failed to allocate regulator subnode array, ret=%d\n",
			ret);
		goto cleanup;
	}

	for (i = 0; i < pmic->vreg_count; i++) {
		ret = rpmh_regulator_init_vreg(&pmic->vreg[i]);
		if (ret < 0) {
			dev_err(dev, "unable to initialize rpmh-regulator vreg %s, ret=%d\n",
				pmic->vreg[i].of_node->name, ret);
			goto cleanup;
		}
	}

	dev_dbg(dev, "successfully probed %d %s regulators\n",
		pmic->vreg_count, pmic->init_data->name);

	return ret;

cleanup:
	rpmh_release(pmic->rpmh_client);

	return ret;
}

static int rpmh_regulator_remove(struct platform_device *pdev)
{
	struct rpmh_pmic *pmic = platform_get_drvdata(pdev);

	rpmh_release(pmic->rpmh_client);

	return 0;
}

static struct platform_driver rpmh_regulator_driver = {
	.driver		= {
		.name		= "qcom-rpmh-regulator",
		.of_match_table	= rpmh_regulator_match_table,
		.owner		= THIS_MODULE,
	},
	.probe		= rpmh_regulator_probe,
	.remove		= rpmh_regulator_remove,
};

static int rpmh_regulator_init(void)
{
	return platform_driver_register(&rpmh_regulator_driver);
}

static void rpmh_regulator_exit(void)
{
	platform_driver_unregister(&rpmh_regulator_driver);
}

arch_initcall(rpmh_regulator_init);
module_exit(rpmh_regulator_exit);

MODULE_DESCRIPTION("Qualcomm RPMh regulator driver");
MODULE_LICENSE("GPL v2");
