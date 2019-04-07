/* Copyright (c) 2014-2018, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/delay.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/regmap.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/spmi.h>
#include <linux/platform_device.h>
#include <linux/string.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/of_regulator.h>

#define QPNP_LABIBB_REGULATOR_DRIVER_NAME	"qcom,qpnp-labibb-regulator"

#define REG_REVISION_2			0x01
#define REG_PERPH_TYPE			0x04

#define QPNP_LAB_TYPE			0x24
#define QPNP_IBB_TYPE			0x20

/* Common register value for LAB/IBB */
#define REG_LAB_IBB_SEC_ACCESS		0xD0
#define REG_LAB_IBB_SEC_UNLOCK_CODE	0xA5

/* LAB register offset definitions */
#define REG_LAB_STATUS1			0x08
#define REG_LAB_ENABLE_CTL		0x46

/* LAB register bits definitions */

/* REG_LAB_STATUS1 */
#define LAB_STATUS1_VREG_OK_BIT		BIT(7)
#define LAB_STATUS1_SC_DETECT_BIT	BIT(6)

/* REG_LAB_ENABLE_CTL */
#define LAB_ENABLE_CTL_EN		BIT(7)

/* IBB register offset definitions */
#define REG_IBB_STATUS1			0x08
#define REG_IBB_ENABLE_CTL		0x46
#define REG_IBB_PWRUP_PWRDN_CTL_1	0x58

/* IBB register bits definition */

/* REG_IBB_STATUS1 */
#define IBB_STATUS1_VREG_OK_BIT		BIT(7)
#define IBB_STATUS1_SC_DETECT_BIT	BIT(6)

/* REG_IBB_ENABLE_CTL */
#define IBB_ENABLE_CTL_MASK		(BIT(7) | BIT(6))
#define IBB_ENABLE_CTL_MODULE_EN	BIT(7)

/* REG_IBB_PWRUP_PWRDN_CTL_1 */
#define IBB_PWRUP_PWRDN_CTL_1_DLY1_MASK	GENMASK(5, 4)
#define IBB_PWRUP_PWRDN_CTL_1_DLY1_SHIFT	4
#define IBB_PWRUP_PWRDN_CTL_1_LAB_VREG_OK	BIT(7)
#define IBB_PWRUP_PWRDN_CTL_1_EN_DLY1	BIT(6)
#define PWRUP_PWRDN_CTL_1_DISCHARGE_EN	BIT(2)

#define IBB_HW_DEFAULT_SLEW_RATE		12000

/**
 * enum qpnp_labibb_mode - working mode of LAB/IBB regulators
 * %QPNP_LABIBB_LCD_MODE:		configure LAB and IBB regulators
 * together to provide power supply for LCD
 */
enum qpnp_labibb_mode {
	QPNP_LABIBB_LCD_MODE,
};

/**
 * IBB_SW_CONTROL_EN: Specifies IBB is enabled through software.
 * IBB_SW_CONTROL_DIS: Specifies IBB is disabled through software.
 */
enum ibb_mode {
	IBB_SW_CONTROL_EN,
	IBB_SW_CONTROL_DIS,
};

static const int ibb_pwrup_dly_table[] = {
	1000,
	2000,
	4000,
	8000,
};

static const int ibb_pwrdn_dly_table[] = {
	1000,
	2000,
	4000,
	8000,
};

struct lab_regulator {
	struct regulator_desc		rdesc;
	struct regulator_dev		*rdev;
	struct mutex			lab_mutex;
	int				lab_vreg_ok_irq;
	int				lab_sc_irq;
	int				curr_volt;
	int				min_volt;
	int				soft_start;
	int				sc_wait_time_ms;
	int				vreg_enabled;
};

struct ibb_regulator {
	struct regulator_desc		rdesc;
	struct regulator_dev		*rdev;
	struct mutex			ibb_mutex;
	int				ibb_sc_irq;
	int				curr_volt;
	int				min_volt;
	int				soft_start;
	u32				pwrup_dly;
	u32				pwrdn_dly;
	int				vreg_enabled;
};

struct qpnp_labibb {
	struct device			*dev;
	struct platform_device		*pdev;
	struct regmap			*regmap;
	u16				lab_base;
	u16				ibb_base;
	u8				lab_dig_major;
	u8				ibb_dig_major;
	struct lab_regulator		lab_vreg;
	struct ibb_regulator		ibb_vreg;
	struct mutex			bus_mutex;
	enum qpnp_labibb_mode		mode;
	struct work_struct		lab_vreg_ok_work;
	struct delayed_work		sc_err_recovery_work;
	struct hrtimer			sc_err_check_timer;
	int				sc_err_count;
	bool				notify_lab_vreg_ok_sts;
	bool				detect_lab_sc;
	bool				sc_detected;
};

static int
qpnp_labibb_read(struct qpnp_labibb *labibb, u16 address,
			u8 *val, int count)
{
	int rc = 0;
	struct platform_device *pdev = labibb->pdev;

	mutex_lock(&(labibb->bus_mutex));
	rc = regmap_bulk_read(labibb->regmap, address, val, count);
	if (rc < 0)
		pr_err("SPMI read failed address=0x%02x sid=0x%02x rc=%d\n",
			address, to_spmi_device(pdev->dev.parent)->usid, rc);

	mutex_unlock(&(labibb->bus_mutex));
	return rc;
}

static int
qpnp_labibb_masked_write(struct qpnp_labibb *labibb, u16 address,
						u8 mask, u8 val)
{
	int rc = 0;
	struct platform_device *pdev = labibb->pdev;

	mutex_lock(&(labibb->bus_mutex));
	if (address == 0) {
		pr_err("address cannot be zero address=0x%02x sid=0x%02x\n",
			address, to_spmi_device(pdev->dev.parent)->usid);
		rc = -EINVAL;
		goto error;
	}

	rc = regmap_update_bits(labibb->regmap, address, mask, val);
	if (rc < 0)
		pr_err("spmi write failed: addr=%03X, rc=%d\n", address, rc);

error:
	mutex_unlock(&(labibb->bus_mutex));
	return rc;
}

static int qpnp_labibb_sec_masked_write(struct qpnp_labibb *labibb, u16 base,
					u8 offset, u8 mask, u8 val)
{
	int rc = 0;
	u8 sec_val = REG_LAB_IBB_SEC_UNLOCK_CODE;
	struct platform_device *pdev = labibb->pdev;

	mutex_lock(&(labibb->bus_mutex));
	if (base == 0) {
		pr_err("base cannot be zero base=0x%02x sid=0x%02x\n",
			base, to_spmi_device(pdev->dev.parent)->usid);
		rc = -EINVAL;
		goto error;
	}

	rc = regmap_write(labibb->regmap, base + REG_LAB_IBB_SEC_ACCESS,
				sec_val);
	if (rc < 0) {
		pr_err("register %x failed rc = %d\n",
			base + REG_LAB_IBB_SEC_ACCESS, rc);
		goto error;
	}

	rc = regmap_update_bits(labibb->regmap, base + offset, mask, val);
	if (rc < 0)
		pr_err("spmi write failed: addr=%03X, rc=%d\n", base, rc);

error:
	mutex_unlock(&(labibb->bus_mutex));
	return rc;
}

static int qpnp_ibb_set_mode(struct qpnp_labibb *labibb, enum ibb_mode mode)
{
	int rc;
	u8 val;

	if (mode == IBB_SW_CONTROL_EN)
		val = IBB_ENABLE_CTL_MODULE_EN;
	else if (mode == IBB_SW_CONTROL_DIS)
		val = 0;
	else
		return -EINVAL;

	rc = qpnp_labibb_masked_write(labibb,
		labibb->ibb_base + REG_IBB_ENABLE_CTL,
		IBB_ENABLE_CTL_MASK, val);
	if (rc < 0)
		pr_err("Unable to configure IBB_ENABLE_CTL rc=%d\n", rc);

	return rc;
}

static int qpnp_labibb_regulator_enable(struct qpnp_labibb *labibb)
{
	int rc;
	u8 val;
	int dly;
	int retries;
	bool enabled = false;

	rc = qpnp_ibb_set_mode(labibb, IBB_SW_CONTROL_EN);
	if (rc) {
		pr_err("Unable to set IBB_MODULE_EN rc = %d\n", rc);
		return rc;
	}

	/* total delay time */
	dly = labibb->lab_vreg.soft_start + labibb->ibb_vreg.soft_start
				+ labibb->ibb_vreg.pwrup_dly;
	usleep_range(dly, dly + 100);

	/* after this delay, lab should be enabled */
	rc = qpnp_labibb_read(labibb, labibb->lab_base + REG_LAB_STATUS1,
			&val, 1);
	if (rc < 0) {
		pr_err("read register %x failed rc = %d\n",
			REG_LAB_STATUS1, rc);
		goto err_out;
	}

	pr_debug("soft=%d %d up=%d dly=%d\n",
		labibb->lab_vreg.soft_start, labibb->ibb_vreg.soft_start,
				labibb->ibb_vreg.pwrup_dly, dly);

	if (!(val & LAB_STATUS1_VREG_OK_BIT)) {
		pr_err("failed for LAB %x\n", val);
		goto err_out;
	}

	/* poll IBB_STATUS to make sure ibb had been enabled */
	dly = labibb->ibb_vreg.soft_start + labibb->ibb_vreg.pwrup_dly;
	retries = 10;
	while (retries--) {
		rc = qpnp_labibb_read(labibb, labibb->ibb_base +
					REG_IBB_STATUS1, &val, 1);
		if (rc < 0) {
			pr_err("read register %x failed rc = %d\n",
				REG_IBB_STATUS1, rc);
			goto err_out;
		}

		if (val & IBB_STATUS1_VREG_OK_BIT) {
			enabled = true;
			break;
		}
		usleep_range(dly, dly + 100);
	}

	if (!enabled) {
		pr_err("failed for IBB %x\n", val);
		goto err_out;
	}

	labibb->lab_vreg.vreg_enabled = 1;
	labibb->ibb_vreg.vreg_enabled = 1;

	return 0;
err_out:
	rc = qpnp_ibb_set_mode(labibb, IBB_SW_CONTROL_DIS);
	if (rc < 0) {
		pr_err("Unable to set IBB_MODULE_EN rc = %d\n", rc);
		return rc;
	}
	return -EINVAL;
}

static int qpnp_labibb_regulator_disable(struct qpnp_labibb *labibb)
{
	int rc;
	u8 val;
	int dly;
	int retries;
	bool disabled = false;

	rc = qpnp_ibb_set_mode(labibb, IBB_SW_CONTROL_DIS);
	if (rc < 0) {
		pr_err("Unable to set IBB_MODULE_EN rc = %d\n", rc);
		return rc;
	}

	/* poll IBB_STATUS to make sure ibb had been disabled */
	dly = labibb->ibb_vreg.pwrdn_dly;
	retries = 2;
	while (retries--) {
		usleep_range(dly, dly + 100);
		rc = qpnp_labibb_read(labibb, labibb->ibb_base +
				REG_IBB_STATUS1, &val, 1);
		if (rc < 0) {
			pr_err("read register %x failed rc = %d\n",
				REG_IBB_STATUS1, rc);
			return rc;
		}

		if (!(val & IBB_STATUS1_VREG_OK_BIT)) {
			disabled = true;
			break;
		}
	}

	if (!disabled) {
		pr_err("failed for IBB %x\n", val);
		return -EINVAL;
	}

	labibb->lab_vreg.vreg_enabled = 0;
	labibb->ibb_vreg.vreg_enabled = 0;

	return 0;
}

static int qpnp_lab_regulator_enable(struct regulator_dev *rdev)
{
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	if (labibb->sc_detected) {
		pr_info("Short circuit detected: disabled LAB/IBB rails\n");
		return 0;
	}
	if (!labibb->lab_vreg.vreg_enabled)
		return qpnp_labibb_regulator_enable(labibb);

	if (labibb->notify_lab_vreg_ok_sts || labibb->detect_lab_sc)
		schedule_work(&labibb->lab_vreg_ok_work);

	return 0;
}

static int qpnp_lab_regulator_disable(struct regulator_dev *rdev)
{
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	if (labibb->lab_vreg.vreg_enabled)
		return qpnp_labibb_regulator_disable(labibb);
	return 0;
}

static int qpnp_lab_regulator_is_enabled(struct regulator_dev *rdev)
{
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	return labibb->lab_vreg.vreg_enabled;
}

#define SC_ERR_RECOVERY_DELAY_MS	250
#define SC_ERR_COUNT_INTERVAL_SEC	1
#define POLLING_SCP_DONE_COUNT		2
#define POLLING_SCP_DONE_INTERVAL_MS	5
static irqreturn_t labibb_sc_err_handler(int irq, void *_labibb)
{
	int rc;
	u16 reg;
	u8 sc_err_mask, val;
	char *str;
	struct qpnp_labibb *labibb = (struct qpnp_labibb *)_labibb;
	bool in_sc_err, lab_en, ibb_en, scp_done = false;
	int count;

	if (irq == labibb->lab_vreg.lab_sc_irq) {
		reg = labibb->lab_base + REG_LAB_STATUS1;
		sc_err_mask = LAB_STATUS1_SC_DETECT_BIT;
		str = "LAB";
	} else if (irq == labibb->ibb_vreg.ibb_sc_irq) {
		reg = labibb->ibb_base + REG_IBB_STATUS1;
		sc_err_mask = IBB_STATUS1_SC_DETECT_BIT;
		str = "IBB";
	} else {
		return IRQ_HANDLED;
	}

	rc = qpnp_labibb_read(labibb, reg, &val, 1);
	if (rc < 0) {
		pr_err("Read 0x%x failed, rc=%d\n", reg, rc);
		return IRQ_HANDLED;
	}
	pr_debug("%s SC error triggered! %s_STATUS1 = %d\n", str, str, val);

	in_sc_err = !!(val & sc_err_mask);

	/*
	 * The SC fault would trigger PBS to disable regulators
	 * for protection. This would cause the SC_DETECT status being
	 * cleared so that it's not able to get the SC fault status.
	 * Check if LAB/IBB regulators are enabled in the driver but
	 * disabled in hardware, this means a SC fault had happened
	 * and SCP handling is completed by PBS.
	 */
	if (!in_sc_err) {
		count = POLLING_SCP_DONE_COUNT;
		do {
			reg = labibb->lab_base + REG_LAB_ENABLE_CTL;
			rc = qpnp_labibb_read(labibb, reg, &val, 1);
			if (rc < 0) {
				pr_err("Read 0x%x failed, rc=%d\n", reg, rc);
				return IRQ_HANDLED;
			}
			lab_en = !!(val & LAB_ENABLE_CTL_EN);

			reg = labibb->ibb_base + REG_IBB_ENABLE_CTL;
			rc = qpnp_labibb_read(labibb, reg, &val, 1);
			if (rc < 0) {
				pr_err("Read 0x%x failed, rc=%d\n", reg, rc);
				return IRQ_HANDLED;
			}
			ibb_en = !!(val & IBB_ENABLE_CTL_MODULE_EN);
			if (lab_en || ibb_en)
				msleep(POLLING_SCP_DONE_INTERVAL_MS);
			else
				break;
		} while ((lab_en || ibb_en) && count--);

		if (labibb->lab_vreg.vreg_enabled
				&& labibb->ibb_vreg.vreg_enabled
				&& !lab_en && !ibb_en) {
			pr_debug("LAB/IBB has been disabled by SCP\n");
			scp_done = true;
		}
	}

	if (in_sc_err || scp_done) {
		if (hrtimer_active(&labibb->sc_err_check_timer) ||
			hrtimer_callback_running(&labibb->sc_err_check_timer)) {
			labibb->sc_err_count++;
		} else {
			labibb->sc_err_count = 1;
			hrtimer_start(&labibb->sc_err_check_timer,
					ktime_set(SC_ERR_COUNT_INTERVAL_SEC, 0),
					HRTIMER_MODE_REL);
		}
		qpnp_labibb_regulator_enable(labibb);
	}
	return IRQ_HANDLED;
}

#define SC_FAULT_COUNT_MAX		4
static enum hrtimer_restart labibb_check_sc_err_count(struct hrtimer *timer)
{
	struct qpnp_labibb *labibb = container_of(timer,
			struct qpnp_labibb, sc_err_check_timer);
	/*
	 * if SC fault triggers more than 4 times in 1 second,
	 * then disable the IRQs and leave as it.
	 */
	if (labibb->sc_err_count > SC_FAULT_COUNT_MAX) {
		disable_irq(labibb->lab_vreg.lab_sc_irq);
		disable_irq(labibb->ibb_vreg.ibb_sc_irq);
	}

	return HRTIMER_NORESTART;
}

static int qpnp_lab_regulator_get_voltage(struct regulator_dev *rdev)
{
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	return labibb->lab_vreg.curr_volt;
}

static struct regulator_ops qpnp_lab_ops = {
	.enable			= qpnp_lab_regulator_enable,
	.disable		= qpnp_lab_regulator_disable,
	.is_enabled		= qpnp_lab_regulator_is_enabled,
	.get_voltage		= qpnp_lab_regulator_get_voltage,
};

static int register_qpnp_lab_regulator(struct qpnp_labibb *labibb,
					struct device_node *of_node)
{
	int rc = 0;
	struct regulator_init_data *init_data;
	struct regulator_desc *rdesc = &labibb->lab_vreg.rdesc;
	struct regulator_config cfg = {};
	u8 val, mask;
	bool config_current_sense = false;
	u32 tmp;

	if (!of_node) {
		dev_err(labibb->dev, "qpnp lab regulator device tree node is missing\n");
		return -EINVAL;
	}

	init_data = of_get_regulator_init_data(labibb->dev, of_node, rdesc);
	if (!init_data) {
		pr_err("unable to get regulator init data for qpnp lab regulator\n");
		return -ENOMEM;
	}

	rc = devm_request_threaded_irq(labibb->dev,
			labibb->lab_vreg.lab_vreg_ok_irq, NULL,
			IRQ_HANDLED,
			IRQF_ONESHOT | IRQF_TRIGGER_RISING,
			"lab-vreg-ok", labibb);
	if (rc) {
		pr_err("Failed to register 'lab-vreg-ok' irq rc=%d\n",
					rc);
		return rc;
	}
	labibb->lab_vreg.sc_wait_time_ms = -EINVAL;
	if (labibb->lab_vreg.lab_sc_irq != -EINVAL) {
		rc = devm_request_threaded_irq(labibb->dev,
				labibb->lab_vreg.lab_sc_irq, NULL,
				labibb_sc_err_handler,
				IRQF_ONESHOT | IRQF_TRIGGER_RISING,
				"lab-sc-err", labibb);
		if (rc) {
			pr_err("Failed to register 'lab-sc-err' irq rc=%d\n",
						rc);
			return rc;
		}
	}

	if (init_data->constraints.name) {
		rdesc->owner		= THIS_MODULE;
		rdesc->type		= REGULATOR_VOLTAGE;
		rdesc->name		= init_data->constraints.name;

		cfg.dev = labibb->dev;
		cfg.init_data = init_data;
		cfg.driver_data = labibb;
		cfg.of_node = of_node;

		if (of_get_property(labibb->dev->of_node, "parent-supply",
				NULL))
			init_data->supply_regulator = "parent";

		init_data->constraints.valid_ops_mask
				|= REGULATOR_CHANGE_VOLTAGE |
					REGULATOR_CHANGE_STATUS;

		labibb->lab_vreg.rdev = regulator_register(rdesc, &cfg);
		if (IS_ERR(labibb->lab_vreg.rdev)) {
			rc = PTR_ERR(labibb->lab_vreg.rdev);
			labibb->lab_vreg.rdev = NULL;
			pr_err("unable to get regulator init data for qpnp lab regulator, rc = %d\n",
				rc);

			return rc;
		}
	} else {
		dev_err(labibb->dev, "qpnp lab regulator name missing\n");
		return -EINVAL;
	}

	return 0;
}
static int qpnp_ibb_dt_init(struct qpnp_labibb *labibb,
				struct device_node *of_node)
{
	int rc = 0;
	u32 i = 0, tmp = 0;
	u8 val=0, mask=0;
	labibb->mode = QPNP_LABIBB_LCD_MODE;

	rc = of_property_read_u32(of_node,
			"qcom,qpnp-ibb-lab-pwrup-delay", &tmp);
	if (!rc) {
		if (tmp > 0) {
			for (i = 0; i < ARRAY_SIZE(ibb_pwrup_dly_table); i++) {
				if (ibb_pwrup_dly_table[i] == tmp)
					break;
			}

			if (i == ARRAY_SIZE(ibb_pwrup_dly_table)) {
				pr_err("Invalid value in qcom,qpnp-ibb-lab-pwrup-delay\n");
				return -EINVAL;
			}
		}

		labibb->ibb_vreg.pwrup_dly = tmp;

		if (tmp > 0)
			val |= IBB_PWRUP_PWRDN_CTL_1_EN_DLY1;

		val |= (i << IBB_PWRUP_PWRDN_CTL_1_DLY1_SHIFT);
		val |= IBB_PWRUP_PWRDN_CTL_1_LAB_VREG_OK;
		mask |= (IBB_PWRUP_PWRDN_CTL_1_EN_DLY1 |
			IBB_PWRUP_PWRDN_CTL_1_DLY1_MASK |
			IBB_PWRUP_PWRDN_CTL_1_LAB_VREG_OK);
	}

	if (of_property_read_bool(of_node,
				"qcom,qpnp-ibb-en-discharge")) {
		val |= PWRUP_PWRDN_CTL_1_DISCHARGE_EN;
		mask |= PWRUP_PWRDN_CTL_1_DISCHARGE_EN;
	}

	rc = qpnp_labibb_sec_masked_write(labibb, labibb->ibb_base,
				REG_IBB_PWRUP_PWRDN_CTL_1, mask, val);
	if (rc < 0) {
		pr_err("qpnp_labibb_sec_write register %x failed rc = %d\n",
			REG_IBB_PWRUP_PWRDN_CTL_1, rc);
		return rc;
	}

	rc = of_property_read_u32(of_node, "qcom,qpnp-ibb-init-voltage",
					&(labibb->ibb_vreg.curr_volt));
	if (rc < 0) {
		pr_err("get qcom,qpnp-ibb-init-voltage failed, rc = %d\n", rc);
		return rc;
	}

	return 0;
}

static int qpnp_ibb_regulator_enable(struct regulator_dev *rdev)
{
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	if (labibb->sc_detected) {
		pr_info("Short circuit detected: disabled LAB/IBB rails\n");
		return 0;
	}
	if (!labibb->ibb_vreg.vreg_enabled)
		return qpnp_labibb_regulator_enable(labibb);
	return 0;
}

static int qpnp_ibb_regulator_disable(struct regulator_dev *rdev)
{
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	if (labibb->ibb_vreg.vreg_enabled)
		return qpnp_labibb_regulator_disable(labibb);
	return 0;
}

static int qpnp_ibb_regulator_is_enabled(struct regulator_dev *rdev)
{
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	return labibb->ibb_vreg.vreg_enabled;
}

static int qpnp_ibb_regulator_get_voltage(struct regulator_dev *rdev)
{
	struct qpnp_labibb *labibb  = rdev_get_drvdata(rdev);

	return labibb->ibb_vreg.curr_volt;
}

static struct regulator_ops qpnp_ibb_ops = {
	.enable			= qpnp_ibb_regulator_enable,
	.disable		= qpnp_ibb_regulator_disable,
	.is_enabled		= qpnp_ibb_regulator_is_enabled,
	.get_voltage		= qpnp_ibb_regulator_get_voltage,
};

static int register_qpnp_ibb_regulator(struct qpnp_labibb *labibb,
					struct device_node *of_node)
{
	int rc = 0;
	struct regulator_init_data *init_data;
	struct regulator_desc *rdesc = &labibb->ibb_vreg.rdesc;
	struct regulator_config cfg = {};
	u8 val, ibb_enable_ctl, index;

	if (!of_node) {
		dev_err(labibb->dev, "qpnp ibb regulator device tree node is missing\n");
		return -EINVAL;
	}

	init_data = of_get_regulator_init_data(labibb->dev, of_node, rdesc);
	if (!init_data) {
		pr_err("unable to get regulator init data for qpnp ibb regulator\n");
		return -ENOMEM;
	}

	rc = qpnp_ibb_dt_init(labibb, of_node);
	if (rc < 0) {
		pr_err("qpnp-ibb: wrong DT parameter specified: rc = %d\n",
			rc);
		return rc;
	}

	if (labibb->ibb_vreg.ibb_sc_irq != -EINVAL) {
		rc = devm_request_threaded_irq(labibb->dev,
				labibb->ibb_vreg.ibb_sc_irq, NULL,
				labibb_sc_err_handler,
				IRQF_ONESHOT | IRQF_TRIGGER_RISING,
				"ibb-sc-err", labibb);
		if (rc) {
			pr_err("Failed to register 'ibb-sc-err' irq rc=%d\n",
						rc);
			return rc;
		}
	}

	if (init_data->constraints.name) {
		rdesc->owner		= THIS_MODULE;
		rdesc->type		= REGULATOR_VOLTAGE;
		rdesc->ops		= &qpnp_ibb_ops;
		rdesc->name		= init_data->constraints.name;

		cfg.dev = labibb->dev;
		cfg.init_data = init_data;
		cfg.driver_data = labibb;
		cfg.of_node = of_node;

		if (of_get_property(labibb->dev->of_node, "parent-supply",
				 NULL))
			init_data->supply_regulator = "parent";

		init_data->constraints.valid_ops_mask
				|= REGULATOR_CHANGE_VOLTAGE |
					REGULATOR_CHANGE_STATUS;

		labibb->ibb_vreg.rdev = regulator_register(rdesc, &cfg);
		if (IS_ERR(labibb->ibb_vreg.rdev)) {
			rc = PTR_ERR(labibb->ibb_vreg.rdev);
			labibb->ibb_vreg.rdev = NULL;
			pr_err("unable to get regulator init data for qpnp ibb regulator, rc = %d\n",
				rc);

			return rc;
		}
	} else {
		dev_err(labibb->dev, "qpnp ibb regulator name missing\n");
		return -EINVAL;
	}

	return 0;
}

static int qpnp_lab_register_irq(struct device_node *child,
				struct qpnp_labibb *labibb)
{
	int rc = 0;

	rc = of_irq_get_byname(child, "lab-vreg-ok");
	if (rc < 0) {
		pr_err("Invalid lab-vreg-ok irq\n");
		return rc;
	}
	labibb->lab_vreg.lab_vreg_ok_irq = rc;
	labibb->lab_vreg.lab_sc_irq = -EINVAL;
	rc = of_irq_get_byname(child, "lab-sc-err");
	if (rc < 0)
		pr_debug("Unable to get lab-sc-err, rc = %d\n", rc);
	else
		labibb->lab_vreg.lab_sc_irq = rc;

	return 0;
}

static int qpnp_ibb_register_irq(struct device_node *child,
				struct qpnp_labibb *labibb)
{
	int rc;

	labibb->ibb_vreg.ibb_sc_irq = -EINVAL;
	rc = of_irq_get_byname(child, "ibb-sc-err");
	if (rc < 0)
		pr_debug("Unable to get ibb-sc-err, rc = %d\n", rc);
	else
		labibb->ibb_vreg.ibb_sc_irq = rc;

	return 0;
}

static int qpnp_labibb_regulator_probe(struct platform_device *pdev)
{
	struct qpnp_labibb *labibb;
	unsigned int base;
	struct device_node *child; 
	u8 type, revision;
	int rc = 0;

	labibb = devm_kzalloc(&pdev->dev, sizeof(*labibb), GFP_KERNEL);
	if (labibb == NULL)
		return -ENOMEM;

	labibb->regmap = dev_get_regmap(pdev->dev.parent, NULL);
	if (!labibb->regmap) {
		dev_err(&pdev->dev, "Couldn't get parent's regmap\n");
		return -EINVAL;
	}

	labibb->dev = &(pdev->dev);
	labibb->pdev = pdev;

	mutex_init(&(labibb->lab_vreg.lab_mutex));
	mutex_init(&(labibb->ibb_vreg.ibb_mutex));
	mutex_init(&(labibb->bus_mutex));

	if (of_get_available_child_count(pdev->dev.of_node) == 0) {
		pr_err("no child nodes\n");
		return -ENXIO;
	}

	for_each_available_child_of_node(pdev->dev.of_node, child) {
		rc = of_property_read_u32(child, "reg", &base);
		if (rc < 0) {
			dev_err(&pdev->dev,
				"Couldn't find reg in node = %s rc = %d\n",
				child->full_name, rc);
			return rc;
		}

		rc = qpnp_labibb_read(labibb, base + REG_REVISION_2,
					 &revision, 1);
		if (rc < 0) {
			pr_err("Reading REVISION_2 failed rc=%d\n", rc);
			goto fail_registration;
		}

		rc = qpnp_labibb_read(labibb, base + REG_PERPH_TYPE,
					&type, 1);
		if (rc < 0) {
			pr_err("Peripheral type read failed rc=%d\n", rc);
			goto fail_registration;
		}

		switch (type) {
		case QPNP_LAB_TYPE:
			labibb->lab_base = base;
			labibb->lab_dig_major = revision;
			rc = qpnp_lab_register_irq(child, labibb);
			if (rc) {
				pr_err("Failed to register LAB IRQ rc=%d\n",
							rc);
				goto fail_registration;
			}
			rc = register_qpnp_lab_regulator(labibb, child);
			if (rc < 0)
				goto fail_registration;
		break;

		case QPNP_IBB_TYPE:
			labibb->ibb_base = base;
			labibb->ibb_dig_major = revision;
			qpnp_ibb_register_irq(child, labibb);
			rc = register_qpnp_ibb_regulator(labibb, child);
			if (rc < 0)
				goto fail_registration;
		break;

		default:
			pr_err("qpnp_labibb: unknown peripheral type %x\n",
				type);
			rc = -EINVAL;
			goto fail_registration;
		}
	}

	hrtimer_init(&labibb->sc_err_check_timer,
			CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	labibb->sc_err_check_timer.function = labibb_check_sc_err_count;
	dev_set_drvdata(&pdev->dev, labibb);
	pr_info("LAB/IBB registered successfully, lab_vreg enable=%d ibb_vreg enable=%d \n",
						labibb->lab_vreg.vreg_enabled,
						labibb->ibb_vreg.vreg_enabled);

	return 0;

fail_registration:
	if (labibb->lab_vreg.rdev)
		regulator_unregister(labibb->lab_vreg.rdev);
	if (labibb->ibb_vreg.rdev)
		regulator_unregister(labibb->ibb_vreg.rdev);

	return rc;
}

static int qpnp_labibb_regulator_remove(struct platform_device *pdev)
{
	struct qpnp_labibb *labibb = dev_get_drvdata(&pdev->dev);

	if (labibb) {
		if (labibb->lab_vreg.rdev)
			regulator_unregister(labibb->lab_vreg.rdev);
		if (labibb->ibb_vreg.rdev)
			regulator_unregister(labibb->ibb_vreg.rdev);

		cancel_work_sync(&labibb->lab_vreg_ok_work);
	}
	return 0;
}

static const struct of_device_id spmi_match_table[] = {
	{ .compatible = QPNP_LABIBB_REGULATOR_DRIVER_NAME, },
	{ },
};

static struct platform_driver qpnp_labibb_regulator_driver = {
	.driver		= {
		.name		= QPNP_LABIBB_REGULATOR_DRIVER_NAME,
		.of_match_table	= spmi_match_table,
	},
	.probe		= qpnp_labibb_regulator_probe,
	.remove		= qpnp_labibb_regulator_remove,
};

static int __init qpnp_labibb_regulator_init(void)
{
	return platform_driver_register(&qpnp_labibb_regulator_driver);
}
arch_initcall(qpnp_labibb_regulator_init);

static void __exit qpnp_labibb_regulator_exit(void)
{
	platform_driver_unregister(&qpnp_labibb_regulator_driver);
}
module_exit(qpnp_labibb_regulator_exit);

MODULE_DESCRIPTION("QPNP labibb driver");
MODULE_AUTHOR("Nisha Kumari");
MODULE_LICENSE("GPL v2");
