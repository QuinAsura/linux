/*
 * Copyright (c) 2012-2015, The Linux Foundation. All rights reserved.
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

#include <linux/clk.h>
#include <linux/clk-provider.h>

#include "dsi_pll.h"
#include "dsi.xml.h"

/*
 * DSI PLL 28nm - clock diagram (eg: DSI0):
 *
 *         dsi0analog_postdiv_clk
 *                             |         dsi0indirect_path_div2_clk
 *                             |          |
 *                   +------+  |  +----+  |  |\   dsi0byte_mux
 *  dsi0vco_clk --o--| DIV1 |--o--| /2 |--o--| \   |
 *                |  +------+     +----+     | m|  |  +----+
 *                |                          | u|--o--| /4 |-- dsi0pllbyte
 *                |                          | x|     +----+
 *                o--------------------------| /
 *                |                          |/
 *                |          +------+
 *                o----------| DIV3 |------------------------- dsi0pll
 *                           +------+
 */

#define POLL_MAX_READS			10
#define POLL_TIMEOUT_US		50

#define NUM_PROVIDED_CLKS		2

#define VCO_REF_CLK_RATE		19200000
#define VCO_MIN_RATE			350000000
#define VCO_MAX_RATE			750000000

#define DSI_BYTE_PLL_CLK		0
#define DSI_PIXEL_PLL_CLK		1

#define LPFR_LUT_SIZE			10
struct lpfr_cfg {
	unsigned long vco_rate;
	u32 resistance;
};

/* Loop filter resistance: */
static const struct lpfr_cfg lpfr_lut[LPFR_LUT_SIZE] = {
	{ 479500000,  8 },
	{ 480000000, 11 },
	{ 575500000,  8 },
	{ 576000000, 12 },
	{ 610500000,  8 },
	{ 659500000,  9 },
	{ 671500000, 10 },
	{ 672000000, 14 },
	{ 708500000, 10 },
	{ 750000000, 11 },
};

struct pll_28nm_cached_state {
	unsigned long vco_rate;
	u8 postdiv3;
	u8 postdiv1;
	u8 byte_mux;
};

struct dsi_pll_28nm {
	struct msm_dsi_pll base;

	int id;
	struct platform_device *pdev;
	void __iomem *mmio;

	unsigned long ref_clk_rate;
	int vco_delay;

	/* private clocks: */
	struct clk *clks[NUM_DSI_CLOCKS_MAX];
	u32 num_clks;

	/* clock-provider: */
	struct clk *provided_clks[NUM_PROVIDED_CLKS];
	struct clk_onecell_data clk_data;

	struct pll_28nm_cached_state cached_state;
};

#define to_pll_28nm(x)	container_of(x, struct dsi_pll_28nm, base)

static bool pll_28nm_poll_for_ready(struct dsi_pll_28nm *pll_28nm,
				u32 nb_tries, u32 timeout_us)
{
	bool pll_locked = false;
	u32 val;

	while (nb_tries--) {
		val = pll_read(pll_28nm->mmio + REG_DSI_28nm_PHY_PLL_STATUS);
		pll_locked = !!(val & DSI_28nm_PHY_PLL_STATUS_PLL_RDY);

		if (pll_locked)
			break;

		udelay(timeout_us);
	}
	DBG("DSI PLL is %slocked", pll_locked ? "" : "*not* ");

	return pll_locked;
}

static void pll_28nm_software_reset(struct dsi_pll_28nm *pll_28nm)
{
	void __iomem *base = pll_28nm->mmio;

	/*
	 * Add HW recommended delays after toggling the software
	 * reset bit off and back on.
	 */
	pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_TEST_CFG,
			DSI_28nm_PHY_PLL_TEST_CFG_PLL_SW_RESET, 1);
	pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_TEST_CFG, 0x00, 1);
}

/*
 * Clock Callbacks
 */
static int dsi_pll_28nm_clk_set_rate(struct clk_hw *hw, unsigned long rate,
		unsigned long parent_rate)
{
	struct msm_dsi_pll *pll = hw_clk_to_pll(hw);
	struct dsi_pll_28nm *pll_28nm = to_pll_28nm(pll);
	struct device *dev = &pll_28nm->pdev->dev;
	void __iomem *base = pll_28nm->mmio;
	s64 refclk_cfg, frac_n_mode, ref_doubler_en_b;
	s64 ref_clk_to_pll, div_fbx1000, frac_n_value;
	s64 sdm_cfg0, sdm_cfg1, sdm_cfg2, sdm_cfg3;
	s64 gen_vco_clk, cal_cfg10, cal_cfg11;
	s64 vco_clk_rate = rate;
	unsigned long ref_clk_rate = pll_28nm->ref_clk_rate;
	s32 rem;
	int i;

	VERB("rate=%lu, parent's=%lu", rate, parent_rate);

	/* Force postdiv2 to be div-4 */
	pll_write(base + REG_DSI_28nm_PHY_PLL_POSTDIV2_CFG, 3);

	/* Configure the Loop filter resistance */
	for (i = 0; i < LPFR_LUT_SIZE; i++)
		if (rate <= lpfr_lut[i].vco_rate)
			break;
	if (i == LPFR_LUT_SIZE) {
		dev_err(dev, "unable to get loop filter resistance. vco=%lu\n",
				rate);
		return -EINVAL;
	}
	pll_write(base + REG_DSI_28nm_PHY_PLL_LPFR_CFG, lpfr_lut[i].resistance);

	/* Loop filter capacitance values : c1 and c2 */
	pll_write(base + REG_DSI_28nm_PHY_PLL_LPFC1_CFG, 0x70);
	pll_write(base + REG_DSI_28nm_PHY_PLL_LPFC2_CFG, 0x15);

	div_s64_rem(vco_clk_rate, ref_clk_rate, &rem);
	if (rem) {
		refclk_cfg = 0x1;
		frac_n_mode = 1;
		ref_doubler_en_b = 0;
	} else {
		refclk_cfg = 0x0;
		frac_n_mode = 0;
		ref_doubler_en_b = 1;
	}

	DBG("refclk_cfg = %lld", refclk_cfg);

	ref_clk_to_pll = ((ref_clk_rate * 2 * (refclk_cfg))
			  + (ref_doubler_en_b * ref_clk_rate));
	div_fbx1000 = div_s64((vco_clk_rate * 1000), ref_clk_to_pll);

	div_s64_rem(div_fbx1000, 1000, &rem);
	frac_n_value = div_s64((rem * (1 << 16)), 1000);
	gen_vco_clk = div_s64(div_fbx1000 * ref_clk_to_pll, 1000);

	DBG("ref_clk_to_pll = %lld", ref_clk_to_pll);
	DBG("div_fb = %lld", div_fbx1000);
	DBG("frac_n_value = %lld", frac_n_value);

	DBG("Generated VCO Clock: %lld", gen_vco_clk);
	rem = 0;
	if (frac_n_mode) {
		sdm_cfg0 = (0x0 << 5);
		sdm_cfg0 |= (0x0 & 0x3f);
		sdm_cfg1 = (div_s64(div_fbx1000, 1000) & 0x3f) - 1;
		sdm_cfg3 = div_s64_rem(frac_n_value, 256, &rem);
		sdm_cfg2 = rem;
	} else {
		sdm_cfg0 = (0x1 << 5);
		sdm_cfg0 |= (div_s64(div_fbx1000, 1000) & 0x3f) - 1;
		sdm_cfg1 = (0x0 & 0x3f);
		sdm_cfg2 = 0;
		sdm_cfg3 = 0;
	}

	DBG("sdm_cfg0=%lld", sdm_cfg0);
	DBG("sdm_cfg1=%lld", sdm_cfg1);
	DBG("sdm_cfg2=%lld", sdm_cfg2);
	DBG("sdm_cfg3=%lld", sdm_cfg3);

	cal_cfg11 = div_s64_rem(gen_vco_clk, 256 * 1000000, &rem);
	cal_cfg10 = rem / 1000000;
	DBG("cal_cfg10=%lld, cal_cfg11=%lld", cal_cfg10, cal_cfg11);

	pll_write(base + REG_DSI_28nm_PHY_PLL_CHGPUMP_CFG, 0x02);
	pll_write(base + REG_DSI_28nm_PHY_PLL_CAL_CFG3,    0x2b);
	pll_write(base + REG_DSI_28nm_PHY_PLL_CAL_CFG4,    0x66);
	pll_write(base + REG_DSI_28nm_PHY_PLL_LKDET_CFG2,  0x0d);

	pll_write(base + REG_DSI_28nm_PHY_PLL_SDM_CFG1, (u32)(sdm_cfg1 & 0xff));
	pll_write(base + REG_DSI_28nm_PHY_PLL_SDM_CFG2, (u32)(sdm_cfg2 & 0xff));
	pll_write(base + REG_DSI_28nm_PHY_PLL_SDM_CFG3, (u32)(sdm_cfg3 & 0xff));
	pll_write(base + REG_DSI_28nm_PHY_PLL_SDM_CFG4, 0x00);

	/* Add hardware recommended delay for correct PLL configuration */
	if (pll_28nm->vco_delay)
		udelay(pll_28nm->vco_delay);

	pll_write(base + REG_DSI_28nm_PHY_PLL_REFCLK_CFG, (u32)refclk_cfg);
	pll_write(base + REG_DSI_28nm_PHY_PLL_PWRGEN_CFG, 0x00);
	pll_write(base + REG_DSI_28nm_PHY_PLL_VCOLPF_CFG, 0x71);
	pll_write(base + REG_DSI_28nm_PHY_PLL_SDM_CFG0,   (u32)sdm_cfg0);
	pll_write(base + REG_DSI_28nm_PHY_PLL_CAL_CFG0,   0x12);
	pll_write(base + REG_DSI_28nm_PHY_PLL_CAL_CFG6,   0x30);
	pll_write(base + REG_DSI_28nm_PHY_PLL_CAL_CFG7,   0x00);
	pll_write(base + REG_DSI_28nm_PHY_PLL_CAL_CFG8,   0x60);
	pll_write(base + REG_DSI_28nm_PHY_PLL_CAL_CFG9,   0x00);
	pll_write(base + REG_DSI_28nm_PHY_PLL_CAL_CFG10,
		(u32)(cal_cfg10 & 0xff));
	pll_write(base + REG_DSI_28nm_PHY_PLL_CAL_CFG11,
		(u32)(cal_cfg11 & 0xff));
	pll_write(base + REG_DSI_28nm_PHY_PLL_EFUSE_CFG,  0x20);

	return 0;
}

static int dsi_pll_28nm_clk_is_enabled(struct clk_hw *hw)
{
	struct msm_dsi_pll *pll = hw_clk_to_pll(hw);
	struct dsi_pll_28nm *pll_28nm = to_pll_28nm(pll);

	return pll_28nm_poll_for_ready(pll_28nm, POLL_MAX_READS,
					POLL_TIMEOUT_US);
}

static unsigned long dsi_pll_28nm_clk_recalc_rate(struct clk_hw *hw,
		unsigned long parent_rate)
{
	struct msm_dsi_pll *pll = hw_clk_to_pll(hw);
	struct dsi_pll_28nm *pll_28nm = to_pll_28nm(pll);
	void __iomem *base = pll_28nm->mmio;
	u32 sdm0, doubler, sdm_byp_div;
	u64 vco_rate;
	u32 sdm_dc_off, sdm_freq_seed, sdm2, sdm3;
	u64 ref_clk = pll_28nm->ref_clk_rate;

	VERB("parent_rate=%lu", parent_rate);

	/* Check to see if the ref clk doubler is enabled */
	doubler = pll_read(base + REG_DSI_28nm_PHY_PLL_REFCLK_CFG) & BIT(0);
	ref_clk += (doubler * pll_28nm->ref_clk_rate);

	/* see if it is integer mode or sdm mode */
	sdm0 = pll_read(base + REG_DSI_28nm_PHY_PLL_SDM_CFG0);
	if (sdm0 & BIT(6)) {
		/* integer mode */
		sdm_byp_div = (pll_read(base + REG_DSI_28nm_PHY_PLL_SDM_CFG0) &
				0x3f) + 1;
		vco_rate = ref_clk * sdm_byp_div;
	} else {
		/* sdm mode */
		sdm_dc_off = pll_read(base + REG_DSI_28nm_PHY_PLL_SDM_CFG1) &
				0xFF;
		DBG("sdm_dc_off = %d", sdm_dc_off);
		sdm2 = pll_read(base + REG_DSI_28nm_PHY_PLL_SDM_CFG2) & 0xFF;
		sdm3 = pll_read(base + REG_DSI_28nm_PHY_PLL_SDM_CFG3) & 0xFF;
		sdm_freq_seed = (sdm3 << 8) | sdm2;
		DBG("sdm_freq_seed = %d", sdm_freq_seed);

		vco_rate = (ref_clk * (sdm_dc_off + 1)) +
			mult_frac(ref_clk, sdm_freq_seed, BIT(16));
		DBG("vco rate = %lld", vco_rate);
	}

	DBG("returning vco rate = %lu", (unsigned long)vco_rate);

	return (unsigned long)vco_rate;
}

static const struct clk_ops clk_ops_dsi_pll_28nm_vco = {
	.round_rate = msm_dsi_pll_helper_clk_round_rate,
	.set_rate = dsi_pll_28nm_clk_set_rate,
	.recalc_rate = dsi_pll_28nm_clk_recalc_rate,
	.prepare = msm_dsi_pll_helper_clk_prepare,
	.unprepare = msm_dsi_pll_helper_clk_unprepare,
	.is_enabled = dsi_pll_28nm_clk_is_enabled,
};

/*
 * PLL Callbacks
 */
static int dsi_pll_28nm_enable_seq_hpm(struct msm_dsi_pll *pll)
{
	struct dsi_pll_28nm *pll_28nm = to_pll_28nm(pll);
	struct device *dev = &pll_28nm->pdev->dev;
	void __iomem *base = pll_28nm->mmio;
	u32 max_reads = 5, timeout_us = 100;
	bool locked;
	u32 val;
	int i;

	DBG("id=%d", pll_28nm->id);

	pll_28nm_software_reset(pll_28nm);

	/*
	 * PLL power up sequence.
	 * Add necessary delays recommended by hardware.
	 */
	val = DSI_28nm_PHY_PLL_GLB_CFG_PLL_PWRDN_B;
	pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 1);

	val |= DSI_28nm_PHY_PLL_GLB_CFG_PLL_PWRGEN_PWRDN_B;
	pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 200);

	val |= DSI_28nm_PHY_PLL_GLB_CFG_PLL_LDO_PWRDN_B;
	pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 500);

	val |= DSI_28nm_PHY_PLL_GLB_CFG_PLL_ENABLE;
	pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 600);

	for (i = 0; i < 2; i++) {
		/* DSI Uniphy lock detect setting */
		pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_LKDET_CFG2,
				0x0c, 100);
		pll_write(base + REG_DSI_28nm_PHY_PLL_LKDET_CFG2, 0x0d);

		/* poll for PLL ready status */
		locked = pll_28nm_poll_for_ready(pll_28nm,
						max_reads, timeout_us);
		if (locked)
			break;

		pll_28nm_software_reset(pll_28nm);

		/*
		 * PLL power up sequence.
		 * Add necessary delays recommended by hardware.
		 */
		val = DSI_28nm_PHY_PLL_GLB_CFG_PLL_PWRDN_B;
		pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 1);

		val |= DSI_28nm_PHY_PLL_GLB_CFG_PLL_PWRGEN_PWRDN_B;
		pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 200);

		val |= DSI_28nm_PHY_PLL_GLB_CFG_PLL_LDO_PWRDN_B;
		pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 250);

		val &= ~DSI_28nm_PHY_PLL_GLB_CFG_PLL_LDO_PWRDN_B;
		pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 200);

		val |= DSI_28nm_PHY_PLL_GLB_CFG_PLL_LDO_PWRDN_B;
		pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 500);

		val |= DSI_28nm_PHY_PLL_GLB_CFG_PLL_ENABLE;
		pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 600);
	}

	if (unlikely(!locked))
		dev_err(dev, "DSI PLL lock failed\n");
	else
		DBG("DSI PLL Lock success");

	return locked ? 0 : -EINVAL;
}

static int dsi_pll_28nm_enable_seq_lp(struct msm_dsi_pll *pll)
{
	struct dsi_pll_28nm *pll_28nm = to_pll_28nm(pll);
	struct device *dev = &pll_28nm->pdev->dev;
	void __iomem *base = pll_28nm->mmio;
	bool locked;
	u32 max_reads = 10, timeout_us = 50;
	u32 val;

	DBG("id=%d", pll_28nm->id);

	pll_28nm_software_reset(pll_28nm);

	/*
	 * PLL power up sequence.
	 * Add necessary delays recommended by hardware.
	 */
	pll_write_ndelay(base + REG_DSI_28nm_PHY_PLL_CAL_CFG1, 0x34, 500);

	val = DSI_28nm_PHY_PLL_GLB_CFG_PLL_PWRDN_B;
	pll_write_ndelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 500);

	val |= DSI_28nm_PHY_PLL_GLB_CFG_PLL_PWRGEN_PWRDN_B;
	pll_write_ndelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 500);

	val |= DSI_28nm_PHY_PLL_GLB_CFG_PLL_LDO_PWRDN_B |
		DSI_28nm_PHY_PLL_GLB_CFG_PLL_ENABLE;
	pll_write_ndelay(base + REG_DSI_28nm_PHY_PLL_GLB_CFG, val, 500);

	/* DSI PLL toggle lock detect setting */
	pll_write_ndelay(base + REG_DSI_28nm_PHY_PLL_LKDET_CFG2, 0x04, 500);
	pll_write_udelay(base + REG_DSI_28nm_PHY_PLL_LKDET_CFG2, 0x05, 512);

	locked = pll_28nm_poll_for_ready(pll_28nm, max_reads, timeout_us);

	if (unlikely(!locked))
		dev_err(dev, "DSI PLL lock failed\n");
	else
		DBG("DSI PLL lock success");

	return locked ? 0 : -EINVAL;
}

static void dsi_pll_28nm_disable_seq(struct msm_dsi_pll *pll)
{
	struct dsi_pll_28nm *pll_28nm = to_pll_28nm(pll);

	DBG("id=%d", pll_28nm->id);
	pll_write(pll_28nm->mmio + REG_DSI_28nm_PHY_PLL_GLB_CFG, 0x00);
}

static void dsi_pll_28nm_save_state(struct msm_dsi_pll *pll)
{
	struct dsi_pll_28nm *pll_28nm = to_pll_28nm(pll);
	struct pll_28nm_cached_state *cached_state = &pll_28nm->cached_state;
	void __iomem *base = pll_28nm->mmio;

	cached_state->postdiv3 =
			pll_read(base + REG_DSI_28nm_PHY_PLL_POSTDIV3_CFG);
	cached_state->postdiv1 =
			pll_read(base + REG_DSI_28nm_PHY_PLL_POSTDIV1_CFG);
	cached_state->byte_mux = pll_read(base + REG_DSI_28nm_PHY_PLL_VREG_CFG);
	cached_state->vco_rate = __clk_get_rate(pll->clk_hw.clk);
}

static int dsi_pll_28nm_restore_state(struct msm_dsi_pll *pll)
{
	struct dsi_pll_28nm *pll_28nm = to_pll_28nm(pll);
	struct pll_28nm_cached_state *cached_state = &pll_28nm->cached_state;
	void __iomem *base = pll_28nm->mmio;
	int ret;

	if ((cached_state->vco_rate != 0) &&
		(cached_state->vco_rate == __clk_get_rate(pll->clk_hw.clk))) {
		ret = dsi_pll_28nm_clk_set_rate(&pll->clk_hw,
						cached_state->vco_rate, 0);
		if (ret) {
			dev_err(&pll_28nm->pdev->dev,
				"restore vco rate failed. ret=%d\n", ret);
			return ret;
		}

		pll_write(base + REG_DSI_28nm_PHY_PLL_POSTDIV3_CFG,
				cached_state->postdiv3);
		pll_write(base + REG_DSI_28nm_PHY_PLL_POSTDIV1_CFG,
				cached_state->postdiv1);
		pll_write(base + REG_DSI_28nm_PHY_PLL_VREG_CFG,
				cached_state->byte_mux);

		cached_state->vco_rate = 0;
	}

	return 0;
}

static int dsi_pll_28nm_get_provider(struct msm_dsi_pll *pll,
				struct clk **byte_clk_provider,
				struct clk **pixel_clk_provider)
{
	struct dsi_pll_28nm *pll_28nm = to_pll_28nm(pll);

	if (byte_clk_provider)
		*byte_clk_provider = pll_28nm->provided_clks[DSI_BYTE_PLL_CLK];
	if (pixel_clk_provider)
		*pixel_clk_provider =
				pll_28nm->provided_clks[DSI_PIXEL_PLL_CLK];

	return 0;
}

static void dsi_pll_28nm_destroy(struct msm_dsi_pll *pll)
{
	struct dsi_pll_28nm *pll_28nm = to_pll_28nm(pll);
	int i;

	msm_dsi_pll_helper_unregister_clks(pll_28nm->pdev,
					pll_28nm->clks, pll_28nm->num_clks);

	for (i = 0; i < NUM_PROVIDED_CLKS; i++)
		pll_28nm->provided_clks[i] = NULL;

	pll_28nm->num_clks = 0;
	pll_28nm->clk_data.clks = NULL;
	pll_28nm->clk_data.clk_num = 0;
}

static int pll_28nm_register(struct dsi_pll_28nm *pll_28nm)
{
	char clk_name[32], parent1[32], parent2[32], vco_name[32];
	struct clk_init_data vco_init = {
		.parent_names = (const char *[]){ "xo" },
		.num_parents = 1,
		.name = vco_name,
		.ops = &clk_ops_dsi_pll_28nm_vco,
	};
	struct device *dev = &pll_28nm->pdev->dev;
	struct clk **clks = pll_28nm->clks;
	struct clk **provided_clks = pll_28nm->provided_clks;
	int num = 0;
	int ret;

	DBG("%d", pll_28nm->id);

	snprintf(vco_name, 32, "dsi%dvco_clk", pll_28nm->id);
	pll_28nm->base.clk_hw.init = &vco_init;
	clks[num++] = clk_register(dev, &pll_28nm->base.clk_hw);

	snprintf(clk_name, 32, "dsi%danalog_postdiv_clk", pll_28nm->id);
	snprintf(parent1, 32, "dsi%dvco_clk", pll_28nm->id);
	clks[num++] = clk_register_divider(dev, clk_name,
			parent1, CLK_SET_RATE_PARENT,
			pll_28nm->mmio +
			REG_DSI_28nm_PHY_PLL_POSTDIV1_CFG,
			0, 4, 0, NULL);

	snprintf(clk_name, 32, "dsi%dindirect_path_div2_clk", pll_28nm->id);
	snprintf(parent1, 32, "dsi%danalog_postdiv_clk", pll_28nm->id);
	clks[num++] = clk_register_fixed_factor(dev, clk_name,
			parent1, CLK_SET_RATE_PARENT,
			1, 2);

	snprintf(clk_name, 32, "dsi%dpll", pll_28nm->id);
	snprintf(parent1, 32, "dsi%dvco_clk", pll_28nm->id);
	clks[num++] = provided_clks[DSI_PIXEL_PLL_CLK] =
			clk_register_divider(dev, clk_name,
				parent1, 0, pll_28nm->mmio +
				REG_DSI_28nm_PHY_PLL_POSTDIV3_CFG,
				0, 8, 0, NULL);

	snprintf(clk_name, 32, "dsi%dbyte_mux", pll_28nm->id);
	snprintf(parent1, 32, "dsi%dvco_clk", pll_28nm->id);
	snprintf(parent2, 32, "dsi%dindirect_path_div2_clk", pll_28nm->id);
	clks[num++] = clk_register_mux(dev, clk_name,
			(const char *[]){
				parent1, parent2
			}, 2, CLK_SET_RATE_PARENT, pll_28nm->mmio +
			REG_DSI_28nm_PHY_PLL_VREG_CFG, 1, 1, 0, NULL);

	snprintf(clk_name, 32, "dsi%dpllbyte", pll_28nm->id);
	snprintf(parent1, 32, "dsi%dbyte_mux", pll_28nm->id);
	clks[num++] = provided_clks[DSI_BYTE_PLL_CLK] =
			clk_register_fixed_factor(dev, clk_name,
				parent1, CLK_SET_RATE_PARENT, 1, 4);

	pll_28nm->num_clks = num;

	pll_28nm->clk_data.clk_num = NUM_PROVIDED_CLKS;
	pll_28nm->clk_data.clks = provided_clks;

	ret = of_clk_add_provider(dev->of_node,
			of_clk_src_onecell_get, &pll_28nm->clk_data);
	if (ret) {
		dev_err(dev, "failed to register clk provider: %d\n", ret);
		return ret;
	}

	return 0;
}

struct msm_dsi_pll *msm_dsi_pll_28nm_init(struct platform_device *pdev,
					enum msm_dsi_phy_type type, int id)
{
	struct dsi_pll_28nm *pll_28nm;
	struct msm_dsi_pll *pll;
	int ret;

	if (!pdev)
		return ERR_PTR(-ENODEV);

	pll_28nm = devm_kzalloc(&pdev->dev, sizeof(*pll_28nm), GFP_KERNEL);
	if (!pll_28nm)
		return ERR_PTR(-ENOMEM);

	pll_28nm->pdev = pdev;
	pll_28nm->id = id;
	pll_28nm->ref_clk_rate = VCO_REF_CLK_RATE;

	pll_28nm->mmio = msm_ioremap(pdev, "dsi_pll", "DSI_PLL");
	if (IS_ERR_OR_NULL(pll_28nm->mmio)) {
		dev_err(&pdev->dev, "%s: failed to map pll base\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

	pll = &pll_28nm->base;
	pll->min_rate = VCO_MIN_RATE;
	pll->max_rate = VCO_MAX_RATE;
	pll->get_provider = dsi_pll_28nm_get_provider;
	pll->destroy = dsi_pll_28nm_destroy;
	pll->disable_seq = dsi_pll_28nm_disable_seq;
	pll->save_state = dsi_pll_28nm_save_state;
	pll->restore_state = dsi_pll_28nm_restore_state;

	if (type == MSM_DSI_PHY_28NM_HPM) {
		pll_28nm->vco_delay = 1;

		pll->en_seq_cnt = 3;
		pll->enable_seqs[0] = dsi_pll_28nm_enable_seq_hpm;
		pll->enable_seqs[1] = dsi_pll_28nm_enable_seq_hpm;
		pll->enable_seqs[2] = dsi_pll_28nm_enable_seq_hpm;
	} else if (type == MSM_DSI_PHY_28NM_LP) {
		pll_28nm->vco_delay = 1000;

		pll->en_seq_cnt = 1;
		pll->enable_seqs[0] = dsi_pll_28nm_enable_seq_lp;
	} else {
		dev_err(&pdev->dev, "phy type (%d) is not 28nm\n", type);
		return ERR_PTR(-EINVAL);
	}

	ret = pll_28nm_register(pll_28nm);
	if (ret) {
		dev_err(&pdev->dev, "failed to register PLL: %d\n", ret);
		return ERR_PTR(ret);
	}

	return pll;
}

