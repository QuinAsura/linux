/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019, The Linux Foundation. All rights reserved.
 */

#ifndef __DRIVERS_INTERCONNECT_QCOM_OSM_L3_H
#define __DRIVERS_INTERCONNECT_QCOM_OSM_L3_H

int qcom_icc_osm_l3_request(u32 avg_bw, u32 peak_bw, u16 buswidth);
int qcom_osm_l3_init(struct platform_device *pdev);

#endif
