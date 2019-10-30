/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PDR_HELPER__
#define __PDR_HELPER__

#include <linux/soc/qcom/qmi.h>

#define SERVREG_NAME_LENGTH	64

enum servreg_service_state {
	SERVREG_NOTIF_SERVICE_STATE_DOWN = 0x0FFFFFFF,
	SERVREG_NOTIF_SERVICE_STATE_UP = 0x1FFFFFFF,
	SERVREG_NOTIF_SERVICE_STATE_EARLY_DOWN = 0x2FFFFFFF,
	SERVREG_NOTIF_SERVICE_STATE_UNINIT = 0x7FFFFFFF,
};

struct pd_status {
	char service_name[SERVREG_NAME_LENGTH + 1];
	char service_path[SERVREG_NAME_LENGTH + 1];
	u8 service_data_valid;

	bool connected;

	unsigned int instance;
	unsigned int service;

	u32 service_data;
	int state;

	struct list_head node;
};

struct pdr_handle {
	struct qmi_handle servloc_client;
	struct qmi_handle servreg_client;

	struct sockaddr_qrtr servloc_addr;
	struct sockaddr_qrtr servreg_addr;

	struct list_head lookups;
	struct list_head servreg_list;
	struct list_head servdel_list;
	struct list_head indack_list;

	struct completion locator_available;
	struct completion servreg_available;

	struct work_struct servreg_work;
	struct work_struct servdel_work;
	struct work_struct indack_work;

	struct workqueue_struct *servreg_wq;
	struct workqueue_struct *indack_wq;

	int(*status)(struct pdr_handle *pdr, struct pd_status *pds);
};

int pdr_handle_init(struct pdr_handle *pdr, int (*status)(struct pdr_handle *pdr, struct pd_status *pds));
int pdr_add_lookup(struct pdr_handle *pdr, const char *service_name, const char *service_path);
/* int pdr_restart_pd(struct pdr_handle *pdr, const char *service_name, const char *service_path); */
void pdr_handle_release(struct pdr_handle *pdr);

#endif
