/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __QCOM_PDR_HELPER__
#define __QCOM_PDR_HELPER__

#include <linux/soc/qcom/qmi.h>

#define SERVREG_NAME_LENGTH	64

enum servreg_service_state {
	SERVREG_LOCATOR_ERR = 0x1,
	SERVREG_LOCATOR_UNKNOWN_SERVICE = 0x2,
	SERVREG_LOCATOR_DB_UPDATED = 0x3,
	SERVREG_SERVICE_STATE_DOWN = 0x0FFFFFFF,
	SERVREG_SERVICE_STATE_UP = 0x1FFFFFFF,
	SERVREG_SERVICE_STATE_EARLY_DOWN = 0x2FFFFFFF,
	SERVREG_SERVICE_STATE_UNINIT = 0x7FFFFFFF,
};

/**
 * struct pdr_service - context to track lookups/restarts
 * @service_name:		name of the service running on the PD
 * @service_path:		service path of the PD
 * @service_data_valid:		indicates if service_data field has valid data
 * @service_data:		service data provided by servreg_locator service
 * @need_servreg_lookup:	state flag for tracking servreg lookup requests
 * @need_servreg_register:	state flag for tracking pending servreg register
 * @need_servreg_remove:	state flag for tracking pending servreg remove
 * @service_connected:		current state of servreg_notifier qmi service
 * @state:			current state of PD
 * @service:			servreg_notifer service type
 * @instance:			instance id of the @service
 * @priv:			handle for client's use
 * @node:			list_head for house keeping
 */
struct pdr_service {
	char service_name[SERVREG_NAME_LENGTH + 1];
	char service_path[SERVREG_NAME_LENGTH + 1];

	u8 service_data_valid;
	u32 service_data;

	bool need_servreg_lookup;
	bool need_servreg_register;
	bool need_servreg_remove;
	bool service_connected;
	int state;

	unsigned int instance;
	unsigned int service;

	void *priv;
	struct list_head node;
};

/**
 * struct pdr_handle - PDR context
 * @servloc_client:	servreg_locator qmi handle
 * @servreg_client:	servreg_notifier qmi handle
 * @servloc_addr:	socket addr of @servloc_client
 * @servreg_addr:	socket addr of @servreg_client
 * @lookups:		list of lookup requests
 * @indack_list:	list of qmi indications from servreg_notifier services
 * @list_lock:		lock for modifications of lists
 * @status_lock:	lock to serialize pd status call back
 * @locator_lock:	lock for the shared locator state flag
 * @locator_available:	state flag to track servreg_locator service
 * @servloc_work:	work for handling lookup requests
 * @servreg_work:	work for registering with servreg_notifier service
 * @indack_work:	work for acking the qmi indications
 * @servreg_wq:		work queue to post @servreg_work and @servdel_work on
 * @indack_wq:		work queue to post @indack_work on
 * @status:		callback to inform the client on PD service state change
 */
struct pdr_handle {
	struct qmi_handle servloc_client;
	struct qmi_handle servreg_client;

	struct sockaddr_qrtr servloc_addr;
	struct sockaddr_qrtr servreg_addr;

	struct list_head lookups;
	struct list_head indack_list;

	/* control access to pdr lookup list */
	struct mutex list_lock;

	/* serialize pd status invocation */
	struct mutex status_lock;

	/* control access to service locator state */
	struct mutex locator_lock;
	bool locator_available;

	struct work_struct servloc_work;
	struct work_struct servreg_work;
	struct work_struct indack_work;

	struct workqueue_struct *servreg_wq;
	struct workqueue_struct *indack_wq;

	void (*status)(struct pdr_handle *pdr, struct pdr_service *pds);
};

int pdr_handle_init(struct pdr_handle *pdr, void (*status)(struct pdr_handle *pdr, struct pdr_service *pds));
int pdr_add_lookup(struct pdr_handle *pdr, const char *service_name, const char *service_path);
int pdr_restart_pd(struct pdr_handle *pdr, const char *service_path);
void pdr_handle_release(struct pdr_handle *pdr);

#endif
