// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 The Linux Foundation. All rights reserved.
 */

#include <linux/completion.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/qrtr.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#include "pdr_internal.h"

struct pdr_list_node {
	enum servreg_service_state curr_state;
	u16 transaction_id;
	struct pdr_service *pds;
	struct list_head node;
};

static int servreg_locator_new_server(struct qmi_handle *qmi,
				      struct qmi_service *svc)
{
	struct pdr_handle *pdr = container_of(qmi, struct pdr_handle,
					      servloc_client);
	struct pdr_service *pds, *tmp;

	/* Create a Local client port for QMI communication */
	pdr->servloc_addr.sq_family = AF_QIPCRTR;
	pdr->servloc_addr.sq_node = svc->node;
	pdr->servloc_addr.sq_port = svc->port;

	mutex_lock(&pdr->locator_lock);
	pdr->locator_available = true;
	mutex_unlock(&pdr->locator_lock);

	/* Service pending lookup requests */
	mutex_lock(&pdr->list_lock);
	list_for_each_entry_safe(pds, tmp, &pdr->lookups, node) {
		if (pds->need_servreg_lookup)
			schedule_work(&pdr->servloc_work);
	}
	mutex_unlock(&pdr->list_lock);

	return 0;
}

static void servreg_locator_del_server(struct qmi_handle *qmi,
				       struct qmi_service *svc)
{
	struct pdr_handle *pdr = container_of(qmi, struct pdr_handle,
					      servloc_client);

	mutex_lock(&pdr->locator_lock);
	pdr->locator_available = false;
	mutex_unlock(&pdr->locator_lock);

	pdr->servloc_addr.sq_node = 0;
	pdr->servloc_addr.sq_port = 0;
}

static struct qmi_ops service_locator_ops = {
	.new_server = servreg_locator_new_server,
	.del_server = servreg_locator_del_server,
};

static int pdr_register_listener(struct pdr_handle *pdr,
				 struct pdr_service *pds,
				 bool enable)
{
	struct servreg_register_listener_resp resp;
	struct servreg_register_listener_req req;
	struct qmi_txn txn;
	int ret;

	ret = qmi_txn_init(&pdr->servreg_client, &txn,
			   servreg_register_listener_resp_ei,
			   &resp);
	if (ret < 0)
		return ret;

	req.enable = enable;
	strcpy(req.service_path, pds->service_path);

	ret = qmi_send_request(&pdr->servreg_client, &pdr->servreg_addr,
			       &txn, SERVREG_REGISTER_LISTENER_REQ,
			       SERVREG_REGISTER_LISTENER_REQ_LEN,
			       servreg_register_listener_req_ei,
			       &req);
	if (ret < 0) {
		qmi_txn_cancel(&txn);
		return ret;
	}

	ret = qmi_txn_wait(&txn, 5 * HZ);
	if (ret < 0) {
		pr_err("PDR: %s register listener txn wait failed: %d\n",
		       pds->service_path, ret);
		return ret;
	}

	/* Check the response */
	if (resp.resp.result != QMI_RESULT_SUCCESS_V01) {
		pr_err("PDR: %s register listener failed: 0x%x\n",
		       pds->service_path, resp.resp.error);
		return ret;
	}

	if ((int)resp.curr_state < INT_MIN || (int)resp.curr_state > INT_MAX)
		pr_err("PDR: %s notification state invalid: 0x%x\n",
		       pds->service_path, resp.curr_state);

	pds->state = resp.curr_state;

	return 0;
}

static void pdr_servreg_work(struct work_struct *work)
{
	struct pdr_handle *pdr = container_of(work, struct pdr_handle,
					      servreg_work);
	struct pdr_service *pds, *tmp;

	mutex_lock(&pdr->list_lock);
	list_for_each_entry_safe(pds, tmp, &pdr->lookups, node) {
		if (pds->service_connected) {
			if (!pds->need_servreg_register)
				continue;

			pds->need_servreg_register = false;
			mutex_unlock(&pdr->list_lock);
			pdr_register_listener(pdr, pds, true);
		} else {
			if (!pds->need_servreg_remove)
				continue;

			pds->need_servreg_remove = false;
			mutex_unlock(&pdr->list_lock);
			pds->state = SERVREG_SERVICE_STATE_DOWN;
		}

		mutex_lock(&pdr->status_lock);
		pdr->status(pdr, pds);
		mutex_unlock(&pdr->status_lock);

		return;
	}
	mutex_unlock(&pdr->list_lock);
}

static int servreg_notifier_new_server(struct qmi_handle *qmi,
				       struct qmi_service *svc)
{
	struct pdr_handle *pdr = container_of(qmi, struct pdr_handle,
					      servreg_client);
	struct pdr_service *pds, *tmp;

	/* Create a Local client port for QMI communication */
	pdr->servreg_addr.sq_family = AF_QIPCRTR;
	pdr->servreg_addr.sq_node = svc->node;
	pdr->servreg_addr.sq_port = svc->port;

	mutex_lock(&pdr->list_lock);
	list_for_each_entry_safe(pds, tmp, &pdr->lookups, node) {
		if (pds->service == svc->service &&
		    pds->instance == svc->instance) {
			pds->service_connected = true;
			pds->need_servreg_register = true;
			queue_work(pdr->servreg_wq, &pdr->servreg_work);
		}
	}
	mutex_unlock(&pdr->list_lock);

	return 0;
}

static void servreg_notifier_del_server(struct qmi_handle *qmi,
					struct qmi_service *svc)
{
	struct pdr_handle *pdr = container_of(qmi, struct pdr_handle,
					      servreg_client);
	struct pdr_service *pds, *tmp;

	pdr->servreg_addr.sq_node = 0;
	pdr->servreg_addr.sq_port = 0;

	mutex_lock(&pdr->list_lock);
	list_for_each_entry_safe(pds, tmp, &pdr->lookups, node) {
		if (pds->service == svc->service &&
		    pds->instance == svc->instance) {
			pds->service_connected = false;
			pds->need_servreg_remove = true;
			queue_work(pdr->servreg_wq, &pdr->servreg_work);
		}
	}
	mutex_unlock(&pdr->list_lock);
}

static struct qmi_ops service_notifier_ops = {
	.new_server = servreg_notifier_new_server,
	.del_server = servreg_notifier_del_server,
};

static int pdr_send_indack_msg(struct pdr_handle *pdr, struct pdr_service *pds,
			       u16 tid)
{
	struct servreg_set_ack_resp resp;
	struct servreg_set_ack_req req;
	struct qmi_txn txn;
	int ret;

	ret = qmi_txn_init(&pdr->servreg_client, &txn, servreg_set_ack_resp_ei,
			   &resp);
	if (ret < 0)
		return ret;

	req.transaction_id = tid;
	strcpy(req.service_path, pds->service_path);

	ret = qmi_send_request(&pdr->servreg_client, &pdr->servreg_addr,
			       &txn, SERVREG_SET_ACK_REQ,
			       SERVREG_SET_ACK_REQ_LEN,
			       servreg_set_ack_req_ei,
			       &req);

	/* Skip waiting for response */
	qmi_txn_cancel(&txn);
	return ret;
}

static void pdr_indack_work(struct work_struct *work)
{
	struct pdr_handle *pdr = container_of(work, struct pdr_handle,
					      indack_work);
	struct pdr_list_node *ind, *tmp;
	struct pdr_service *pds;

	list_for_each_entry_safe(ind, tmp, &pdr->indack_list, node) {
		pds = ind->pds;
		pdr_send_indack_msg(pdr, pds, ind->transaction_id);
		mutex_lock(&pdr->status_lock);
		pds->state = ind->curr_state;
		pdr->status(pdr, pds);
		mutex_unlock(&pdr->status_lock);
		list_del(&ind->node);
		kfree(ind);
	}
}

static void pdr_servreg_ind_cb(struct qmi_handle *qmi,
			       struct sockaddr_qrtr *sq,
			       struct qmi_txn *txn, const void *data)
{
	struct pdr_handle *pdr = container_of(qmi, struct pdr_handle,
					      servreg_client);
	const struct servreg_state_updated_ind *ind_msg = data;
	struct pdr_list_node *ind;
	struct pdr_service *pds;

	if (!ind_msg || !ind_msg->service_path[0] ||
	    strlen(ind_msg->service_path) > SERVREG_NAME_LENGTH)
		return;

	list_for_each_entry(pds, &pdr->lookups, node) {
		if (!strcmp(pds->service_path, ind_msg->service_path))
			goto found;
	}
	return;

found:
	ind = kzalloc(sizeof(*ind), GFP_KERNEL);
	if (!ind)
		return;

	pr_info("PDR: Indication received from %s, state: 0x%x, trans-id: %d\n",
		ind_msg->service_path, ind_msg->curr_state,
		ind_msg->transaction_id);

	ind->transaction_id = ind_msg->transaction_id;
	ind->curr_state = ind_msg->curr_state;
	ind->pds = pds;

	mutex_lock(&pdr->list_lock);
	list_add_tail(&ind->node, &pdr->indack_list);
	mutex_unlock(&pdr->list_lock);

	queue_work(pdr->indack_wq, &pdr->indack_work);
}

static struct qmi_msg_handler qmi_indication_handler[] = {
	{
		.type = QMI_INDICATION,
		.msg_id = SERVREG_STATE_UPDATED_IND_ID,
		.ei = servreg_state_updated_ind_ei,
		.decoded_size = sizeof(struct servreg_state_updated_ind),
		.fn = pdr_servreg_ind_cb,
	},
	{}
};

static int pdr_get_domain_list(struct servreg_get_domain_list_req *req,
			       struct servreg_get_domain_list_resp *resp,
			       struct pdr_handle *pdr)
{
	struct qmi_txn txn;
	int ret;

	ret = qmi_txn_init(&pdr->servloc_client, &txn,
			   servreg_get_domain_list_resp_ei, resp);
	if (ret < 0)
		return ret;

	ret = qmi_send_request(&pdr->servloc_client,
			       &pdr->servloc_addr,
			       &txn, SERVREG_GET_DOMAIN_LIST_REQ,
			       SERVREG_GET_DOMAIN_LIST_REQ_MAX_LEN,
			       servreg_get_domain_list_req_ei,
			       req);
	if (ret < 0) {
		qmi_txn_cancel(&txn);
		return ret;
	}

	ret = qmi_txn_wait(&txn, 5 * HZ);
	if (ret < 0) {
		pr_err("PDR: %s get domain list txn wait failed: %d\n",
		       req->service_name, ret);
		return ret;
	}

	/* Check the response */
	if (resp->resp.result != QMI_RESULT_SUCCESS_V01) {
		pr_err("PDR: %s get domain list failed: 0x%x\n",
		       req->service_name, resp->resp.error);
		return -EREMOTEIO;
	}

	return 0;
}

static void pdr_servreg_link_create(struct pdr_handle *pdr,
				    struct pdr_service *pds)
{
	struct pdr_service *pds_iter, *tmp;
	bool link_exists = false;

	/* Check if a QMI link to SERVREG instance already exists */
	mutex_lock(&pdr->list_lock);
	list_for_each_entry_safe(pds_iter, tmp, &pdr->lookups, node) {
		if (pds_iter->instance == pds->instance &&
		    strcmp(pds_iter->service_path, pds->service_path)) {
			link_exists = true;
			pds->service_connected = pds_iter->service_connected;
			if (pds_iter->service_connected)
				pds->need_servreg_register = true;
			else
				pds->need_servreg_remove = true;
			queue_work(pdr->servreg_wq, &pdr->servreg_work);
			break;
		}
	}
	mutex_unlock(&pdr->list_lock);

	if (!link_exists)
		qmi_add_lookup(&pdr->servreg_client, pds->service, 1,
			       pds->instance);
}

static int pdr_locate_service(struct pdr_handle *pdr, struct pdr_service *pds)
{
	struct servreg_get_domain_list_resp *resp = NULL;
	struct servreg_get_domain_list_req req;
	int db_rev_count = 0, domains_read = 0;
	struct servreg_location_entry *entry;
	int ret, i;

	resp = kzalloc(sizeof(*resp), GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	/* Prepare req message */
	strcpy(req.service_name, pds->service_name);
	req.domain_offset_valid = true;
	req.domain_offset = 0;

	do {
		req.domain_offset = domains_read;
		ret = pdr_get_domain_list(&req, resp, pdr);
		if (ret < 0)
			goto out;

		if (!domains_read)
			db_rev_count = resp->db_rev_count;

		if (db_rev_count != resp->db_rev_count) {
			ret = -EAGAIN;
			goto out;
		}

		for (i = domains_read; i < resp->domain_list_len; i++) {
			entry = &resp->domain_list[i];

			if (strnlen(entry->name, sizeof(entry->name)) == sizeof(entry->name))
				continue;

			if (!strcmp(entry->name, pds->service_path)) {
				pds->service_data_valid = entry->service_data_valid;
				pds->service_data = entry->service_data;
				pds->instance = entry->instance;
				goto out;
			}
		}

		/* Update ret to indicate that the service is not yet found */
		ret = -ENXIO;

		/* Always read total_domains from the response msg */
		if (resp->domain_list_len > resp->total_domains)
			resp->domain_list_len = resp->total_domains;

		domains_read += resp->domain_list_len;
	} while (domains_read < resp->total_domains);
out:
	kfree(resp);
	return ret;
}

static void pdr_servloc_work(struct work_struct *work)
{
	struct pdr_handle *pdr = container_of(work, struct pdr_handle,
					      servloc_work);
	struct pdr_service *pds, *tmp;
	int ret;

	/* Bail out early if PD Mapper is not up */
	mutex_lock(&pdr->locator_lock);
	if (!pdr->locator_available) {
		mutex_unlock(&pdr->locator_lock);
		pr_warn("PDR: SERVICE LOCATOR service not available\n");
		return;
	}
	mutex_unlock(&pdr->locator_lock);

	mutex_lock(&pdr->list_lock);
	list_for_each_entry_safe(pds, tmp, &pdr->lookups, node) {
		if (!pds->need_servreg_lookup)
			continue;

		pds->need_servreg_lookup = false;
		mutex_unlock(&pdr->list_lock);

		ret = pdr_locate_service(pdr, pds);
		if (ret < 0) {
			if (ret == -ENXIO)
				pds->state = SERVREG_LOCATOR_UNKNOWN_SERVICE;
			else if (ret == -EAGAIN)
				pds->state = SERVREG_LOCATOR_DB_UPDATED;
			else
				pds->state = SERVREG_LOCATOR_ERR;

			pr_err("PDR: service lookup for %s failed: %d\n",
			       pds->service_name, ret);

			/* Remove from lookup list */
			mutex_lock(&pdr->list_lock);
			list_del(&pds->node);
			mutex_unlock(&pdr->list_lock);

			/* Notify Lookup failed */
			mutex_lock(&pdr->status_lock);
			pdr->status(pdr, pds);
			mutex_unlock(&pdr->status_lock);
			kfree(pds);
		} else {
			pdr_servreg_link_create(pdr, pds);
		}

		return;
	}
	mutex_unlock(&pdr->list_lock);
}

/**
 * pdr_add_lookup() - register a tracking request for a PD
 * @pdr:		PDR client handle
 * @service_name:	service name of the tracking request
 * @service_path:	service path of the tracking request
 *
 * Registering a pdr lookup allows for tracking the life cycle of the PD.
 *
 * Return: 0 on success, negative errno on failure.
 */
int pdr_add_lookup(struct pdr_handle *pdr, const char *service_name,
		   const char *service_path)
{
	struct pdr_service *pds, *pds_iter, *tmp;
	int ret;

	if (!service_name || strlen(service_name) > SERVREG_NAME_LENGTH ||
	    !service_path || strlen(service_path) > SERVREG_NAME_LENGTH)
		return -EINVAL;

	pds = kzalloc(sizeof(*pds), GFP_KERNEL);
	if (!pds)
		return -ENOMEM;

	pds->service = SERVREG_NOTIFIER_SERVICE;
	strcpy(pds->service_name, service_name);
	strcpy(pds->service_path, service_path);
	pds->need_servreg_lookup = true;

	mutex_lock(&pdr->list_lock);
	list_for_each_entry_safe(pds_iter, tmp, &pdr->lookups, node) {
		if (!strcmp(pds_iter->service_path, service_path)) {
			mutex_unlock(&pdr->list_lock);
			ret = -EALREADY;
			goto err;
		}
	}

	list_add(&pds->node, &pdr->lookups);
	mutex_unlock(&pdr->list_lock);

	schedule_work(&pdr->servloc_work);

	return 0;
err:
	kfree(pds);

	return ret;
}
EXPORT_SYMBOL(pdr_add_lookup);

/**
 * pdr_restart_pd() - restart PD
 * @pdr:		PDR client handle
 * @service_path:	service path of restart request
 *
 * Restarts the PD tracked by the PDR client handle for a given service path.
 *
 * Return: 0 on success, negative errno on failure.
 */
int pdr_restart_pd(struct pdr_handle *pdr, const char *service_path)
{
	struct servreg_restart_pd_req req;
	struct servreg_restart_pd_resp resp;
	struct pdr_service *pds = NULL, *pds_iter, *tmp;
	struct qmi_txn txn;
	int ret;

	if (!service_path || strlen(service_path) > SERVREG_NAME_LENGTH)
		return -EINVAL;

	mutex_lock(&pdr->list_lock);
	list_for_each_entry_safe(pds_iter, tmp, &pdr->lookups, node) {
		if (!pds_iter->service_connected)
			continue;

		if (!strcmp(pds_iter->service_path, service_path)) {
			pds = pds_iter;
			break;
		}
	}
	mutex_unlock(&pdr->list_lock);

	if (!pds)
		return -EINVAL;

	/* Prepare req message */
	strcpy(req.service_path, pds->service_path);

	ret = qmi_txn_init(&pdr->servreg_client, &txn,
			   servreg_restart_pd_resp_ei,
			   &resp);
	if (ret < 0)
		return ret;

	ret = qmi_send_request(&pdr->servreg_client, &pdr->servreg_addr,
			       &txn, SERVREG_RESTART_PD_REQ,
			       SERVREG_RESTART_PD_REQ_MAX_LEN,
			       servreg_restart_pd_req_ei, &req);
	if (ret < 0) {
		qmi_txn_cancel(&txn);
		return ret;
	}

	ret = qmi_txn_wait(&txn, 5 * HZ);
	if (ret < 0) {
		pr_err("PDR: %s PD restart txn wait failed: %d\n",
		       pds->service_path, ret);
		return ret;
	}

	/* Check response if PDR is disabled */
	if (resp.resp.result == QMI_RESULT_FAILURE_V01 &&
	    resp.resp.error == QMI_ERR_DISABLED_V01) {
		pr_err("PDR: %s PD restart is disabled: 0x%x\n",
		       pds->service_path, resp.resp.error);
		return -EOPNOTSUPP;
	}

	/* Check the response for other error case*/
	if (resp.resp.result != QMI_RESULT_SUCCESS_V01) {
		pr_err("PDR: %s request for PD restart failed: 0x%x\n",
		       pds->service_path, resp.resp.error);
		return -EREMOTEIO;
	}

	return ret;
}
EXPORT_SYMBOL(pdr_restart_pd);

/**
 * pdr_handle_init() - initialize the PDR client handle
 * @pdr:	PDR client handle
 * @status:	function to be called on PD state change
 *
 * Initializes the PDR client handle to allow for tracking/restart of PDs.
 *
 * Return: 0 on success, negative errno on failure.
 */
int pdr_handle_init(struct pdr_handle *pdr,
		    void (*status)(struct pdr_handle *pdr,
				   struct pdr_service *pds))
{
	int ret;

	if (!status)
		return -EINVAL;

	pdr->status = *status;

	mutex_init(&pdr->locator_lock);
	mutex_init(&pdr->list_lock);
	mutex_init(&pdr->status_lock);

	INIT_LIST_HEAD(&pdr->lookups);
	INIT_LIST_HEAD(&pdr->indack_list);

	INIT_WORK(&pdr->servloc_work, pdr_servloc_work);
	INIT_WORK(&pdr->servreg_work, pdr_servreg_work);
	INIT_WORK(&pdr->indack_work, pdr_indack_work);

	pdr->servreg_wq = create_singlethread_workqueue("pdr_servreg_wq");
	if (!pdr->servreg_wq)
		return -ENOMEM;

	pdr->indack_wq = alloc_ordered_workqueue("pdr_indack_wq", WQ_HIGHPRI);
	if (!pdr->indack_wq) {
		ret = -ENOMEM;
		goto destroy_servreg;
	}

	ret = qmi_handle_init(&pdr->servloc_client,
			      SERVREG_GET_DOMAIN_LIST_RESP_MAX_LEN,
			      &service_locator_ops, NULL);
	if (ret < 0)
		goto destroy_indack;

	ret = qmi_handle_init(&pdr->servreg_client,
			      SERVREG_STATE_UPDATED_IND_MAX_LEN,
			      &service_notifier_ops, qmi_indication_handler);
	if (ret < 0)
		goto release_handle;

	qmi_add_lookup(&pdr->servloc_client, SERVREG_LOCATOR_SERVICE, 1, 1);

	return 0;

release_handle:
	qmi_handle_release(&pdr->servloc_client);
destroy_indack:
	destroy_workqueue(pdr->indack_wq);
destroy_servreg:
	destroy_workqueue(pdr->servreg_wq);

	return ret;
}
EXPORT_SYMBOL(pdr_handle_init);

/**
 * pdr_handle_release() - release the PDR client handle
 * @pdr:	PDR client handle
 *
 * Cleans up pending tracking requests and releases the underlying qmi handles.
 */
void pdr_handle_release(struct pdr_handle *pdr)
{
	struct pdr_service *pds, *tmp;

	mutex_lock(&pdr->list_lock);
	list_for_each_entry_safe(pds, tmp, &pdr->lookups, node) {
		list_del(&pds->node);
		kfree(pds);
	}
	mutex_unlock(&pdr->list_lock);

	cancel_work_sync(&pdr->servloc_work);
	cancel_work_sync(&pdr->servreg_work);
	cancel_work_sync(&pdr->indack_work);

	destroy_workqueue(pdr->servreg_wq);
	destroy_workqueue(pdr->indack_wq);

	qmi_handle_release(&pdr->servloc_client);
	qmi_handle_release(&pdr->servreg_client);
}
EXPORT_SYMBOL(pdr_handle_release);
