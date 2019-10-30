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

struct indack_node {
	char service_path[SERVREG_NAME_LENGTH + 1];
	u16 transaction_id;
	struct pd_status *pds;
	struct list_head node;
};

struct servreg_node {
	char service_path[SERVREG_NAME_LENGTH + 1];
	struct pd_status *pds;
	struct list_head node;
};

static int service_locator_new_server(struct qmi_handle *qmi,
				      struct qmi_service *svc)
{
	struct pdr_handle *pdr = container_of(qmi, struct pdr_handle, servloc_client);

	/* Create a Local client port for QMI communication */
	pdr->servloc_addr.sq_family = AF_QIPCRTR;
	pdr->servloc_addr.sq_node = svc->node;
	pdr->servloc_addr.sq_port = svc->port;

	complete_all(&pdr->locator_available);

	return 0;
}

static void service_locator_del_server(struct qmi_handle *qmi,
				       struct qmi_service *svc)
{
	struct pdr_handle *pdr = container_of(qmi, struct pdr_handle, servloc_client);

	reinit_completion(&pdr->locator_available);
}

static struct qmi_ops service_locator_ops = {
	.new_server = service_locator_new_server,
	.del_server = service_locator_del_server,
};

static int pdr_send_servreg(struct pdr_handle *pdr, struct pd_status *pds, bool enable)
{
	struct servreg_notif_register_listener_resp_msg resp;
	struct servreg_notif_register_listener_req_msg req;
	struct qmi_txn txn;
	int ret;

	ret = qmi_txn_init(&pdr->servreg_client, &txn,
			   servreg_notif_register_listener_resp_msg_ei,
			   &resp);

	if (ret < 0) {
		pr_err("QMI tx init failed , ret - %d\n", ret);
		return ret;
	}

	req.enable = enable;
	snprintf(req.service_path, ARRAY_SIZE(req.service_path), "%s",
		 pds->service_path);

	ret = qmi_send_request(&pdr->servreg_client, &pdr->servreg_addr,
			       &txn, SERVREG_NOTIF_REGISTER_LISTENER_REQ,
			       SERVREG_NOTIF_REGISTER_LISTENER_REQ_MSG_LEN,
			       servreg_notif_register_listener_req_msg_ei,
			       &req);
	if (ret < 0) {
		pr_err("QMI send req failed, ret - %d\n", ret);
		qmi_txn_cancel(&txn);
		return ret;
	}

	ret = qmi_txn_wait(&txn, 5 * HZ);
	if (ret < 0) {
		pr_err("QMI qmi txn wait failed, ret - %d\n", ret);
		return ret;
	}

	/* Check the response */
	if (resp.resp.result != QMI_RESULT_SUCCESS_V01) {
		pr_err("QMI request failed 0x%x\n", resp.resp.error);
		return ret;
	}

	if ((int) resp.curr_state < INT_MIN ||
				(int) resp.curr_state > INT_MAX)
		pr_err("Invalid indication notification state %d\n",
		       resp.curr_state);

	pds->state = resp.curr_state;

	return 0;
}

static void pdr_servreg_work(struct work_struct *work)
{
	struct pdr_handle *pdr = container_of(work, struct pdr_handle, servreg_work);
	struct servreg_node *servreg, *tmp;
	struct pd_status *pds;

	if (!list_empty(&pdr->servreg_list)) {
		list_for_each_entry_safe(servreg, tmp, &pdr->servreg_list, node) {
			pds = servreg->pds;
			if (pdr_send_servreg(pdr, pds, true))
				pds->connected = true;
			pdr->status(pdr, pds);
			list_del(&servreg->node);
			kfree(servreg);
		}
	}
}

static int service_notifier_new_server(struct qmi_handle *qmi,
				       struct qmi_service *svc)
{
	struct pdr_handle *pdr = container_of(qmi, struct pdr_handle, servreg_client);
	struct servreg_node *servreg;
	struct pd_status *pds, *tmp;

	/* Create a Local client port for QMI communication */
	pdr->servreg_addr.sq_family = AF_QIPCRTR;
	pdr->servreg_addr.sq_node = svc->node;
	pdr->servreg_addr.sq_port = svc->port;

	servreg = kzalloc(sizeof(*servreg), GFP_KERNEL);
	if (!servreg)
		return -ENOMEM;

	list_for_each_entry_safe(pds, tmp, &pdr->lookups, node) {
		if ((pds->service == svc->service) && (pds->instance == svc->instance)) {
			servreg->pds = pds;
			list_add_tail(&servreg->node, &pdr->servreg_list);
			break;
		}
	}

	queue_work(pdr->servreg_wq, &pdr->servreg_work);

	return 0;
}

static void pdr_servdel_work(struct work_struct *work)
{
	struct pdr_handle *pdr = container_of(work, struct pdr_handle, servdel_work);
	struct servreg_node *servreg, *tmp;
	struct pd_status *pds;

	if (!list_empty(&pdr->servdel_list)) {
		list_for_each_entry_safe(servreg, tmp, &pdr->servdel_list, node) {
			pds = servreg->pds;
			pds->state = SERVREG_NOTIF_SERVICE_STATE_DOWN;
			pdr->status(pdr, pds);
			list_del(&servreg->node);
			kfree(servreg);
		}
	}
}

static void service_notifier_del_server(struct qmi_handle *qmi,
					struct qmi_service *svc)
{
	struct pdr_handle *pdr = container_of(qmi, struct pdr_handle, servreg_client);
	struct servreg_node *servreg;
	struct pd_status *pds, *tmp;

	servreg = kzalloc(sizeof(*servreg), GFP_KERNEL);
	if (!servreg)
		return;

	list_for_each_entry_safe(pds, tmp, &pdr->lookups, node) {
		if ((pds->service == svc->service) && (pds->instance == svc->instance)) {
			servreg->pds = pds;
			list_add_tail(&servreg->node, &pdr->servdel_list);
			break;
		}
	}

	queue_work(pdr->servreg_wq, &pdr->servdel_work);
}

static struct qmi_ops service_notifier_ops = {
	.new_server = service_notifier_new_server,
	.del_server = service_notifier_del_server,
};

static int pdr_send_indack_msg(struct pdr_handle *pdr, struct indack_node *ind)
{
	struct servreg_notif_set_ack_resp_msg resp;
	struct servreg_notif_set_ack_req_msg req;
	struct qmi_txn txn;
	int ret;

	ret = qmi_txn_init(&pdr->servreg_client, &txn, servreg_notif_set_ack_resp_msg_ei,
			   &resp);
	if (ret < 0) {
		pr_err("QMI tx init failed , ret - %d\n", ret);
		return ret;
	}

	req.transaction_id = ind->transaction_id;
	snprintf(req.service_path, ARRAY_SIZE(req.service_path), "%s",
		 ind->service_path);

	ret = qmi_send_request(&pdr->servreg_client, &pdr->servreg_addr,
			       &txn, SERVREG_NOTIF_SET_ACK_REQ,
			       SERVREG_NOTIF_SET_ACK_REQ_MSG_LEN,
			       servreg_notif_set_ack_req_msg_ei,
			       &req);
	if (ret < 0) {
		pr_err("QMI send ACK failed, ret - %d\n", ret);
		qmi_txn_cancel(&txn);
		return ret;
	}

	ret = qmi_txn_wait(&txn, 5 * HZ);
	if (ret < 0) {
		pr_err("QMI qmi txn wait failed, ret - %d\n", ret);
		return ret;
	}

	/* Check the response */
	if (resp.resp.result != QMI_RESULT_SUCCESS_V01)
		pr_err("QMI request failed 0x%x\n", resp.resp.error);
	else
		pr_err("QMI ack success\n");

	return 0;
}

static void pdr_indack_work(struct work_struct *work) {
	struct pdr_handle *pdr = container_of(work, struct pdr_handle, indack_work);
	struct indack_node *ind, *tmp;
	struct pd_status *pds;

	if (!list_empty(&pdr->indack_list)) {
		list_for_each_entry_safe(ind, tmp, &pdr->indack_list, node) {
			pdr_send_indack_msg(pdr, ind);
			pds = ind->pds;
			pdr->status(pdr, pds);
			list_del(&ind->node);
			kfree(ind);
		}
	}
}

static void pdr_servreg_ind_cb(struct qmi_handle *qmi,
			       struct sockaddr_qrtr *sq,
			       struct qmi_txn *txn, const void *data)
{
	struct pdr_handle *pdr = container_of(qmi, struct pdr_handle, servreg_client);
	struct servreg_notif_state_updated_ind_msg *ind_msg =
		((struct servreg_notif_state_updated_ind_msg *)data);
	struct pd_status *pds, *tmp;
	struct indack_node *ind;

	list_for_each_entry_safe(pds, tmp, &pdr->lookups, node) {
		if (!strncmp(pds->service_path, ind_msg->service_path,
			     SERVREG_NAME_LENGTH + 1)) {
			pds->state = ind_msg->curr_state;
			break;
		}
	}

	if (!pds)
		return;

	ind = kzalloc(sizeof(*ind), GFP_KERNEL);
	if (!ind)
		return;

	pr_info("Indication received from %s, state: 0x%x, trans-id: %d\n",
		ind_msg->service_path, ind_msg->curr_state,
		ind_msg->transaction_id);

	ind->pds = pds;
	ind->transaction_id = ind_msg->transaction_id;
	snprintf(ind->service_path, ARRAY_SIZE(ind->service_path), "%s",
		 ind_msg->service_path);

	list_add_tail(&ind->node, &pdr->indack_list);
	queue_work(pdr->indack_wq, &pdr->indack_work);
}

static struct qmi_msg_handler qmi_indication_handler[] = {
	{
		.type = QMI_INDICATION,
		.msg_id = SERVREG_NOTIF_STATE_UPDATED_IND_MSG_ID,
		.ei = servreg_notif_state_updated_ind_msg_ei,
		.decoded_size = sizeof(struct servreg_notif_state_updated_ind_msg),
		.fn = pdr_servreg_ind_cb,
	},
	{}
};

static int pdr_get_domain_list(struct servreg_loc_get_domain_list_req_msg *req,
			       struct servreg_loc_get_domain_list_resp_msg *resp,
			       struct pdr_handle *pdr)
{
	struct qmi_txn txn;
	int ret;

	ret = qmi_txn_init(&pdr->servloc_client, &txn,
			   servreg_loc_get_domain_list_resp_msg_ei, resp);
	if (ret < 0) {
		pr_err("QMI tx init failed ret - %d\n", ret);
		return ret;
	}

	ret = qmi_send_request(&pdr->servloc_client,
			       &pdr->servloc_addr,
			       &txn, SERVREG_LOC_GET_DOMAIN_LIST_REQ,
			       SERVREG_LOC_GET_DOMAIN_LIST_REQ_MAX_MSG_LEN,
			       servreg_loc_get_domain_list_req_msg_ei,
			       req);
	if (ret < 0) {
		pr_err("QMI send req failed ret - %d\n", ret);
		qmi_txn_cancel(&txn);
		return ret;
	}

	ret = qmi_txn_wait(&txn, 5 * HZ);
	if (ret < 0) {
		pr_err("QMI qmi txn wait failed ret - %d\n", ret);
		return ret;
	}

	/* Check the response */
	if (resp->resp.result != QMI_RESULT_SUCCESS_V01) {
		pr_err("QMI request failed 0x%x\n", resp->resp.error);
		return -EREMOTEIO;
	}

	return ret;
}

static int pdr_locate_service(struct pdr_handle *pdr, struct pd_status *pds)
{
	struct servreg_loc_get_domain_list_resp_msg *resp = NULL;
	struct servreg_loc_get_domain_list_req_msg *req = NULL;
	int domains_read = 0;
	int ret, i;

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		pr_err("Unable to allocate memory for req message\n");
		ret = -ENOMEM;
		goto out;
	}

	resp = kzalloc(sizeof(*resp), GFP_KERNEL);
	if (!resp) {
		pr_err("Unable to allocate memory for resp message\n");
		ret = -ENOMEM;
		goto out;
	}

	/* Prepare req and response message */
	strlcpy(req->service_name, pds->service_name, SERVREG_NAME_LENGTH + 1);
	req->domain_offset_valid = true;
	req->domain_offset = 0;

	do {
		/* Need to check this logic */
		req->domain_offset = domains_read;
		ret = pdr_get_domain_list(req, resp, pdr);
		if (ret < 0) {
			pr_err("send msg failed ret:%d\n", ret);
			goto out;
		}

		for (i = domains_read; i < resp->domain_list_len; i++) {
			if (!strncmp(resp->domain_list[i].name, pds->service_path, SERVREG_NAME_LENGTH + 1)) {
				pds->service_data_valid = resp->domain_list[i].service_data_valid;
				pds->service_data = resp->domain_list[i].service_data;
				pds->instance = resp->domain_list[i].instance;
				goto out;
			}
		}

		/* Always read total_domains from the response msg */
		if (resp->domain_list_len >  resp->total_domains)
			resp->domain_list_len = resp->total_domains;
		domains_read += resp->domain_list_len;

		/* Update ret to indicate that the service is not yet found */
		ret = -EINVAL;
	} while (domains_read < resp->total_domains);
out:
	kfree(req);
	kfree(resp);
	return ret;
}

int pdr_add_lookup(struct pdr_handle *pdr, const char *service_name,
		   const char *service_path)
{
	struct pd_status *pds, *tmp;
	int ret;

	if (!service_name && !service_path)
		return -EINVAL;

	if (!list_empty(&pdr->lookups)) {
		list_for_each_entry_safe(pds, tmp, &pdr->lookups, node) {
			if (!strncmp(pds->service_path, service_path, SERVREG_NAME_LENGTH + 1))
				return -EALREADY;
		}
	}

	pds = kzalloc(sizeof(*pds), GFP_KERNEL);
	if (!pds)
		return -ENOMEM;

	pds->service = SERVREG_NOTIF_SERVICE; 
	strlcpy(pds->service_name, service_name, ARRAY_SIZE(pds->service_name));
	strlcpy(pds->service_path, service_path, ARRAY_SIZE(pds->service_path));

	list_add(&pds->node, &pdr->lookups);

	/* wait for PD Mapper to come up */
	ret = wait_for_completion_timeout(&pdr->locator_available, 10 * HZ);
	if (!ret) {
		pr_err("timed out waiting for PD Mapper\n");
		ret = -ETIMEDOUT;
		goto err;
	}

	ret = pdr_locate_service(pdr, pds);
	if (ret < 0) {
		pr_err("Failed to find %s ret: %d\n",
		       pds->service_name, ret);
		goto err;
	}

	qmi_add_lookup(&pdr->servreg_client, pds->service, 1,
		       pds->instance);

	return 0;

err:
	list_del(&pds->node);
	kfree(pds);
	return ret;
}
EXPORT_SYMBOL(pdr_add_lookup);

int pdr_handle_init(struct pdr_handle *pdr,
		    int (*status)(struct pdr_handle *pdr, struct pd_status *pds))
{
	int ret;

	if (!status)
		return -EINVAL;

	pdr->status = *status;

	init_completion(&pdr->locator_available);

	INIT_LIST_HEAD(&pdr->lookups);
	INIT_LIST_HEAD(&pdr->servreg_list);
	INIT_LIST_HEAD(&pdr->servdel_list);
	INIT_LIST_HEAD(&pdr->indack_list);

	INIT_WORK(&pdr->servreg_work, pdr_servreg_work);
	INIT_WORK(&pdr->servdel_work, pdr_servdel_work);
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
			      SERVREG_LOC_GET_DOMAIN_LIST_RESP_MAX_MSG_LEN,
			      &service_locator_ops, NULL);
	if (ret < 0)
		goto destroy_indack;

	ret = qmi_handle_init(&pdr->servreg_client,
			      SERVREG_NOTIF_STATE_UPDATED_IND_MAX_MSG_LEN,
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

void pdr_handle_release(struct pdr_handle *pdr)
{
	struct pd_status *pds, *tmp;

	cancel_work_sync(&pdr->servreg_work);
	cancel_work_sync(&pdr->servdel_work);
	cancel_work_sync(&pdr->indack_work);

	qmi_handle_release(&pdr->servloc_client);
	qmi_handle_release(&pdr->servreg_client);

	destroy_workqueue(pdr->servreg_wq);
	destroy_workqueue(pdr->indack_wq);

	list_for_each_entry_safe(pds, tmp, &pdr->lookups, node) {
		list_del(&pds->node);
		kfree(pds);
	}
}
EXPORT_SYMBOL(pdr_handle_release);
