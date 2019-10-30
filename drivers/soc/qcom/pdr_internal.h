// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 The Linux Foundation. All rights reserved.
 */
#include <linux/soc/qcom/pdr.h>
#include <linux/soc/qcom/qmi.h>

#define SERVREG_LOCATOR_SERVICE				0x40
#define SERVREG_NOTIF_SERVICE				0x42

#define SERVREG_LOC_LIST_LENGTH				32
#define SERVREG_LOC_GET_DOMAIN_LIST_REQ			0x21
#define SERVREG_LOC_GET_DOMAIN_LIST_REQ_MAX_MSG_LEN	74
#define SERVREG_LOC_GET_DOMAIN_LIST_RESP_MAX_MSG_LEN	2389

#define SERVREG_NOTIF_REGISTER_LISTENER_REQ		0x20
#define SERVREG_NOTIF_REGISTER_LISTENER_REQ_MSG_LEN	71

#define SERVREG_NOTIF_STATE_UPDATED_IND_MSG_ID		0x22
#define SERVREG_NOTIF_SET_ACK_REQ			0x23
#define SERVREG_NOTIF_SET_ACK_REQ_MSG_LEN		72
#define SERVREG_NOTIF_STATE_UPDATED_IND_MAX_MSG_LEN	79


struct servreg_loc_entry {
	char name[SERVREG_NAME_LENGTH + 1];
	uint8_t service_data_valid;
	uint32_t service_data;
	uint32_t instance;
};

struct qmi_elem_info servreg_loc_entry_ei[] = {
	{
		.data_type      = QMI_STRING,
		.elem_len       = SERVREG_NAME_LENGTH + 1,
		.elem_size      = sizeof(char),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct servreg_loc_entry,
					   name),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint32_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct servreg_loc_entry,
					   instance),
	},
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint8_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct servreg_loc_entry,
					   service_data_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint32_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0,
		.offset         = offsetof(struct servreg_loc_entry,
					   service_data),
	},
	{}
};

struct servreg_loc_get_domain_list_req_msg {
	char service_name[SERVREG_NAME_LENGTH + 1];
	uint8_t domain_offset_valid;
	uint32_t domain_offset;
};

struct qmi_elem_info servreg_loc_get_domain_list_req_msg_ei[] = {
	{
		.data_type      = QMI_STRING,
		.elem_len       = SERVREG_NAME_LENGTH + 1,
		.elem_size      = sizeof(char),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(struct
				servreg_loc_get_domain_list_req_msg,
				service_name),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(uint8_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(struct
				servreg_loc_get_domain_list_req_msg,
				domain_offset_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_4_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint32_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(struct
				servreg_loc_get_domain_list_req_msg,
				domain_offset),
	},
	{}
};

struct servreg_loc_get_domain_list_resp_msg {
	struct qmi_response_type_v01 resp;
	uint8_t total_domains_valid;
	uint16_t total_domains;
	uint8_t db_rev_count_valid;
	uint16_t db_rev_count;
	uint8_t domain_list_valid;
	uint32_t domain_list_len;
	struct servreg_loc_entry domain_list[SERVREG_LOC_LIST_LENGTH];
};

struct qmi_elem_info servreg_loc_get_domain_list_resp_msg_ei[] = {
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_response_type_v01),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(struct
				servreg_loc_get_domain_list_resp_msg,
				resp),
		.ei_array      = qmi_response_type_v01_ei,
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(uint8_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(struct
				servreg_loc_get_domain_list_resp_msg,
				total_domains_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_2_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint16_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(struct
				servreg_loc_get_domain_list_resp_msg,
				total_domains),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(uint8_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(struct
				servreg_loc_get_domain_list_resp_msg,
				db_rev_count_valid),
	},
	{
		.data_type      = QMI_UNSIGNED_2_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint16_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x11,
		.offset         = offsetof(struct
				servreg_loc_get_domain_list_resp_msg,
				db_rev_count),
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(uint8_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(struct
				servreg_loc_get_domain_list_resp_msg,
				domain_list_valid),
	},
	{
		.data_type      = QMI_DATA_LEN,
		.elem_len       = 1,
		.elem_size      = sizeof(uint8_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(struct
				servreg_loc_get_domain_list_resp_msg,
				domain_list_len),
	},
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = SERVREG_LOC_LIST_LENGTH,
		.elem_size      = sizeof(struct servreg_loc_entry),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x12,
		.offset         = offsetof(struct
				servreg_loc_get_domain_list_resp_msg,
				domain_list),
		.ei_array      = servreg_loc_entry_ei,
	},
	{}
};

struct servreg_notif_register_listener_req_msg {
	uint8_t enable;
	char service_path[SERVREG_NAME_LENGTH + 1];
};

struct qmi_elem_info servreg_notif_register_listener_req_msg_ei[] = {
	{
		.data_type      = QMI_UNSIGNED_1_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint8_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(struct servreg_notif_register_listener_req_msg, enable),
	},
	{
		.data_type      = QMI_STRING,
		.elem_len       = SERVREG_NAME_LENGTH + 1,
		.elem_size      = sizeof(char),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(struct servreg_notif_register_listener_req_msg, service_path),
	},
	{}
};

struct servreg_notif_register_listener_resp_msg {
	struct qmi_response_type_v01 resp;
	uint8_t curr_state_valid;
	enum servreg_service_state curr_state;
};

struct qmi_elem_info servreg_notif_register_listener_resp_msg_ei[] = {
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_response_type_v01),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(struct
			servreg_notif_register_listener_resp_msg, resp),
		.ei_array      = qmi_response_type_v01_ei,
	},
	{
		.data_type      = QMI_OPT_FLAG,
		.elem_len       = 1,
		.elem_size      = sizeof(uint8_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(struct
			servreg_notif_register_listener_resp_msg,
							curr_state_valid),
	},
	{
		.data_type      = QMI_SIGNED_4_BYTE_ENUM,
		.elem_len       = 1,
		.elem_size      = sizeof(enum servreg_service_state),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x10,
		.offset         = offsetof(struct
			servreg_notif_register_listener_resp_msg,
								curr_state),
	},
	{}
};

struct servreg_notif_state_updated_ind_msg {
	enum servreg_service_state curr_state;
	char service_path[SERVREG_NAME_LENGTH + 1];
	uint16_t transaction_id;
};

struct qmi_elem_info servreg_notif_state_updated_ind_msg_ei[] = {
	{
		.data_type      = QMI_SIGNED_4_BYTE_ENUM,
		.elem_len       = 1,
		.elem_size      = sizeof(uint32_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(struct servreg_notif_state_updated_ind_msg, curr_state),
	},
	{
		.data_type      = QMI_STRING,
		.elem_len       = SERVREG_NAME_LENGTH + 1,
		.elem_size      = sizeof(char),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(struct servreg_notif_state_updated_ind_msg, service_path),
	},
	{
		.data_type      = QMI_UNSIGNED_2_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint16_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x03,
		.offset         = offsetof(struct servreg_notif_state_updated_ind_msg, transaction_id),
	},
	{}
};

struct servreg_notif_set_ack_req_msg {
	char service_path[SERVREG_NAME_LENGTH + 1];
	uint16_t transaction_id;
};

struct qmi_elem_info servreg_notif_set_ack_req_msg_ei[] = {
	{
		.data_type      = QMI_STRING,
		.elem_len       = SERVREG_NAME_LENGTH + 1,
		.elem_size      = sizeof(char),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x01,
		.offset         = offsetof(struct servreg_notif_set_ack_req_msg,
					   service_path),
	},
	{
		.data_type      = QMI_UNSIGNED_2_BYTE,
		.elem_len       = 1,
		.elem_size      = sizeof(uint16_t),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(struct servreg_notif_set_ack_req_msg,
					   transaction_id),
	},
	{}
};

struct servreg_notif_set_ack_resp_msg {
	struct qmi_response_type_v01 resp;
};

struct qmi_elem_info servreg_notif_set_ack_resp_msg_ei[] = {
	{
		.data_type      = QMI_STRUCT,
		.elem_len       = 1,
		.elem_size      = sizeof(struct qmi_response_type_v01),
		.array_type	= NO_ARRAY,
		.tlv_type       = 0x02,
		.offset         = offsetof(struct servreg_notif_set_ack_resp_msg, resp),
		.ei_array       = qmi_response_type_v01_ei,
	},
	{}
};
