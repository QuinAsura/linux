/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.
 */

#if !defined(_TRACE_RPMH_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_RPMH_H

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rpmh

#include <linux/tracepoint.h>
#include "rpmh-internal.h"

DECLARE_EVENT_CLASS(rpmh_notify,

	TP_PROTO(struct rsc_drv *d, struct tcs_response *r),

	TP_ARGS(d, r),

	TP_STRUCT__entry(
			 __string(name, d->name)
			 __field(int, m)
			 __field(u32, addr)
			 __field(int, errno)
	),

	TP_fast_assign(
		       __assign_str(name, d->name);
		       __entry->m = r->m;
		       __entry->addr = r->msg->cmds[0].addr;
		       __entry->errno = r->err;
	),

	TP_printk("%s: ack: tcs-m:%d addr: %#x errno: %d",
		  __get_str(name), __entry->m, __entry->addr, __entry->errno)
);

DEFINE_EVENT(rpmh_notify, rpmh_notify_irq,
	     TP_PROTO(struct rsc_drv *d, struct tcs_response *r),
	     TP_ARGS(d, r)
);

DEFINE_EVENT(rpmh_notify, rpmh_notify_tx_done,
	     TP_PROTO(struct rsc_drv *d, struct tcs_response *r),
	     TP_ARGS(d, r)
);


TRACE_EVENT(rpmh_send_msg,

	TP_PROTO(struct rsc_drv *d, int m, int n, u32 h, struct tcs_cmd *c),

	TP_ARGS(d, m, n, h, c),

	TP_STRUCT__entry(
			 __string(name, d->name)
			 __field(int, m)
			 __field(int, n)
			 __field(u32, hdr)
			 __field(u32, addr)
			 __field(u32, data)
			 __field(bool, wait)
	),

	TP_fast_assign(
		       __assign_str(name, d->name);
		       __entry->m = m;
		       __entry->n = n;
		       __entry->hdr = h;
		       __entry->addr = c->addr;
		       __entry->data = c->data;
		       __entry->wait = c->wait;
	),

	TP_printk("%s: send-msg: tcs(m): %d cmd(n): %d msgid: %#x addr: %#x data: %#x complete: %d",
		  __get_str(name), __entry->m, __entry->n, __entry->hdr,
		  __entry->addr, __entry->data, __entry->wait)
);

#endif /* _TRACE_RPMH_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace-rpmh

#include <trace/define_trace.h>
