/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 *
 * SLIP driver using uart_pipe. This is meant for network connectivity between
 * host and qemu. The host will need to run tunslip process.
 */


#if defined(CONFIG_OPENTHREAD_DEBUG)
#define SYS_LOG_DOMAIN "openthread"
#define SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#include <logging/sys_log.h>
#include <stdio.h>
#endif

#include <kernel.h>

#include <stdbool.h>
#include <errno.h>
#include <init.h>
#include <misc/util.h>
#include <net/net_pkt.h>
#include <net/net_if.h>
#include <net/net_core.h>
#include <stddef.h>

#include <openthread/openthread.h>
#include <openthread/cli.h>
#include <openthread/platform/platform.h>

#define OT_STACK_SIZE (1024 * 8)
#define OT_PRIORITY 5

K_MUTEX_DEFINE(ot_mutex);
K_THREAD_STACK_DEFINE(ot_stack_area, OT_STACK_SIZE);
struct k_thread ot_thread_data;
k_tid_t ot_tid;

struct openthread_context {
	otInstance *instance;
	otExtAddress ext_address;
	struct net_if *iface;

	struct net_linkaddr ll_addr;
};

struct pkt_list_elem {
	struct net_pkt *pkt;
};

static u16_t pkt_list_in_idx;
static u16_t pkt_list_out_idx;
static u8_t pkt_list_full;
static struct pkt_list_elem pkt_list[CONFIG_OPENTHREAD_PKT_LIST_SIZE];

static struct openthread_context openthread_context;

static inline int pkt_list_add(struct net_pkt *pkt)
{
	u16_t i_idx = pkt_list_in_idx;

	if (pkt_list_full) {
		return -ENOMEM;
	}

	i_idx++;

	if (i_idx == CONFIG_OPENTHREAD_PKT_LIST_SIZE) {
		i_idx = 0;
	}

	if (i_idx == pkt_list_out_idx) {
		pkt_list_full = 1;
	}

	pkt_list[pkt_list_in_idx].pkt = pkt;
	pkt_list_in_idx = i_idx;

	return 0;
}

static inline struct net_pkt* pkt_list_peek(void) {
	if ((pkt_list_in_idx == pkt_list_out_idx) && (!pkt_list_full)) {
		return NULL;
	}
	return pkt_list[pkt_list_out_idx].pkt;
}

static inline void pkt_list_remove_last(void) {
	if ((pkt_list_in_idx == pkt_list_out_idx) && (!pkt_list_full)) {
		return;
	}

	pkt_list_out_idx++;

	if (pkt_list_out_idx == CONFIG_OPENTHREAD_PKT_LIST_SIZE) {
		pkt_list_out_idx = 0;
	}

	pkt_list_full = 0;
}

static inline int pkt_list_is_full(void) {
	return pkt_list_full;
}

static void openthread_process(void * arg1, void * arg2, void * arg3)
{
	while (1) {
		k_mutex_lock(&ot_mutex, K_FOREVER);

		SYS_LOG_DBG("OT mutex locked");

		while (otTaskletsArePending(openthread_context.instance)) {
			otTaskletsProcess(openthread_context.instance);
		}
		PlatformProcessDrivers(openthread_context.instance);

		k_mutex_unlock(&ot_mutex);

		SYS_LOG_DBG("OT mutex unlocked");

		k_sleep(K_MSEC(1));
	}
}


void ot_state_changed_handler(uint32_t flags, void * p_context)
{
	SYS_LOG_DBG("State changed! Flags: 0x%08x Current role: %d", flags, otThreadGetDeviceRole(p_context));
	
}

void ot_receive_handler(otMessage *aMessage, void *aContext) {
	struct openthread_context *context = (struct openthread_context*)aContext;
	uint16_t offset = 0;
	uint16_t read_len;
	struct net_pkt *pkt;
	struct net_buf *prev_buf = NULL;

	SYS_LOG_DBG("Data received from ot stack");

	pkt = net_pkt_get_reserve_rx(0, K_NO_WAIT);
	if (!pkt) {
		SYS_LOG_ERR("Failed to reserve net pkt");
		otMessageFree(aMessage);
		return;
	}

	do {
		struct net_buf *pkt_buf;

		pkt_buf = net_pkt_get_frag(pkt, K_NO_WAIT);
		if (!pkt_buf) {
			SYS_LOG_ERR("Failed to get fragment buf");
			net_pkt_unref(pkt);
			otMessageFree(aMessage);
			return;
		}

		if (!prev_buf) {
			net_pkt_frag_insert(pkt, pkt_buf);
		} else {
			net_buf_frag_insert(prev_buf, pkt_buf);
		}

		prev_buf = pkt_buf;

		read_len = otMessageRead(aMessage, offset, pkt_buf->data, net_buf_tailroom(pkt_buf));

		net_buf_add(pkt_buf, read_len);

		offset += read_len;

	} while (read_len);

	SYS_LOG_DBG("Injecting Ip6 packet to Zephyr net stack");

	if (!pkt_list_is_full()) {
		if (net_recv_data(context->iface, pkt) < 0) {
			SYS_LOG_ERR("Failed recv_data");
			net_pkt_unref(pkt);
			otMessageFree(aMessage);
			return;
		}

		pkt_list_add(pkt);
	} else {
		SYS_LOG_INF("Pacet list is full");
	}

	otMessageFree(aMessage);
}

static enum net_verdict openthread_recv(struct net_if *iface, struct net_pkt *pkt)
{
	if (pkt_list_peek() == pkt) {
		pkt_list_remove_last();
		SYS_LOG_DBG("Got injected Ip6 packet, sending to upper layers");
		return NET_CONTINUE;
	}

	SYS_LOG_DBG("Got 15.4 packet, sending to OT");

	otRadioFrame recv_frame;
	recv_frame.mPsdu = net_buf_frag_last(pkt->frags)->data;
	recv_frame.mLength = net_buf_frags_len(pkt->frags); // Length inc. CRC.
	recv_frame.mChannel = 11; // TODO: get channel from packet
	recv_frame.mLqi = 0; // TODO: get LQI from the buffer
	recv_frame.mPower = 0;//pkt->ieee802154_rssi; // TODO: get RSSI from packet

#if OPENTHREAD_ENABLE_DIAG
	if (otPlatDiagModeGet())
	{
		otPlatDiagRadioReceiveDone(openthread_context.instance, &recv_frame, OT_ERROR_NONE);
	}
	else
#endif
	{
		otPlatRadioReceiveDone(openthread_context.instance, &recv_frame, OT_ERROR_NONE);
	}

	net_pkt_unref(pkt);

	return NET_OK;

}

static enum net_verdict openthread_send(struct net_if *iface, struct net_pkt *pkt)
{
	SYS_LOG_DBG("Sending Ip6 packet to ot stack");

	k_mutex_lock(&ot_mutex, K_FOREVER);

	SYS_LOG_DBG("OT mutex locked");

	otMessage *message = otIp6NewMessage(openthread_context.instance, true);
	if (message == NULL) {
		goto exit;
	}
	
	struct net_buf *frag;

	for (frag = pkt->frags; frag; frag = frag->frags) {
		if (otMessageAppend(message, frag->data, frag->len) != OT_ERROR_NONE) {
			SYS_LOG_ERR("Error while appending to otMessage");
			otMessageFree(message);
			goto exit;
		}
	}

	if (otIp6Send(openthread_context.instance, message) != OT_ERROR_NONE) {
		goto exit;
	}

exit:

	k_mutex_unlock(&ot_mutex);

	SYS_LOG_DBG("OT mutex unlocked");

	net_pkt_unref(pkt);

	return NET_DROP;
}

static inline u16_t openthread_reserve(struct net_if *iface, void *unused)
{
	ARG_UNUSED(iface);
	ARG_UNUSED(unused);

	return 0;
}

static int openthread_init(struct device *unused)
{
	SYS_LOG_DBG("openthread_init");

	PlatformInit(0, NULL);

    openthread_context.instance = otInstanceInitSingle();

    otCliUartInit(openthread_context.instance);

    SYS_LOG_INF("OpenThread version: %s", otGetVersionString());
    SYS_LOG_INF("Network name:   %s", otThreadGetNetworkName(openthread_context.instance));

    otSetStateChangedCallback(openthread_context.instance, &ot_state_changed_handler, openthread_context.instance);

	otLinkSetChannel(openthread_context.instance, CONFIG_OPENTHREAD_CHANNEL);
	otLinkSetPanId(openthread_context.instance, CONFIG_OPENTHREAD_PANID);
	otIp6SetEnabled(openthread_context.instance, true);
	otThreadSetEnabled(openthread_context.instance, true);

	
	otIp6SetReceiveCallback(openthread_context.instance, ot_receive_handler, NULL);

	ot_tid = k_thread_create(&ot_thread_data, ot_stack_area,
		K_THREAD_STACK_SIZEOF(ot_stack_area),
		openthread_process,
		NULL, NULL, NULL,
		OT_PRIORITY, 0, K_NO_WAIT);

	return 0;
}
#if 0
static void openthread_iface_init(struct net_if *iface)
{
	struct openthread_context *context = net_if_get_device(iface)->driver_data;
	const otExtAddress *ext_address;

	context->iface = iface;
	ext_address = otLinkGetExtendedAddress(context->instance);
	context->ext_address = *ext_address;
	net_if_set_link_addr(iface, context->ext_address.m8, sizeof(context->ext_address),
			     NET_LINK_ETHERNET);
}
#endif

SYS_INIT(openthread_init, POST_KERNEL, 80);

NET_L2_INIT(OPENTHREAD_L2, openthread_recv, openthread_send, openthread_reserve, NULL);
