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
#include <stddef.h>
#include <misc/util.h>
#include <net/net_pkt.h>
#include <net/net_if.h>
#include <net/net_core.h>

#include <openthread/openthread.h>
#include <openthread/cli.h>
#include <openthread/platform/platform.h>

#define OT_STACK_SIZE (1024 * 8)
#define OT_PRIOIRTY 5

K_MUTEX_DEFINE(ot_mutex);
K_THREAD_STACK_DEFINE(ot_stack_area, OT_STACK_SIZE);
struct k_thread ot_thread_data;
k_tid ot_tid;

struct openthread_context {
	otInstance *instance;
	otExtAddress ext_address;
	struct net_if *iface;

	struct net_linkaddr ll_addr;
};

struct pkt_list_elem {
	struct net_pkt *pkt;
}

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

	packets[pkt_list_in_idx].pkt = pkt;
	pkt_list_in_idx = i_idx;

	return 0;
}

static inline struct net_pkt* pkt_list_peek(void) {
	if ((in_pkt == out_pkt) && (!pkt_list_full)) {
		return NULL;
	}
	return packets[out_pkt].pkt;
}

static inline void pkt_list_remove_last(void) {
	if ((in_pkt == out_pkt) && (!pkt_list_full)) {
		return;
	}

	out_pkt++;

	if (out_pkt == CONFIG_OPENTHREAD_PKT_LIST_SIZE) {
		out_pkt = 0;
	}

	pkt_list_full = 0;
}

static void openthread_process(void * arg1, void * arg2, void * arg3)
{
	while(1){
		k_mutex_lock(&ot_mutex, K_FOREVER);

		SYS_LOG_DBG("OT mutex locked");

		otTaskletsProcess(openthread_context.instance);
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

	// work in progress - add packets to list, more logs

	struct openthread_context *context = (struct openthread_context*)aContext;
	uint16_t offset = 0;
	uint16_t read_len;
	struct net_pkt *pkt;
	struct net_buf *prev_buf = NULL;

	SYS_LOG_DBG("Data received from ot stack");

	pkt = net_pkt_get_reserve_rx(0, K_NO_WAIT);
	if (!pkt) {
		SYS_LOG_ERR("Failed to get net pkt");
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

	if (net_recv_data(context->iface, pkt) < 0) {
		SYS_LOG_ERR("Failed recv_data");
		net_pkt_unref(pkt);
	}
}

static enum net_verdict openthread_recv(struct net_if *iface, struct net_pkt *pkt)
{
	// work in progress - unimplemented
	if (pkt_list_peek() == pkt) {
		pkt_list_remove_last();
		SYS_LOG_DBG("Got reinjected Ip6 packet, sending to upper layers");
		return NET_CONTINUE;
	}

}

static enum net_verdict openthread_send(struct net_if *iface, struct net_pkt *pkt)
{
	SYS_LOG_DBG("Sending Ip6 packet to ot stack");

	k_mutex_lock(&ot_mutex, K_FOREVER);

	SYS_LOG_DBG("OT mutex locked");

	otMessage *message = otIp6NewMessage(openthread_context.instance, true);
	if (message == NULL) {
		return NET_DROP;
	}
	
	struct net_buf *frag;

	for (frag = pkt->frags; frag; frag = frag->frags) {
		if (otMessageAppend(message, frag->data, frag->len) != OT_ERROR_NONE) {
			SYS_LOG_ERR("Error while appending to otMessage");
			otMessageFree(message);
			return NET_DROP;
		}
	}

	if (otIp6Send(openthread_context.instance, message) != OT_ERROR_NONE) {
		SYS_LOG_ERROR("Error while trying to forward Ip6 packet to OT stack");
		return NET_DROP;
	}

	k_mutex_unlock(&ot_mutex);

	SYS_LOG_DBG("OT mutex unlocked");

	net_pkt_unref(pkt);

	return NET_DROP;
}

static int openthread_init(struct device *unused)
{
	SYS_LOG_DBG("openthread_init");

	PlatformInit(0, NULL);

    openthread_context.instance = otInstanceInitSingle();

    otCliUartInit(openthread_context.instance);

    SYS_LOG_INF("OpenThread version: %s", otGetVersionString());
    SYS_LOG_INF("Network name:   %s", otThreadGetNetworkName(openthread_context.instance));

    otSetStateChangedCallback(p_instance, &ot_state_changed_handler, openthread_context.instance);

	otLinkSetChannel(openthread_context.instance, CONFIG_OPENTHREAD_CHANNEL);
	otLinkSetPanId(openthread_context.instance, CONFIG_OPENTHREAD_PANID);
	otIp6SetEnabled(openthread_context.instance, true);
	otThreadSetEnabled(openthread_context.instance, true);

	
	otIp6SetReceiveCallback(openthread_context.instance, ot_receive_handler, NULL);

	k_tid_t my_tid = k_thread_create(&my_thread_data, my_stack_area,
		K_THREAD_STACK_SIZEOF(my_stack_area),
		openthread_process,
		NULL, NULL, NULL,
		MY_PRIORITY, 0, K_NO_WAIT);

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

NET_L2_INIT(OT_L2, openthread_recv, openthread_send, openthread_reserve, openthread_enable);
