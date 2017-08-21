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
#include <openthread/diag.h>
#include <openthread/cli.h>
#include <openthread/tasklet.h>
#include <openthread/platform/platform.h>


K_TIMER_DEFINE(openthread_timer, openthread_timer_handler, NULL);
K_WORK_DEFINE(openthread_process, openthread_process_handler);

struct openthread_context {
	otInstance *sInstance;
	struct net_if *iface;

	u8_t mac_addr[6];
	struct net_linkaddr ll_addr;
};

void openthread_timer_handler(struct k_timer *dummy)
{
    k_work_submit(&openthread_process);
}

void openthread_process_handler(struct k_work *work)
{
	otTaskletsProcess(sInstance);
	PlatformProcessDrivers(sInstance);
}

void ot_state_changed_handler(uint32_t flags, void * p_context)
{
	SYS_LOG_DBG("State changed! Flags: 0x%08x Current role: %d", flags, otThreadGetDeviceRole(p_context));
}

void ot_receive_handler(otMessage *aMessage, void *aContext) {
	struct openthread_context *context = net_if_get_device(iface)->driver_data;
	uint16_t offset = 0;
	uint16_t read_len;
	struct net_pkt *pkt;
	struct net_buf *prev_buf = NULL;

	pkt = net_pkt_get_reserve_rx(0, K_NO_WAIT);
	if (!pkt) {
		SYS_LOG_ERR("Failed to get net pkt\n");
		otMessageFree(aMessage);
		return;
	}

	do {
		struct net_buf *pkt_buf;

		pkt_buf = net_pkt_get_frag(pkt, K_NO_WAIT);
		if (!pkt_buf) {
			SYS_LOG_ERR("Failed to get fragment buf\n");
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
		SYS_LOG_ERR("Failed recv_data\n");
		net_pkt_unref(pkt);
	}

	otMessageFree(aMessage);
}

static int openthread_send(struct net_if *iface, struct net_pkt *pkt)
{
	struct openthread_context *context = net_if_get_device(iface)->driver_data;
	
	otMessage *message = otIp6NewMessage(context->otInstance, true);
	
	struct net_buf *frag;

	for (frag = pkt->frags; frag; frag = frag->frags) {
		if (otMessageAppend(message, frag->data, frag->len) != OT_ERROR_NONE) {
			otMessageFree(message);
			return -ENOMEM;
		}
	}

	if (otIp6Send(context->otInstance, message) != OT_ERROR_NONE) {
		otMessageFree(message);
		return -1; // TODO find proper error
	}

	net_pkt_unref(pkt);

	return 0;
}

static otInstance * initialize_thread(void)
{
    otInstance *p_instance;

    p_instance = otInstanceInitSingle();
    assert(p_instance);

    otCliUartInit(p_instance);

    SYS_LOG_INF("OpenThread version: %s", otGetVersionString());
    SYS_LOG_INF("Network name:   %s", otThreadGetNetworkName(p_instance));

    otSetStateChangedCallback(p_instance, &ot_state_changed_handler, p_instance);

//    otSetChannel(p_instance, 11);
//    otSetPanId(p_instance, 0xabcd);
//    otInterfaceUp(p_instance);
//    otThreadStart(p_instance);

    return p_instance;
}

static int openthread_init(struct device *dev)
{
	struct openthread_context *context= dev->driver_data;

	SYS_LOG_DBG("openthread_init");

	PlatformInit();
	context->otInstance = initialize_thread();
	otIp6SetReceiveCallback(context->otInstance, ot_receive_handler, context);
	k_timer_start(&openthread_timer, K_MSEC(1), K_MSEC(1));

	return 0;
}

static void openthread_iface_init(struct net_if *iface)
{
	struct openthread_context *context = net_if_get_device(iface)->driver_data;
	const otExtAddress *ext_address;

	context->iface = iface;
	ext_address = otLinkGetExtendedAddress(context);
	net_if_set_link_addr(iface, ext_addr, sizeof(*ext_addr),
			     NET_LINK_ETHERNET);
}

static struct net_if_api openthread_if_api = {
	.init = openthread_iface_init,
	.send = openthread_send,
};

static struct openthread_context openthread_context_data;

#define _OPENTHREAD_L2_LAYER DUMMY_L2
#define _OPENTHREAD_L2_CTX_TYPE NET_L2_GET_CTX_TYPE(DUMMY_L2)
#define _OPENTHREAD_MTU 1280

NET_DEVICE_INIT(openthread, CONFIG_OPENTHREAD_DRV_NAME, openthread_init, &openthread_context_data,
		NULL, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT, &openthread_if_api,
		_OPENTHREAD_L2_LAYER, _OPENTHREAD_L2_CTX_TYPE, _OPENTHREAD_MTU);
