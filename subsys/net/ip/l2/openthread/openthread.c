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
#include <misc/__assert.h>
#include <net/net_pkt.h>
#include <net/net_if.h>
#include <net/net_core.h>
#include <stddef.h>

#include <openthread/openthread.h>
#include <openthread/cli.h>
#include <openthread/platform/platform.h>

#define OT_STACK_SIZE (1024 * 8)
#define OT_PRIORITY 5

struct openthread_context {
	otInstance *instance;
	struct net_if *iface;
};

struct pkt_list_elem {
	struct net_pkt *pkt;
};

K_MUTEX_DEFINE(ot_mutex);

K_THREAD_STACK_DEFINE(ot_stack_area, OT_STACK_SIZE);
static struct k_thread ot_thread_data;
static k_tid_t ot_tid;

static struct net_mgmt_event_callback mgmt6_cb;

static struct openthread_context context;

static u16_t pkt_list_in_idx;
static u16_t pkt_list_out_idx;
static u8_t pkt_list_full;
static struct pkt_list_elem pkt_list[CONFIG_OPENTHREAD_PKT_LIST_SIZE];

static void hexdump(const char *str, const u8_t *packet, size_t length)
{
	int n = 0;

	char buff[100] = "";
	char buff2[100] = "";

	if (!length) {
		SYS_LOG_DBG("%s zero-length packet", str);
		return;
	}

	while (length--) {
		if (n % 16 == 0) {
			sprintf(buff2, "%s %08X ", str, n);
			strcat(buff, buff2);
		}

		sprintf(buff2, "%02X ", *packet++);
		strcat(buff, buff2);

		n++;
		if (n % 8 == 0) {
			if (n % 16 == 0) {
				SYS_LOG_DBG("%s", buff);
				buff[0] = '\0';
			} else {
				strcat(buff, " ");
			}
		}
	}

	if (n % 16) {
		SYS_LOG_DBG("%s", buff);
		buff[0] = '\0';
	}
}

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

		while (otTaskletsArePending(context.instance)) {
			otTaskletsProcess(context.instance);
		}
		PlatformProcessDrivers(context.instance);

		k_mutex_unlock(&ot_mutex);

		k_sleep(K_MSEC(1));
	}
}

static void add_ipv6_addr(void)
{
	const otNetifAddress *address;
	for (address = otIp6GetUnicastAddresses(context.instance); address; address = address->mNext) {
#if defined(CONFIG_OPENTHREAD_DEBUG)
		char buf[NET_IPV6_ADDR_LEN];
		SYS_LOG_DBG("Adding %s", net_addr_ntop(AF_INET6, (struct in6_addr *)(&address->mAddress), buf, sizeof(buf)));
#endif
		net_if_ipv6_addr_add(context.iface, (struct in6_addr *)(&address->mAddress), NET_ADDR_ANY, 0);
	}
}

static void add_ipv6_maddr(void)
{
	const otNetifMulticastAddress *maddress;
	for (maddress = otIp6GetMulticastAddresses(context.instance); maddress; maddress = maddress->mNext) {
#if defined(CONFIG_OPENTHREAD_DEBUG)
		char buf[NET_IPV6_ADDR_LEN];
		SYS_LOG_DBG("Adding multicast %s", net_addr_ntop(AF_INET6, (struct in6_addr *)(&maddress->mAddress), buf, sizeof(buf)));
#endif
		net_if_ipv6_maddr_add(context.iface, (struct in6_addr *)(&maddress->mAddress));
	}
}

static void add_ipv6_prefix(void)
{
	otNetworkDataIterator *iterator = OT_NETWORK_DATA_ITERATOR_INIT;
	otBorderRouterConfig config;
	
	while (otNetDataGetNextOnMeshPrefix(context.instance, iterator, &config) == OT_ERROR_NONE) {
#if defined(CONFIG_OPENTHREAD_DEBUG)
		char buf[NET_IPV6_ADDR_LEN];
		SYS_LOG_DBG("Adding prefix %s/%d", net_addr_ntop(AF_INET6, (struct in6_addr *)(&config.mPrefix.mPrefix), buf, sizeof(buf)), config.mPrefix.mLength);
#endif
		net_if_ipv6_prefix_add(context.iface, (struct in6_addr *)(&config.mPrefix.mPrefix), config.mPrefix.mLength, 0);
	}

}

static void rm_ipv6_addr(void)
{
	int i;
	
	for (i = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {
		if (!context.iface->ipv6.unicast[i].is_used) {
			continue;
		}

		const otNetifAddress *address;
		bool used = false;
		for (address = otIp6GetUnicastAddresses(context.instance); address; address = address->mNext) {
			if (net_ipv6_addr_cmp((struct in6_addr *)(&address->mAddress),
				&context.iface->ipv6.unicast[i].address.in6_addr)) {
				used = true;
				break;
			}
		}
		if (!used) {
#if defined(CONFIG_OPENTHREAD_DEBUG)
			char buf[NET_IPV6_ADDR_LEN];
			SYS_LOG_DBG("Removing %s", net_addr_ntop(AF_INET6, (struct in6_addr *)(&address->mAddress), buf, sizeof(buf)));
#endif
			net_if_ipv6_addr_rm(context.iface, (struct in6_addr *)(&address->mAddress));
		}
	}
}

static void rm_ipv6_maddr(void)
{
	int i;

	for (i = 0; i < NET_IF_MAX_IPV6_MADDR; i++) {
		if (!context.iface->ipv6.mcast[i].is_used) {
			continue;
		}

		const otNetifMulticastAddress *maddress;
		bool used = false;
		for (maddress = otIp6GetMulticastAddresses(context.instance); maddress; maddress = maddress->mNext) {
			if (net_ipv6_addr_cmp((struct in6_addr *)(&maddress->mAddress),
				&context.iface->ipv6.mcast[i].address.in6_addr)) {
				used = true;
				break;
			}
		}
		if (!used) {
#if defined(CONFIG_OPENTHREAD_DEBUG)
			char buf[NET_IPV6_ADDR_LEN];
			SYS_LOG_DBG("Removing multicast %s", net_addr_ntop(AF_INET6, (struct in6_addr *)(&maddress->mAddress), buf, sizeof(buf)));
#endif
			net_if_ipv6_maddr_rm(context.iface, (struct in6_addr *)(&maddress->mAddress));
		}
	}
}

static void ipv6_event_handler(struct net_mgmt_event_callback *cb,
	u32_t mgmt_event, struct net_if *iface)
{
	if (mgmt_event == NET_EVENT_IPV6_ADDR_ADD) {
		SYS_LOG_DBG("Added address event");
		/* save the last added IP address for this interface */
		// for (i = NET_IF_MAX_IPV6_ADDR - 1; i >= 0; i--) {
		// 	if (iface->ipv6.unicast[i].is_used) {
		// 	memcpy(&laddr,
		// 			&iface->ipv6.unicast[i].address.in6_addr,
		// 			sizeof(laddr));
		// 	}
		// }
	}
}

void ot_state_changed_handler(uint32_t flags, void * p_context)
{
	SYS_LOG_DBG("State changed! Flags: 0x%08x Current role: %d", flags, otThreadGetDeviceRole(p_context));

	if (flags & OT_CHANGED_IP6_ADDRESS_ADDED) {
		SYS_LOG_DBG("Ipv6 address added");
		add_ipv6_prefix();
		add_ipv6_addr();
		add_ipv6_maddr();
	}	

	if (flags & OT_CHANGED_IP6_ADDRESS_REMOVED) {
		SYS_LOG_DBG("Ipv6 address removed");
		rm_ipv6_addr();
		rm_ipv6_maddr();
	}
}

void ot_receive_handler(otMessage *aMessage, void *aContext)
{
	uint16_t offset = 0;
	uint16_t read_len;
	struct net_pkt *pkt;
	struct net_buf *prev_buf = NULL;

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
		if (net_recv_data(context.iface, pkt) < 0) {
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

	hexdump("otRadioFrame mPsdu dump", recv_frame.mPsdu, recv_frame.mLength);

#if OPENTHREAD_ENABLE_DIAG
	if (otPlatDiagModeGet())
	{
		otPlatDiagRadioReceiveDone(context.instance, &recv_frame, OT_ERROR_NONE);
	}
	else
#endif
	{
		k_mutex_lock(&ot_mutex, K_FOREVER);
		otPlatRadioReceiveDone(context.instance, &recv_frame, OT_ERROR_NONE);
		k_mutex_unlock(&ot_mutex);
	}

	net_pkt_unref(pkt);

	return NET_OK;

}

static enum net_verdict openthread_send(struct net_if *iface, struct net_pkt *pkt)
{
	SYS_LOG_DBG("Sending Ip6 packet to ot stack");

	k_mutex_lock(&ot_mutex, K_FOREVER);

	otMessage *message = otIp6NewMessage(context.instance, true);
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

	if (otIp6Send(context.instance, message) != OT_ERROR_NONE) {
		SYS_LOG_ERR("Error while calling otIp6Send");
		goto exit;
	}

exit:

	k_mutex_unlock(&ot_mutex);

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

	context.instance = otInstanceInitSingle();
	context.iface = net_if_get_first_by_type(&NET_L2_GET_NAME(OPENTHREAD));

	__ASSERT(context.instance, "OT instance is NULL",);

    otCliUartInit(context.instance);

    SYS_LOG_INF("OpenThread version: %s", otGetVersionString());
    SYS_LOG_INF("Network name:   %s", otThreadGetNetworkName(context.instance));

    otSetStateChangedCallback(context.instance, &ot_state_changed_handler, context.instance);

	otLinkSetChannel(context.instance, CONFIG_OPENTHREAD_CHANNEL);
	otLinkSetPanId(context.instance, CONFIG_OPENTHREAD_PANID);
	otIp6SetEnabled(context.instance, true);
	otThreadSetEnabled(context.instance, true);

	//otIp6SetReceiveCallback(context.instance, ot_receive_handler, NULL);

	net_mgmt_init_event_callback(&mgmt6_cb, ipv6_event_handler, NET_EVENT_IPV6_ADDR_ADD);
	net_mgmt_add_event_callback(&mgmt6_cb);

	ot_tid = k_thread_create(&ot_thread_data, ot_stack_area,
		K_THREAD_STACK_SIZEOF(ot_stack_area),
		openthread_process,
		NULL, NULL, NULL,
		OT_PRIORITY, 0, K_NO_WAIT);

	return 0;
}

SYS_INIT(openthread_init, POST_KERNEL, 80);

NET_L2_INIT(OPENTHREAD_L2, openthread_recv, openthread_send, openthread_reserve, NULL);
