/*
 * Copyright (c) 2017 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <kernel.h>

#include <net/net_pkt.h>
#include <net/openthread.h>

#include <openthread/openthread.h>

#include "openthread_utils.h"

#if defined(CONFIG_OPENTHREAD_L2_DEBUG_DUMP_15_4) || \
	defined(CONFIG_OPENTHREAD_L2_DEBUG_DUMP_IPV6)
void dump_pkt(const char *str, struct net_pkt *pkt)
{
	struct net_buf *frag;
	int n = 0;
	int i;

	printk("%s packet len %d\r\n", str, net_buf_frags_len(pkt->frags));

	for (frag = pkt->frags; frag; frag = frag->frags) {
		for (i = 0; i < frag->len; i++) {
			if (n % 16 == 0) {
				printk("%s %08X ", str, n);
			}

			printk("%02X ", frag->data[i]);

			n++;
			if (n % 8 == 0) {
				if (n % 16 == 0) {
					printk("\r\n");
				} else {
					printk(" ");
				}
			}
		}
	}

	if (n % 16) {
		printk("\r\n");
	}
}
#endif

int pkt_list_add(struct openthread_context *context, struct net_pkt *pkt)
{
	u16_t i_idx = context->pkt_list_in_idx;

	if (context->pkt_list_full) {
		return -ENOMEM;
	}

	i_idx++;

	if (i_idx == CONFIG_OPENTHREAD_PKT_LIST_SIZE) {
		i_idx = 0;
	}

	if (i_idx == context->pkt_list_out_idx) {
		context->pkt_list_full = 1;
	}

	context->pkt_list[context->pkt_list_in_idx].pkt = pkt;
	context->pkt_list_in_idx = i_idx;

	return 0;
}

struct net_pkt *pkt_list_peek(struct openthread_context *context)
{
	if ((context->pkt_list_in_idx == context->pkt_list_out_idx) &&
		(!context->pkt_list_full)) {

		return NULL;
	}
	return context->pkt_list[context->pkt_list_out_idx].pkt;
}

void pkt_list_remove_last(struct openthread_context *context)
{
	if ((context->pkt_list_in_idx == context->pkt_list_out_idx) &&
		(!context->pkt_list_full)) {

		return;
	}

	context->pkt_list_out_idx++;

	if (context->pkt_list_out_idx == CONFIG_OPENTHREAD_PKT_LIST_SIZE) {
		context->pkt_list_out_idx = 0;
	}

	context->pkt_list_full = 0;
}

void add_ipv6_addr_to_zephyr(struct openthread_context *context)
{
	const otNetifAddress *address;

	for (address = otIp6GetUnicastAddresses(context->instance);
		address; address = address->mNext) {
#if CONFIG_OPENTHREAD_L2_LOG_LEVEL == SYS_LOG_LEVEL_DEBUG
		char buf[NET_IPV6_ADDR_LEN];

		SYS_LOG_DBG("Adding %s", net_addr_ntop(AF_INET6,
			(struct in6_addr *)(&address->mAddress),
			buf, sizeof(buf)));
#endif
		net_if_ipv6_addr_add(context->iface,
			(struct in6_addr *)(&address->mAddress),
			NET_ADDR_ANY, 0);
	}
}

void add_ipv6_addr_to_ot(struct openthread_context *context)
{
	struct in6_addr laddr;
	int i;

	/* save the last added IP address for this interface */
	for (i = NET_IF_MAX_IPV6_ADDR - 1; i >= 0; i--) {
		if (context->iface->ipv6.unicast[i].is_used) {
			memcpy(&laddr, &context->iface->ipv6.unicast[i].address.in6_addr,
				sizeof(laddr));
			break;
		}
	}

	otIp6AddUnicastAddress(context->instance,
		(const otNetifAddress *)(&laddr));

#if CONFIG_OPENTHREAD_L2_LOG_LEVEL == SYS_LOG_LEVEL_DEBUG
	char buf[NET_IPV6_ADDR_LEN];

	SYS_LOG_DBG("Added %s", net_addr_ntop(AF_INET6,
		&laddr, buf, sizeof(buf)));
#endif
}

void add_ipv6_maddr_to_zephyr(struct openthread_context *context)
{
	const otNetifMulticastAddress *maddress;

	for (maddress = otIp6GetMulticastAddresses(context->instance);
		maddress; maddress = maddress->mNext) {
#if CONFIG_OPENTHREAD_L2_LOG_LEVEL == SYS_LOG_LEVEL_DEBUG
		char buf[NET_IPV6_ADDR_LEN];

		SYS_LOG_DBG("Adding multicast %s", net_addr_ntop(AF_INET6,
			(struct in6_addr *)(&maddress->mAddress),
			buf, sizeof(buf)));
#endif
		net_if_ipv6_maddr_add(context->iface,
			(struct in6_addr *)(&maddress->mAddress));
	}
}

void add_ipv6_prefix_to_zephyr(struct openthread_context *context)
{
	otNetworkDataIterator *iterator = OT_NETWORK_DATA_ITERATOR_INIT;
	otBorderRouterConfig config;

	while (otNetDataGetNextOnMeshPrefix(context->instance,
		iterator, &config) == OT_ERROR_NONE) {
#if CONFIG_OPENTHREAD_L2_LOG_LEVEL == SYS_LOG_LEVEL_DEBUG
		char buf[NET_IPV6_ADDR_LEN];

		SYS_LOG_DBG("Adding prefix %s/%d", net_addr_ntop(AF_INET6,
			(struct in6_addr *)(&config.mPrefix.mPrefix),
			buf, sizeof(buf)), config.mPrefix.mLength);
#endif
		net_if_ipv6_prefix_add(context->iface,
			(struct in6_addr *)(&config.mPrefix.mPrefix),
			config.mPrefix.mLength, 0);
	}

}

void rm_ipv6_addr_from_zephyr(struct openthread_context *context)
{
	struct in6_addr *ot_addr;
	struct net_if_addr *zephyr_addr;
	int i;

	for (i = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {
		zephyr_addr = &context->iface->ipv6.unicast[i];
		if (!zephyr_addr->is_used) {
			continue;
		}

		const otNetifAddress *address;
		bool used = false;

		for (address = otIp6GetUnicastAddresses(context->instance);
			address; address = address->mNext) {

			ot_addr = (struct in6_addr *)(&address->mAddress);
			if (net_ipv6_addr_cmp(ot_addr,
				&zephyr_addr->address.in6_addr)) {

				used = true;
				break;
			}
		}
		if (!used) {
#if CONFIG_OPENTHREAD_L2_LOG_LEVEL == SYS_LOG_LEVEL_DEBUG
			char buf[NET_IPV6_ADDR_LEN];

			SYS_LOG_DBG("Removing %s", net_addr_ntop(AF_INET6,
				&zephyr_addr->address.in6_addr,
				buf, sizeof(buf)));
#endif
			net_if_ipv6_addr_rm(context->iface,
				&zephyr_addr->address.in6_addr);
		}
	}
}

void rm_ipv6_maddr_from_zephyr(struct openthread_context *context)
{
	struct in6_addr *ot_addr;
	struct net_if_mcast_addr *zephyr_addr;
	int i;

	for (i = 0; i < NET_IF_MAX_IPV6_MADDR; i++) {
		zephyr_addr = &context->iface->ipv6.mcast[i];
		if (!zephyr_addr->is_used) {
			continue;
		}

		const otNetifMulticastAddress *maddress;
		bool used = false;

		for (maddress = otIp6GetMulticastAddresses(context->instance);
			maddress; maddress = maddress->mNext) {

			ot_addr = (struct in6_addr *)(&maddress->mAddress);
			if (net_ipv6_addr_cmp(ot_addr,
				&zephyr_addr->address.in6_addr)) {

				used = true;
				break;
			}
		}
		if (!used) {
#if CONFIG_OPENTHREAD_L2_LOG_LEVEL == SYS_LOG_LEVEL_DEBUG
			char buf[NET_IPV6_ADDR_LEN];

			SYS_LOG_DBG("Removing multicast %s",
				net_addr_ntop(AF_INET6,
				&zephyr_addr->address.in6_addr,
				buf, sizeof(buf)));
#endif
			net_if_ipv6_maddr_rm(context->iface,
				&zephyr_addr->address.in6_addr);
		}
	}
}
