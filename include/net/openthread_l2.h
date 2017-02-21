/**
 * @file
 * @brief BSD Sockets compatible API definitions
 *
 * An API for applications to use BSD Sockets like API.
 */

/*
 * Copyright (c) 2017 Linaro Limited
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __NET_OPENTHREAD_H_
#define __NET_OPENTHREAD_H_

#include <kernel.h>

#include <net/net_if.h>

#include <openthread/openthread.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pkt_list_elem {
	struct net_pkt *pkt;
};

struct openthread_context {
	otInstance *instance;
    struct net_if *iface;
    u16_t pkt_list_in_idx;
    u16_t pkt_list_out_idx;
    u8_t pkt_list_full;
    struct pkt_list_elem pkt_list[CONFIG_OPENTHREAD_PKT_LIST_SIZE];
};

#ifdef __cplusplus
}
#endif

#endif /* __NET_OPENTHREAD_H_ */
