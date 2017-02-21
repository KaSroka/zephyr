#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

include $(ZEPHYR_BASE)/samples/net/common/Makefile.common

obj-y += echo-server.o
obj-$(CONFIG_NET_UDP) += udp.o
obj-$(CONFIG_NET_TCP) += tcp.o

ccflags-$(CONFIG_NET_L2_OPENTHREAD) += -I$(O)/openthread/include
