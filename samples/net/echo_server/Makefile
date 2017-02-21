# Makefile - echo server that is used in testing

#
# Copyright (c) 2015 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

BOARD ?= qemu_x86
CONF_FILE ?= prj_$(BOARD).conf

include $(ZEPHYR_BASE)/Makefile.inc

ifeq ($(CONFIG_NET_L2_BT), y)
	QEMU_EXTRA_FLAGS = -serial unix:/tmp/bt-server-bredr
else
	include $(ZEPHYR_BASE)/samples/net/common/Makefile.ipstack
endif

ccflags-$(CONFIG_NET_L2_OPENTHREAD) += -I$(O)/openthread/include

export LIB_INCLUDE_DIR += -L$(O)/openthread/lib
export ALL_LIBS += openthread-cli-ftd openthread-ftd openthread-platform-utils mbedcrypto

all: lib-openthread

lib-openthread: outputexports
	$(MAKE) -f ../../../ext/lib/openthread/Makefile.library O=$(O)
