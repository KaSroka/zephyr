ccflags-$(CONFIG_OPENTHREAD_DRV) += -I$(O)/openthread/include
obj-$(CONFIG_OPENTHREAD_DRV) += openthread.o

all: lib-openthread

lib-openthread: outputexports
	$(MAKE) -f ../../../ext/lib/openthread/Makefile.library O=$(O)
