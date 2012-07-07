#
# Makefile for UART Linux Bluetooth HCI device drivers.
#

CONFIG_FILE := $(PWD)/.config
-include $(CONFIG_FILE)

ifeq ($(CONFIG_PXA950), y)
CONFIG_PXA9XX=y
endif
ifeq ($(CONFIG_PXA920), y)
CONFIG_PXA9XX=y
endif
ifeq ($(CONFIG_PXA9XX), y)
EXTRA_CFLAGS += -DPXA9XX
ifeq ($(CONFIG_PXA950), y)
EXTRA_CFLAGS += -DPXA950
KERNELDIR ?= /usr/src/arm/linux-2.6.29-pxa950
CROSS_COMPILE ?= /usr/local/arm-marvell-linux-gnueabi/bin/arm-marvell-linux-gnueabi-
else
ifeq ($(CONFIG_PXA920), y)
EXTRA_CFLAGS += -DPXA920
KERNELDIR ?= /usr/src/arm/linux-2.6.29-pxa920
CROSS_COMPILE ?= /usr/local/arm-marvell-linux-gnueabi/bin/arm-marvell-linux-gnueabi-
else
ifeq ($(KMINORVER),25)
KERNELDIR ?= /usr/src/arm/linux-2.6.25-pxa9xx
CROSS_COMPILE ?= /usr/local/arm/4.1.1/bin/arm-linux-
else
KERNELDIR ?= /usr/src/arm/linux-2.6.24-pxa9xx
CROSS_COMPILE ?= /usr/local/arm/4.1.1/bin/arm-linux-
endif
endif
endif
ARCH ?= arm
else
ifeq ($(CONFIG_MOORESTOWN), y)
KERNELDIR ?= /root/rpmbuild/BUILD/kernel-2.6.31/linux-2.6.31
else
KERNELDIR = /lib/modules/$(shell uname -r)/build
endif
endif

	EXTRA_CFLAGS += -DFPNUM='"XX"'

ifeq ($(CONFIG_AMP), y)
EXTRA_CFLAGS += -DBT_AMP
EXTRA_CFLAGS += -I$(PWD)/include
endif

EXTRA_CFLAGS += -DCONFIG_BT_HCIUART_PS

hci_uart-y				:= hci_ldisc.o
hci_uart-$(CONFIG_BT_HCIUART_H4)	+= hci_h4.o
hci_uart-$(CONFIG_BT_HCIUART_BCSP)	+= hci_bcsp.o
hci_uart-$(CONFIG_BT_HCIUART_LL)	+= hci_ll.o
hci_uart-y				+= hci_ps.o
hci_uart-objs				:= $(hci_uart-y)

obj-m	:= hci_uart.o

BINDIR = ../bin_bturt
KMODPATH := kernel/drivers/bluetooth

PWD   := $(shell pwd)

default:
ifeq ($(CONFIG_PXA9XX), y)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules
else
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif

build: default
	@if [ ! -d $(BINDIR) ]; then \
		mkdir $(BINDIR); \
	fi 
	@cp -f hci_uart.ko $(BINDIR)
	@cp -f README $(BINDIR)

clean:
	find . -name "*.o" -exec rm {} \;
	find . -name "*.*~" -exec rm {} \;
	find . -name "*.d" -exec rm {} \;
	find . -name "*.mod.c" -exec rm {} \;
	find . -name "*.ko" -exec rm {} \;
	find . -name "*.symvers" -exec rm {} \;
	find . -name ".*.cmd" -exec rm {} \;
	rm -rf .tmp_versions

install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install INSTALL_MOD_DIR=$(KMODPATH)

PXA9XX PXA950 PXA920 X86 MOORESTOWN:
	@echo CONFIG_$@=y > $(CONFIG_FILE)

2.6.25:
	@echo "KMINORVER=25" >> $(CONFIG_FILE)

AMP:
	@echo "CONFIG_AMP=y" >> $(CONFIG_FILE)
