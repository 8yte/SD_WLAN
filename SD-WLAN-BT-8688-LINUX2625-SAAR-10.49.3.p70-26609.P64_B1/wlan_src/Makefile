# File: Makefile
#
# Copyright (C) 2003-2008, Marvell International Ltd. 
#
# This software file (the "File") is distributed by Marvell International 
# Ltd. under the terms of the GNU General Public License Version 2, June 1991 
# (the "License").  You may use, redistribute and/or modify this File in 
# accordance with the terms and conditions of the License, a copy of which 
# is available along with the File in the gpl.txt file or by writing to 
# the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 
# 02111-1307 or on the worldwide web at http://www.gnu.org/licenses/gpl.txt.
#
# THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE 
# ARE EXPRESSLY DISCLAIMED.  The License provides additional details about 
# this warranty disclaimer.

CC=		$(CROSS_COMPILE)gcc
LD=		$(CROSS_COMPILE)ld
BACKUP=		/root/backup
YMD=		`date +%Y%m%d%H%M`

#############################################################################
# Configuration Options
#############################################################################

# Debug Option
# DEBUG LEVEL n/1/2:
# n: NO DEBUG
# 1: Only PRINTM(MSG,...), PRINTM(FATAL,...), ...
# 2: All PRINTM()
CONFIG_DEBUG=1

# Proc in /proc/net/wlan
CONFIG_PROC_DEBUG=y

# Re-association in driver
CONFIG_REASSOCIATION=y

# Manufacturing firmware support
CONFIG_MFG_CMD_SUPPORT=y

# Big-endian platform
CONFIG_BIG_ENDIAN=n

# PXA DMA alignment
CONFIG_PXA3XX_DMA_ALIGN=y

# WAPI support
CONFIG_WAPI=y

# WAPI support in driver
CONFIG_WAPI_DRIVER=y

# SDIO suspend/resume
CONFIG_SDIO_SUSPEND_RESUME=n

#############################################################################
# Select Platform Tools
#############################################################################

MODEXT = ko
EXTRA_CFLAGS += -I$(PWD)/wlan

# KERNELDIR point to the installed kernel directory
# for PXA3XX BSP. 
# KERNELDIR can be set on the command line 
# make KERNELDIR=/usr/src/arm/<arch-bsp-path>
# Alternatively KERNELDIR can be set in the environment.
# Default value for KERNELDIR is set below.
KERNELDIR ?= /usr/src/arm/linux-2.6.25-pxa9xx

# CROSS_COMPILE specify the prefix used for all executables used
# during compilation. Only gcc and related bin-utils executables
# CROSS_COMPILE can be set on the command line 
# make CROSS_COMPILE=</usr/local/arm/4.1.1/bin/>arm-linux-
# Alternatively CROSS_COMPILE can be set in the environment.
# Default value for CROSS_COMPILE is set below.
CROSS_COMPILE ?= /usr/local/arm/4.1.1/bin/arm-linux-

# INSTALLDIR specify the path to install the kernel module after
# succesful compilation.
# INSTALLDIR can be set on the command line 
# make INSTALLDIR=/tftpboot/<rootfs>
# Alternatively INSTALLDIR can be set in the environment.
# Default value for INSTALL is set below.
INSTALLDIR ?= /tftpboot/pxa3xx/root

# ARCH specifies the architecture of the target processor, this kernel
# module will run.
# ARCH can be set on the command line
# make ARCH=<arm/i386>
# Alternatively ARCH can be set in the environment
# Default values of ARCH for specific platform are set below.
ARCH ?= arm

LD += -S

BINDIR = ../bin_sd8688

#############################################################################
# Compiler Flags
#############################################################################

	EXTRA_CFLAGS += -I$(KERNELDIR)/include

ifeq ($(CONFIG_WAPI_DRIVER),y)
	EXTRA_CFLAGS += -I$(PWD)/mcypt
endif

	EXTRA_CFLAGS += -DFPNUM='"49"'

ifeq ($(CONFIG_DEBUG),1)
	EXTRA_CFLAGS += -DDEBUG_LEVEL1
endif

ifeq ($(CONFIG_DEBUG),2)
	EXTRA_CFLAGS += -DDEBUG_LEVEL1
	EXTRA_CFLAGS += -DDEBUG_LEVEL2
	DBG=	-dbg
endif

ifeq ($(CONFIG_PROC_DEBUG),y)
	EXTRA_CFLAGS += -DPROC_DEBUG
	export CONFIG_PROC_DEBUG
endif

ifeq ($(CONFIG_REASSOCIATION),y)
	EXTRA_CFLAGS += -DREASSOCIATION
endif

ifeq ($(CONFIG_MFG_CMD_SUPPORT),y)
	EXTRA_CFLAGS += -DMFG_CMD_SUPPORT
endif

ifeq ($(CONFIG_BIG_ENDIAN),y)
	EXTRA_CFLAGS += -DBIG_ENDIAN
endif

ifeq ($(CONFIG_PXA3XX_DMA_ALIGN), y)
	EXTRA_CFLAGS += -DPXA3XX_DMA_ALIGN
	export CONFIG_PXA3XX_DMA_ALIGN
endif

ifeq ($(CONFIG_WAPI),y)
	EXTRA_CFLAGS += -DWAPI
ifeq ($(CONFIG_WAPI_DRIVER),y)
	EXTRA_CFLAGS += -DWAPI_DRIVER
endif
endif

ifeq ($(CONFIG_SDIO_SUSPEND_RESUME),y)
	EXTRA_CFLAGS += -DSDIO_SUSPEND_RESUME
endif

#############################################################################
# Make Targets
#############################################################################

ifneq ($(KERNELRELEASE),)

WLANOBJS = wlan/wlan_main.o wlan/wlan_init.o \
		wlan/wlan_wext.o \
		wlan/wlan_rx.o wlan/wlan_tx.o \
		wlan/wlan_cmd.o wlan/wlan_cmdresp.o \
		wlan/wlan_scan.o wlan/wlan_join.o

WLANOBJS += wlan/wlan_priv.o
WLANOBJS += wlan/wlan_wmm.o
WLANOBJS += wlan/wlan_11d.o
WLANOBJS += wlan/wlan_11h.o
WLANOBJS += wlan/wlan_meas.o
ifeq ($(CONFIG_WAPI),y)
ifeq ($(CONFIG_WAPI_DRIVER),y)
WLANOBJS += wlan/wlan_wapi.o
MCYPTOBJS =	mcypt/mcypt.o
endif
endif

ifdef CONFIG_PROC_FS
WLANOBJS += wlan/wlan_proc.o
ifeq ($(CONFIG_PROC_DEBUG), y)
WLANOBJS += wlan/wlan_debug.o
endif
endif

WLANOBJS += wlan/wlan_sdio_mmc.o
obj-m := sd8xxx.o
sd8xxx-objs := $(WLANOBJS)

ifeq ($(CONFIG_WAPI),y)
ifeq ($(CONFIG_WAPI_DRIVER),y)
obj-m += mcypt.o
mcypt-objs := $(MCYPTOBJS)
endif
endif

# Otherwise we were called directly from the command line; invoke the kernel build system.
else

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

endif

###############################################################

export		CC LD EXTRA_CFLAGS KERNELDIR

.PHONY: app/wlanconfig wlan clean distclean


	@echo "Finished Making Marvell Wlan Linux Driver"

wlan app/wlanconfig:
	$(MAKE) -C $@

echo:

build:		echo default

	@if [ ! -d $(BINDIR) ]; then \
		mkdir $(BINDIR); \
	fi 
	cp -f sd8xxx.$(MODEXT) $(BINDIR)/sd8688$(DBG).$(MODEXT)
ifeq ($(CONFIG_WAPI),y)
ifeq ($(CONFIG_WAPI_DRIVER),y)
	cp -f mcypt.$(MODEXT) $(BINDIR)
endif
endif

	cp -f README $(BINDIR)
	$(MAKE) -C app/wlanconfig $@ INSTALLDIR=$(BINDIR)
	cp -r config $(BINDIR)

clean:
	-find . -name "*.o" -exec rm {} \;
	-find . -name "*.ko" -exec rm {} \;
	-find . -name ".*.cmd" -exec rm {} \;
	-find . -name "*.mod.c" -exec rm {} \;
	-find . -name "Module.symvers" -exec rm {} \;
	-rm -rf .tmp_versions
	$(MAKE) -C app/wlanconfig $@

install: default

	$(MAKE) -C app/wlanconfig $@ INSTALLDIR=$(INSTALLDIR)
	cp -f sd8xxx.$(MODEXT) $(INSTALLDIR)/sd8688$(DBG).$(MODEXT)
	echo "sd8688 Driver Installed"


distclean:
	-find . -name "*.o" -exec rm {} \;
	-find . -name "*.orig" -exec rm {} \;
	-find . -name "*.swp" -exec rm {} \;
	-find . -name "*.*~" -exec rm {} \;
	-find . -name "*~" -exec rm {} \;
	-find . -name "*.d" -exec rm {} \;
	-find . -name "*.a" -exec rm {} \;
	-find . -name "tags" -exec rm {} \;
	-find . -name ".*" -exec rm -rf 2> /dev/null \;
	-find . -name "*.ko" -exec rm {} \;
	-find . -name ".*.cmd" -exec rm {} \;
	-find . -name "*.mod.c" -exec rm {} \;
	-rm -rf .tmp_versions
	$(MAKE) -C app/wlanconfig $@

# End of file
