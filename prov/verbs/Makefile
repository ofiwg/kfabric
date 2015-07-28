# build out-of-tree kernel module: kfi (Infiniband verbs) provider.

KFI_TOP=$(shell pwd)/../..
KFI=$(KFI_TOP)/kfi

MOD=kfip_verbs

ifneq ("","$(wildcard /usr/src/compat-rdma)")
  #for OFED-3.12
  OFED_DIR:=/usr/src/compat-rdma
else ifneq ("","$(wildcard /usr/src/ofa_kernel)")
  #for OFED 1.5.4.1
  OFED_DIR:=/usr/src/ofa_kernel
else
  OFED_DIR:=
endif

KDIR ?= /lib/modules/`uname -r`/build
autoconf_h=$(shell /bin/ls -1 $(KDIR)/include/*/autoconf.h | head -1)
kconfig_h=$(shell /bin/ls -1 $(KDIR)/include/*/kconfig.h 2>/dev/null | head -1)

MODULE_DIR:=$(PWD)
BASE_DIR:=$(MODULE_DIR)/../..

KSYM := $(BASE_DIR)/kfi/Module.symvers

ifeq ("$(OFED_DIR)","")
 INCLUDES:=
else
 KSYM += $(OFED_DIR)/Module.symvers

 INCLUDES:= -include $(autoconf_h)

 ifneq ($(kconfig_h),)
   INCLUDES+= -include $(kconfig_h)
 endif

 INCLUDES+= -I$(BASE_DIR)/include \
	    -I$(OFED_DIR)/include \
	    -I$$(srctree)/arch/$$(SRCARCH)/include \
	    -Iarch/$$(SRCARCH)/include/generated \
	    $$(if $$(KBUILD_SRC), -I$$(srctree)/include) \
	    -Iinclude \
	    -I$$(srctree)/arch/$$(SRCARCH)/include/uapi \
	    -Iarch/$$(SRCARCH)/include/generated/uapi \
	    -I$$(srctree)/include/uapi \
	    -Iinclude/generated/uapi
endif

INCLUDES+=-g

KBUILD_SRC=$(KDIR)

obj-m += $(MODULE_NAME).o

$(MODULE_NAME)-y := \
	main.o

all: $(KSYM)
	@echo $(PWD)
	@make -C $(KDIR) M=$(MODULE_DIR) modules \
		LINUXINCLUDE='$(INCLUDES)' KBUILD_EXTRA_SYMBOLS+='$(KSYM)'

clean:
	@make -C $(KDIR) M=$(MODULE_DIR) clean 2>&1 >/dev/null
	@echo Done.

main.o: main.c ibpv.h Makefile

info: $(MOD).ko
	modinfo $(MOD).ko

load: $(MOD).ko
	insmod $(MOD).ko

kcheck:
	@lsmod | fgrep  kf; if [ $$? -eq 1 ] ; then echo "kf* not loaded" ; fi

unload:
	rmmod $(MOD)

help:
	@echo "  make		# build ib provider"
	@echo "  make clean	# remove generated files"
	@echo "  make load	# load ib provider"
	@echo "  make unload	# unload ib provider"
	@echo "  make info	# show modinfo ib provider"
