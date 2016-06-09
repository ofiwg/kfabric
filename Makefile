ifneq ($(KERNELRELEASE),)

include Kbuild

else

KVER	:= $(shell uname -r)
#KVER	:=4.5.0

KDIR	:= /lib/modules/$(KVER)/build
PWD	:= $(shell pwd)
INSTALL_MOD_DIR	:= kfabric
DEPMOD	:= /usr/sbin/depmod

ifneq ("","$(wildcard /usr/src/compat-rdma)")
  #for OFED
  KSYM	:= /usr/src/compat-rdma/Module.symvers
else
  KSYM :=
endif

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules KBUILD_EXTRA_SYMBOLS+='$(KSYM)'

install:
	$(MAKE) INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) -C $(KDIR) M=$(PWD) modules_install
	$(DEPMOD) $(KVER)

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

help:
	$(MAKE) -C $(KDIR) M=$(PWD) help

endif
