
MOD=kfit-info

KFI_TOP ?=$(shell pwd)/../..
KFI=$(KFI_TOP)/kfi

all:
	echo $(PWD)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) \
		KBUILD_EXTRA_SYMBOLS+=$(KFI)/Module.symvers modules
 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

main.o: main.c Makefile

LOC ?=$(shell ip addr show ib0 | fgrep 'inet ' | cut -f 6 -d' ' | cut -f 1 -d '/')

info: $(MOD).ko
	modinfo $(MOD).ko

load: $(MOD).ko
	insmod $(MOD).ko ibv_ipaddr=$(LOC)

check:
	@lsmod | fgrep  $(MOD); if [ $$? -eq 1 ] ; then echo "$(MOD) not loaded" ; fi


unload:
	rmmod $(MOD)

reset:
	-@sudo rmmod $(MODULE_NAME) 2>/dev/null || echo > /dev/null
	-@dmesg -c &> /dev/null

creset:
	-@sudo rmmod $(MODULE_NAME) 2> /dev/null || echo > /dev/null
	-@dmesg -c &>/dev/null
	clear


help:
	@echo "make load	# load getinfo test, see dmesg output"
	@echo "make unload	# unload getinfo test"
	@echo "make kfi_load	# load kfi + verbs provider"
	@echo "make kcheck	# check if any kfi* modules loaded"
	@echo "make reset	# unload $(MOD) and clear dmesg"

kfi_unload:
	-rmmod kfip_verbs
	-rmmod kfi

kfi_load:
	-insmod $(KFI_TOP)/kfi/kfi.ko
	insmod $(KFI_TOP)/prov/verbs/kfip_verbs.ko

kcheck:
	@lsmod | fgrep  kf; if [ $$? -eq 1 ] ; then echo "kf* not loaded" ; fi

