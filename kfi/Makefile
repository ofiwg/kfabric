# build out-of-tree kernel module: kfi (Kernel Fabric Interface)
# kfabric module exports kfi_* kfi API

MOD=kfabric

all:
	echo $(PWD)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

main.o: $(src)/main.c Makefile
kfi.o: $(src)/kfi.c Makefile
common.o: $(src)/common.c Makefile
enosys.o: $(src)/enosys.c Makefile

info: $(MOD).ko
	modinfo $(MOD).ko

load: $(MOD).ko
	insmod $(MOD).ko

kcheck:
	@lsmod | fgrep  $(MOD); if [ $$? -eq 1 ] ; then echo "$(MOD) not loaded" ; fi


unload:
	rmmod $(MOD)
