# build kfi modules and provider tests.

IBV_SUBDIRS=prov/ibverbs

PROVIDERS=kfi $(IBV_SUBDIRS)

TESTS=tests

SUBDIRS=$(PROVIDERS) $(TESTS)

all:
	@for d in $(SUBDIRS) ; do \
		pushd $$d >/dev/null		; \
		make || exit 1			; \
		popd >/dev/null			; \
	done
	find . -name "*.ko"

tests:
	@for d in $(TESTS) ; do \
		pushd $$d >/dev/null            ; \
		make || exit 1                  ; \
		popd >/dev/null                 ; \
	done
	find . -name "*.ko"

clean:
	@for d in $(SUBDIRS) ; do		  \
		pushd $$d >/dev/null		; \
		echo "  `pwd`"			; \
		make clean >/dev/null 2>&1	; \
		popd >/dev/null			; \
	done


kfi_ib_load:
	( pushd kfi > /dev/null; make load; popd > /dev/null )
	( pushd prov/ibverbs > /dev/null; make load; popd > /dev/null )

kfi_ib_unload:
	( pushd prov/ibverbs > /dev/null; make unload; popd > /dev/null )
	( pushd kfi > /dev/null; make unload; popd > /dev/null )

kcheck:
	@lsmod | fgrep  kfi; if [ $$? -eq 1 ] ; then echo "kfi* not loaded" ; fi

help:
	@echo "  make or make all    - to build kfi kernel modules" 
	@echo "  make clean          - to rm kfi kernel modules" 
	@echo "  make kcheck         - to list kfi kernel modules" 
	@echo "  make kfi_ib_load    - to load kfi+ib-provider kernel modules" 
	@echo "  make kfi_ib_unload  - to rm kfi kernel modules" 

