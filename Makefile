# build kfi modules and provider tests.

VERBS_SUBDIRS=prov/verbs

PROVIDERS=kfi $(VERBS_SUBDIRS)

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


kfi_verbs_load:
	( pushd kfi > /dev/null; make load; popd > /dev/null )
	( pushd prov/verbs > /dev/null; make load; popd > /dev/null )

kfi_verbs_unload:
	( pushd prov/verbs > /dev/null; make unload; popd > /dev/null )
	( pushd kfi > /dev/null; make unload; popd > /dev/null )

kcheck:
	@lsmod | fgrep  kfi; if [ $$? -eq 1 ] ; then echo "kfi* not loaded" ; fi

help:
	@echo "  make or make all    - to build kfi kernel modules" 
	@echo "  make clean          - to rm kfi kernel modules" 
	@echo "  make kcheck         - to list kfi kernel modules" 
	@echo "  make kfi_verbs_load - to load kfi+ib-provider kernel modules" 
	@echo "  make kfi_verbs_unload - to rm kfi kernel modules" 

