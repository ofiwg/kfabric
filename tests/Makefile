SUBDIRS= getinfo				\
	ibverbs/mm2/svr ibverbs/mm2/cli

all:
	@for d in $(SUBDIRS); do \
		pushd $$d >/dev/null ; make && popd >/dev/null; \
	done
	find . -name "*.ko" -print

clean:
	@for d in $(SUBDIRS); do \
		pushd $$d >/dev/null ; make clean && popd >/dev/null; \
	done

