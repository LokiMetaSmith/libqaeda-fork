all: lib
	make -C src all

lib:
	make -C src dev-lib

test: all
	make -C src test

coverage:
	make -C src/test coverage

clean:
	make -C src clean

#shared: lib
#	make -C src shared-gpg

.PHONY: clean
