OBJS := $(patsubst %.c,%.o,$(wildcard *.c))
INCLUDES := -I.. -I../aux/include $(shell pkg-config --cflags libtasn1 libgcrypt)
CFLAGS += $(INCLUDES) -Wall -g3
#LIBS := ../asn1/defs_asn1_tab.o `pkg-config --libs libtasn1 libgcrypt` -L../aux/lib -llash -lhashmap
LIBS := -L.. -L../aux/lib -lqaeda -lhashmap $(shell pkg-config --libs libtasn1 libgcrypt) -lgpg-error
LDFLAGS := -lcheck -lsubunit -lm $(LIBS)

TEST_SRCS := test_test.c test_debug.c test_config.c test_crypto.c test_msg.c test_cert.c test_envelope.c test_trust.c test_store.c test_query.c test_faults.c
TEST_BINS := $(TEST_SRCS:.c=_bin)

coverage: CFLAGS += -fprofile-arcs -ftest-coverage -DCOVERAGE_TEST
coverage: LDFLAGS += -fprofile-arcs -ftest-coverage
coverage: build all-tests coverage-report

coverage-report:
	@echo "------------------------------------------------------------------------------"
	@echo "                           Coverage Summary                                   "
	@echo "------------------------------------------------------------------------------"
	@echo "File                                       Lines Exec  Lines Total  Coverage"
	@echo "------------------------------------------------------------------------------"
	@for file in ../lq/*.c ../store/*.c ../crypto/*.c ../io/*.c ../mem/*.c; do \
		gcov -n -o .. $${file} > /dev/null 2>&1; \
		gcov_file=$$(basename $${file}).gcov; \
		if [ -f $$gcov_file ]; then \
			awk -v fname=$$(basename $${file}) '/Lines executed:/ { printf "%-40s %10s %12s %9s\n", fname, $$2, $$4, $$2 }' $$gcov_file | sed 's/%//g' | awk '{ printf "%-40s %10d %12d %8.2f%%\n", $$1, $$2/100*$$3, $$3, $$2 }'; \
			rm $$gcov_file; \
		fi \
	done
	@echo "------------------------------------------------------------------------------"

all: build all-tests
#all: build one-test

all-tests:
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_test_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_debug_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_config_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_crypto_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_msg_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_cert_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_envelope_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_trust_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_store_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_query_bin
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_faults_bin

one-test: build
	CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_cert_bin
	#CK_FORK=no LD_LIBRARY_PATH=`realpath ../aux/lib` ./test_query_bin

test: all

build: $(TEST_BINS)

test_test_bin: test_test.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test_debug_bin: test_debug.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test_config_bin: test_config.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test_crypto_bin: test_crypto.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lgcrypt

test_msg_bin: test_msg.c ../store/dummy.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lgcrypt

test_cert_bin: test_cert.c ../store/dummy.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lgcrypt

test_envelope_bin: test_envelope.c ../store/dummy.o
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lgcrypt

test_trust_bin: test_trust.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

test_store_bin: test_store.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lgcrypt

test_query_bin: test_query.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lgcrypt

test_faults_bin: test_faults.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) -lgcrypt

clean:
	rm -vf test_*_bin
	rm -vf *.o
	rm -vf *.gcno *.gcda

.PHONY: clean coverage coverage-report
