#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "lq/base.h"
#include "lq/io.h"
#include "lq/mem.h"
#include "lq/store.h"
#include "lq/msg.h"
#include "lq/cert.h"
#include "lq/envelope.h"
#include "lq/config.h"
#include "lq/crypto.h"
#include "lq/err.h"

START_TEST(check_oom_allocation) {
	void *ptr;

	// Normal allocation should succeed
	lq_mem_simulate_oom(-1, 0);
	ptr = lq_alloc(10);
	ck_assert_ptr_nonnull(ptr);
	lq_free(ptr);

	// Fail on next allocation
	lq_mem_simulate_oom(0, 0);
	ptr = lq_alloc(10);
	ck_assert_ptr_null(ptr);

	// Should be back to normal
	ptr = lq_alloc(10);
	ck_assert_ptr_nonnull(ptr);
	lq_free(ptr);

	// Fail after 1 successful allocation
	lq_mem_simulate_oom(1, 0);
	ptr = lq_alloc(10);
	ck_assert_ptr_nonnull(ptr);
	lq_free(ptr);
	ptr = lq_alloc(10);
	ck_assert_ptr_null(ptr);

	// Reset
	lq_mem_simulate_oom(-1, 0);
}
END_TEST

START_TEST(check_io_error) {
	int fd;
	char path[] = "/tmp/lq_test_io_XXXXXX";
	char buf[10];

	mktemp(path);

	// Normal open/write should succeed (creating file)
	lq_io_simulate_error(-1, 0);
	fd = lq_open(path, O_RDWR | O_CREAT, 0600);
	ck_assert_int_ge(fd, 0);
	ck_assert_int_eq(lq_write(fd, "test", 4), 4);
	lq_close(fd);

	// Fail open
	lq_io_simulate_error(0, 0);
	fd = lq_open(path, O_RDONLY, 0);
	ck_assert_int_eq(fd, -1);
	ck_assert_int_eq(errno, EIO);

	// Fail read after open
	lq_io_simulate_error(1, 0);
	fd = lq_open(path, O_RDONLY, 0);
	ck_assert_int_ge(fd, 0);
	ck_assert_int_eq(lq_read(fd, buf, 4), -1);
	ck_assert_int_eq(errno, EIO);
	lq_close(fd);

	// Cleanup
	unlink(path);
	lq_io_simulate_error(-1, 0);
}
END_TEST

START_TEST(check_store_new_oom) {
	LQStore *store;
	char path[LQ_PATH_MAX];
	int i;
	int success = 0;

	lq_cpy(path, "/tmp/lq_test_store_oom_XXXXXX", 30);
	mktempdir(path);

	// Iteratively fail allocations 0, 1, 2... until we cover all paths in lq_store_new (and its children)
	// We don't know exactly how many allocations, so we just try a reasonable number.
	// This is a basic "fuzz" of the allocation path.
	for (i = 0; i < 50; i++) {
		lq_mem_simulate_oom(i, 0);
		store = lq_store_new(path);
		if (store) {
			// If it succeeded, verify we can free it.
			// Ideally we want to reach a point where it consistently succeeds.
			store->free(store);
			success++;
		}
		// Reset OOM
		lq_mem_simulate_oom(-1, 0);
	}

	// At least one (the later ones) should have succeeded.
	ck_assert_int_gt(success, 0);
}
END_TEST

START_TEST(check_file_store_io_errors) {
	LQStore *store;
	char path[LQ_PATH_MAX];
	char key[10] = "testkey";
	size_t key_len = 7;
	char val[10] = "val";
	size_t val_len = 3;
	char out_val[10];
	size_t out_len = 10;
	int r;

	lq_cpy(path, "/tmp/lq_test_store_io_XXXXXX", 30);
	mktempdir(path);
	store = lq_store_new(path);
	ck_assert_ptr_nonnull(store);

	// Test PUT failure (Open)
	lq_io_simulate_error(0, 0);
	r = store->put(LQ_CONTENT_RAW, store, key, &key_len, val, val_len);
	ck_assert_int_eq(r, ERR_NOENT);

	// Test PUT failure (Write)
	lq_io_simulate_error(1, 0); // 0=open succeeds, 1=write fails
	r = store->put(LQ_CONTENT_RAW, store, key, &key_len, val, val_len);
	ck_assert_int_eq(r, ERR_WRITE);

	// Successful PUT for setup
	lq_io_simulate_error(-1, 0);
	r = store->put(LQ_CONTENT_RAW, store, key, &key_len, val, val_len);
	ck_assert_int_eq(r, ERR_OK);

	// Test GET failure (Open)
	lq_io_simulate_error(0, 0);
	r = store->get(LQ_CONTENT_RAW, store, key, key_len, out_val, &out_len);
	ck_assert_int_eq(r, ERR_NOENT);

	// Test GET failure (Read)
	lq_io_simulate_error(1, 0); // 0=open succeeds, 1=read fails
	r = store->get(LQ_CONTENT_RAW, store, key, key_len, out_val, &out_len);
	ck_assert_int_eq(r, ERR_FAIL);

	store->free(store);
	lq_io_simulate_error(-1, 0);
}
END_TEST

START_TEST(check_msg_new_oom) {
	LQMsg *msg;
	const char *data = "testdata";
	size_t len = 8;

	// 1. Fail first alloc (structure)
	lq_mem_simulate_oom(0, 0);
	msg = lq_msg_new(data, len);
	ck_assert_ptr_null(msg);

	// 2. Fail second alloc (data)
	lq_mem_simulate_oom(1, 0);
	msg = lq_msg_new(data, len);
	ck_assert_ptr_null(msg);

	// 3. Success
	lq_mem_simulate_oom(-1, 0);
	msg = lq_msg_new(data, len);
	ck_assert_ptr_nonnull(msg);
	lq_msg_free(msg);
}
END_TEST

START_TEST(check_cert_new_oom) {
	LQCert *cert;

	// 1. Fail first alloc
	lq_mem_simulate_oom(0, 0);
	cert = lq_certificate_new(NULL);
	ck_assert_ptr_null(cert);

	// 2. Success
	lq_mem_simulate_oom(-1, 0);
	cert = lq_certificate_new(NULL);
	ck_assert_ptr_nonnull(cert);
	lq_certificate_free(cert);
}
END_TEST

START_TEST(check_envelope_new_oom) {
	LQEnvelope *env;

	// 1. Fail first alloc (structure)
	lq_mem_simulate_oom(0, 0);
	env = lq_envelope_new(NULL, 0);
	ck_assert_ptr_null(env);

	// 2. Fail second alloc (attach structure in new())
	lq_mem_simulate_oom(1, 0);
	env = lq_envelope_new(NULL, 0);
	ck_assert_ptr_null(env);

	// 3. Success
	lq_mem_simulate_oom(-1, 0);
	env = lq_envelope_new(NULL, 0);
	ck_assert_ptr_nonnull(env);
	lq_envelope_free(env);
}
END_TEST

START_TEST(check_config_init_oom) {
	int r;

	// Fail various allocs in config_init
	lq_mem_simulate_oom(0, 0);
	r = lq_config_init();
	ck_assert_int_eq(r, ERR_MEM);

	lq_mem_simulate_oom(1, 0);
	r = lq_config_init();
	ck_assert_int_eq(r, ERR_MEM);

	lq_mem_simulate_oom(2, 0);
	r = lq_config_init();
	ck_assert_int_eq(r, ERR_MEM);

	lq_mem_simulate_oom(3, 0);
	r = lq_config_init();
	ck_assert_int_eq(r, ERR_MEM);

	lq_mem_simulate_oom(-1, 0);
}
END_TEST

START_TEST(check_crypto_oom) {
	LQPrivKey *pk;
	LQPubKey *pubk;
	char *pk_bytes;

	// Private key new
	lq_mem_simulate_oom(0, 0);
	pk = lq_privatekey_new("pass", 4);
	ck_assert_ptr_null(pk);

	lq_mem_simulate_oom(1, 0);
	pk = lq_privatekey_new("pass", 4);
	ck_assert_ptr_null(pk);

	// Public key new
	lq_mem_simulate_oom(-1, 0);
	pk = lq_privatekey_new("pass", 4); // Need a valid one to get bytes
	ck_assert_ptr_nonnull(pk);
	lq_privatekey_bytes(pk, &pk_bytes);

	lq_mem_simulate_oom(0, 0);
	pubk = lq_publickey_new(pk_bytes);
	ck_assert_ptr_null(pubk);

	lq_mem_simulate_oom(1, 0);
	pubk = lq_publickey_new(pk_bytes);
	ck_assert_ptr_null(pubk);

	lq_privatekey_free(pk);
	lq_mem_simulate_oom(-1, 0);
}
END_TEST

Suite * faults_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("faults");
	tc = tcase_create("core");
	tcase_add_test(tc, check_oom_allocation);
	tcase_add_test(tc, check_io_error);
	tcase_add_test(tc, check_store_new_oom);
	tcase_add_test(tc, check_file_store_io_errors);
	tcase_add_test(tc, check_msg_new_oom);
	tcase_add_test(tc, check_cert_new_oom);
	tcase_add_test(tc, check_envelope_new_oom);
	tcase_add_test(tc, check_config_init_oom);
	tcase_add_test(tc, check_crypto_oom);
	suite_add_tcase(s, tc);

	return s;
}

int main(void) {
	int r;
	int n_fail;

	Suite *s;
	SRunner *sr;

	r = lq_init();
	if (r) {
		return 1;
	}

	s = faults_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_VERBOSE);
	n_fail = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (n_fail == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
