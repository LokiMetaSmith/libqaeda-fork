#include <check.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "lq/base.h"
#include "lq/io.h"
#include "lq/mem.h"
#include "lq/store.h"

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

Suite * faults_suite(void) {
	Suite *s;
	TCase *tc;

	s = suite_create("faults");
	tc = tcase_create("core");
	tcase_add_test(tc, check_oom_allocation);
	tcase_add_test(tc, check_io_error);
	tcase_add_test(tc, check_store_new_oom);
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
