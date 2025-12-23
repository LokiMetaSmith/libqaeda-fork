#include <string.h>
#include <stdlib.h>
#include <stddef.h>

static int lq_mem_oom_countdown = -1;
static int lq_mem_oom_repeat = 0;

void lq_mem_simulate_oom(int countdown, int repeat) {
	lq_mem_oom_countdown = countdown;
	lq_mem_oom_repeat = repeat;
}

void* lq_alloc(size_t bytes) {
	if (lq_mem_oom_countdown >= 0) {
		if (lq_mem_oom_countdown == 0) {
			if (!lq_mem_oom_repeat) {
				lq_mem_oom_countdown = -1;
			}
			return NULL;
		}
		lq_mem_oom_countdown--;
	}
	return malloc(bytes);
}

void lq_free(void *o) {
	free(o);
}

int lq_cmp(const void *dst, const void *src, size_t len) {
	return memcmp(dst, src, len);
}

void* lq_cpy(void *dst, const void *src, size_t len) {
	return memcpy(dst, src, len);
}

void* lq_set(void *dst, const char b, size_t len) {
	return memset(dst, (int)b, len);
}

void* lq_zero(void *dst, size_t len) {
	return lq_set(dst, 0, len);
}

size_t lq_len(const char *s) {
	return strlen(s);
}
