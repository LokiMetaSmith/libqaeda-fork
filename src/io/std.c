#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "lq/mem.h"


char *mktempdir(char *s) {
	return mkdtemp(s);
}

char *ensuredir(char *s) {
	int r;

	r = mkdir(s, S_IRWXU);
	if (r && r != EEXIST) {
		return NULL;	
	}
	return s;
}

static int lq_io_error_countdown = -1;
static int lq_io_error_repeat = 0;

void lq_io_simulate_error(int countdown, int repeat) {
	lq_io_error_countdown = countdown;
	lq_io_error_repeat = repeat;
}

static int lq_io_check_fail(void) {
	if (lq_io_error_countdown >= 0) {
		if (lq_io_error_countdown == 0) {
			if (!lq_io_error_repeat) {
				lq_io_error_countdown = -1;
			}
			errno = EIO;
			return 1;
		}
		lq_io_error_countdown--;
	}
	return 0;
}

int lq_open(const char *pathname, int flags, int mode) {
	if (lq_io_check_fail()) return -1;
	return open(pathname, flags, (mode_t)mode);
}

int lq_read(int f, void *buf, size_t c) {
	if (lq_io_check_fail()) return -1;
	return read(f, buf, c);
}

int lq_write(int f, void *buf, size_t c) {
	if (lq_io_check_fail()) return -1;
	return write(f, buf, c);
}

void lq_close(int fd) {
	close(fd);
}

static int fltr_files(const struct dirent *d) {
	int r;
	if (*((char*)d->d_name) == '.') {
		return 0;
	}
	return (d->d_type & (DT_LNK | DT_REG)) > 0 ? 1 : 0;
	return r;
}

/**
 * \todo scandir calls malloc, so lq_alloc needs malloc alias that maps to it.
 * \todo strdup doubles the mem needed for the iteration, instead need to keep scandir state and release after treatment
 */
int lq_files(const char *path, char **files, size_t files_len) {
	int r;
	int i;
	struct dirent **ls;

	r = 0;
	r = scandir(path, &ls, fltr_files, alphasort);
	if (r < 0) {
		return -1;
	}
	if (r > files_len + 1) {
		return -2;	
	}
	for (i = 0; i < r; i++) {
		//*(files+i) = (*(ls+i))->d_name;
		*(files+i) = strdup((*(ls+i))->d_name);
	}
	*(files+i+1) = NULL;
	lq_free(ls);
	return r;
}

int lq_files_pfx(const char *path, char **files, size_t files_len, const char *prefix, char prefix_len) {
	int r;
	int i;
	int c;
	size_t l;

	c = 0;
	r = lq_files(path, files, files_len);
	for (i = 0; i < r; i++) {
		l = strlen(*(files+i));
		if (l < prefix_len) {
			lq_free(*(files+i));
		}
		if (!lq_cmp(prefix, *(files+i), prefix_len)) {
			*(files+c) = *(files+i);
			c++;
		}
		*(files+i) = NULL;
	}
	for (i = c + 1; i < r; i++) {
		if (*(files+i) != NULL) {
			lq_free(*(files+i));
			*(files+i) = NULL;
		}
	}
	return c;
}

void lq_files_free(char **files) {
	int i;

	i = 0;
	do {
		if (*(files+i) == NULL) {
			break;
		}
		lq_free(*(files+i));
	} while(++i);
}
