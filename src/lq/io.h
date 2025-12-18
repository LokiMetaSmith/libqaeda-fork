#ifndef LIBQAEDA_IO_H_
#define LIBQAEDA_IO_H_

#ifndef LQ_PATH_MAX
#define LQ_PATH_MAX 1024
#endif

#ifndef LQ_DIRS_MAX
#define LQ_DIRS_MAX 1024
#endif

/**
 * @brief Create temporary directory using template.
 *
 * @param[in] Directory path template
 * @return Pointer to valid path string. NULL if directory could not be created.
 */
char* mktempdir(char *s);
char* ensuredir(char *s);
int lq_open(const char *pathname, int flags, int mode);
int lq_read(int f, char *buf, int c);
int lq_write(int f, char *buf, int c);

/**
 * @brief Configure I/O error simulation.
 *
 * @param[in] countdown Number of successful I/O ops before failure.
 * @param[in] repeat    If true, fail all subsequent I/O ops after countdown reaches 0.
 *                      If false, fail only once when countdown reaches 0.
 */
void lq_io_simulate_error(int countdown, int repeat);

int lq_files(const char *path, char **files, size_t files_len);
int lq_files_pfx(const char *path, char **files, size_t files_len, const char *prefix, size_t prefix_len);
void lq_close(int fd);

#endif // LIBQAEDA_IO_H_
