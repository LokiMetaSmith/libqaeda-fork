## Archived: 2026-11-02

* `src/cli/main.c` serves as a test/demo program that initializes Alice and Bob keys and creates/serializes certificates, rather than being a core library component.
* The project is built using `make`, and the test suite is executed via `make test`.
* Tests generally require the environment variable `CK_FORK=no` (e.g., `CK_FORK=no make test`) to run successfully without forking issues.
* The build system requires internal dependencies (like `liblash` and `cwalk`) to be located in `src/aux`; `src/aux_lib` was renamed to `src/aux` to match this expectation.
* The build configuration requires `RERR_N_PFX` in `src/aux/liblash/src/rerr/Makefile` to be set sufficiently high (e.g., 8) and `-DRERR` added to `src/lq/Makefile` to prevent runtime segmentation faults in the logging system.
* The project `libqaeda` is a C library aimed at enabling bi-lateral countersigning of chains of promises and statements.
* The module `src/lq/trust.c` utilizes stack allocation and does not perform dynamic memory allocations via `lq_alloc`, making it naturally resilient to OOM faults.
* The current development environment restricts installing system packages or compiling heavy dependencies (e.g., `libtasn1`), necessitating manual mocking of `src/asn1` outputs or skipping generation steps.
* The project implements `ALWAYS()`, `NEVER()`, and `testcase()` macros in `src/debug.h` to facilitate MC/DC coverage analysis and enforce coverage expectations.
* Core components (`msg`, `cert`, `envelope`, `config`, `ctx`), storage modules (`store/file.c`, `store/mem.c`), and crypto backends (`gcrypt`, `dummy`) implement strict NULL checking for `lq_alloc` to handle OOM scenarios.
* System dependencies required for development include `libtasn1-6-dev`, `libgcrypt20-dev`, `check`, and `pkg-config`.
* I/O utility functions such as `mktempdir` are implemented in `src/io/std.c` (and `dummy.c`) and declared in `src/lq/io.h`.
* The I/O wrapper functions `lq_read` and `lq_write` in `src/lq/io.h` and `src/io/std.c` use `size_t` for the byte count argument to prevent truncation.
* Out-Of-Memory (OOM) fault injection is implemented in `src/mem/std.c` via `lq_mem_simulate_oom`, which modifies `lq_alloc` to simulate failures using a deterministic global countdown.
* Linking tests in `src/test/Makefile` requires strict library ordering where `libqaeda` must precede its dependencies (like `libgcrypt`) in the linker command to resolve symbols correctly.
* The `lq_query_new` functionality is implemented only in `src/store/file.c`, indicating that complex query support is currently specific to the file-based store and not implemented for the memory-based store.
* Linking against `libgcrypt` in this environment requires explicitly adding `-lgpg-error` to the linker flags (e.g., in `src/test/Makefile`) to resolve symbols like `gpg_err_code_from_syserror`.
* The user requires a deep planning mode before changes, involving clarifying questions to ensure absolute certainty of requirements.
* The `src/asn1/Makefile` conditionally executes `generate_asn1` to create `defs_asn1_tab.c`; if the generator is missing, it skips generation to prevent build failures in restricted environments.
* Cryptographic signature generation in `src/crypto/gcrypt.c` logic was patched to enforce 32-byte length for MPI exports, handling padding and trimming of leading zeros.
* I/O error fault injection is implemented in `src/io/std.c` via `lq_io_simulate_error`, which modifies `lq_open`, `lq_read`, and `lq_write` to simulate failures using a deterministic global countdown.
* `lq_certificate_serialize` in `src/lq/cert.c` implements a fallback mechanism for the resolver: it prioritizes the passed `resolve` argument but falls back to the certificate's internal `cert->resolve` if the argument is NULL.
* `make clean` targets in `src/test/Makefile` and `src/lq/Makefile` explicitly remove coverage artifacts (`*.gcno`, `*.gcda`).
* `lq_privatekey_bytes` is implemented in `src/crypto/gcrypt.c` by caching the private key bytes (extracted from the 'd' parameter of the S-expression) within `struct gpg_store` during key application.
* The `testcase()` macro is used in source files (instrumented in `lq/msg.c`, `lq/cert.c`, `lq/envelope.c`, `lq/config.c`, `lq/ctx.c`, `store/file.c`, `store/mem.c`, `crypto/gcrypt.c`, `crypto/dummy.c`, `lq/trust.c`) to mark reachable defensive checks to ensure they are counted during coverage analysis.
* `src/store/file.c` uses `lq_write` and `lq_read` wrappers exclusively (instead of syscalls) to support I/O fault injection.
* `src/Makefile` explicitly defines dependencies (`gpg` depends on components, which depend on `core`, which depends on `aux` and `asn1`) to enforce correct ordering during parallel builds (`make -j`).
* Fault injection verification tests are located in `src/test/test_faults.c` and integrated into the `src/test/Makefile` build process.
* The project targets 100% MC/DC coverage and robust anomaly testing (OOM, I/O errors) modeled after SQLite's testing strategy, tracked in `TODO.md`.
* `src/test/Makefile` utilizes individual targets for each test binary to enable parallel compilation.
* The `coverage` target in `src/test/Makefile` compiles with coverage flags, executes tests, and generates a text-based summary report using `gcov` and `awk`.
