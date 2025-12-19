# TODO: Complete Test Coverage

## Goals
- Achieve 100% MC/DC (Modified Condition/Decision Coverage) for core logic.
- Implement robust anomaly testing for Out-Of-Memory (OOM) and I/O error conditions.

## Tasks
- [x] Create `TODO.md`
- [x] Implement OOM simulation hooks in `lq_alloc`.
- [x] Implement I/O error simulation hooks in `lq_open`, `lq_read`, `lq_write`.
- [x] Create `test_faults.c` to verify library behavior under simulated faults.
- [x] Integrate new tests into the build system.
- [x] Add OOM coverage for core objects (`LQMsg`, `LQCert`, `LQEnvelope`).
- [x] Add OOM coverage for `src/crypto` (gcrypt and dummy) and `src/lq/config`.
- [x] Run coverage analysis to identify remaining untested branches.
- [ ] Utilize `ALWAYS`, `NEVER`, `testcase` macros in codebase.
- [ ] Add `coverage` target to root Makefile and automate reports.
