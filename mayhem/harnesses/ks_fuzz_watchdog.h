/*
 * ks_fuzz_watchdog.h — per-input watchdog for the keystone fuzz harnesses.
 *
 * keystone's assembler expands directives like `.rept <huge>` and can spend unbounded time/memory on
 * a single adversarial input (a real, but slow/DoS-class, finding rather than a memory-safety bug).
 * Under libFuzzer's default 1200s per-unit timeout that stalls the whole campaign (and the local
 * fuzz-smoke gate) on the first such unit. This header arms a SIGALRM watchdog around every
 * LLVMFuzzerTestOneInput call so any single input that runs longer than KS_FUZZ_UNIT_TIMEOUT seconds
 * aborts (recorded as a timeout) instead of hanging indefinitely.
 *
 * It is force-included by mayhem/build.sh (-include) so the shipped harness .c files are unmodified:
 * the macro renames the harness's own entry point to an inner symbol; the real LLVMFuzzerTestOneInput
 * is provided by ks_fuzz_watchdog.c, which arms the alarm and calls the inner function.
 */
#ifndef KS_FUZZ_WATCHDOG_H
#define KS_FUZZ_WATCHDOG_H

#include <stdint.h>
#include <stddef.h>

#ifndef KS_FUZZ_UNIT_TIMEOUT
#define KS_FUZZ_UNIT_TIMEOUT 3   /* seconds per input before we declare a timeout */
#endif

/* Rename the harness's entry point; ks_fuzz_watchdog.c defines the real LLVMFuzzerTestOneInput. */
#define LLVMFuzzerTestOneInput ks_fuzz_inner_test_one_input
int ks_fuzz_inner_test_one_input(const uint8_t *Data, size_t Size);

#endif /* KS_FUZZ_WATCHDOG_H */
