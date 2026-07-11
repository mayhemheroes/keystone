/*
 * ks_fuzz_watchdog.c — defines the real LLVMFuzzerTestOneInput, which arms a per-input SIGALRM
 * watchdog (see ks_fuzz_watchdog.h) and delegates to the harness's renamed inner entry point.
 *
 * This file does NOT include ks_fuzz_watchdog.h (so LLVMFuzzerTestOneInput is the real name here),
 * but declares the inner symbol that the force-included header exposes in each harness object.
 */
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

#ifndef KS_FUZZ_UNIT_TIMEOUT
#define KS_FUZZ_UNIT_TIMEOUT 3
#endif

/* Provided by each harness object (its LLVMFuzzerTestOneInput renamed by the header). */
int ks_fuzz_inner_test_one_input(const uint8_t *Data, size_t Size);

static void ks_fuzz_alarm_handler(int sig) {
    (void)sig;
    _exit(70);   /* libFuzzer's kTimeoutExitCode — classified as a timeout, not a clean exit */
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int installed = 0;
    if (!installed) {
        struct sigaction sa;
        sa.sa_handler = ks_fuzz_alarm_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGALRM, &sa, NULL);
        installed = 1;
    }
    alarm(KS_FUZZ_UNIT_TIMEOUT);          /* arm: abort this input if it runs too long */
    int r = ks_fuzz_inner_test_one_input(Data, Size);
    alarm(0);                              /* disarm on normal completion */
    return r;
}
