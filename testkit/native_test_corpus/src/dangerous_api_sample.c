/*
 * dangerous_api_sample.c — Mega-Analyzer test fixture
 *
 * Purpose: exercise the raw byte/string heuristic rules in
 * pkg/internal/pipeline/security_heuristics.go — "system(" (critical),
 * "dlopen" (high), "ptrace" (high). These are dynamic-symbol names, so
 * they survive stripping (-s) since the dynamic linker needs them —
 * only local debug symbols get stripped, not imported PLT entries.
 *
 * Every call here is inert: system() only runs `true`, dlopen() targets
 * a library that intentionally doesn't exist and the NULL return is
 * handled, and the ptrace() self-trace check just prints a message.
 */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

/* Note: the classic ptrace(PTRACE_TRACEME) self-debug check lives in
 * evasion_sample.c instead of here. Combining it with system()'s
 * internal fork+exec makes the process stop under trace waiting for a
 * debugger that never continues it (no tracer attached) — a real
 * hang, not a scanner concern, so the two patterns are kept apart. */

int main(void) {
    int rc = system("true"); /* no-op shell command */
    printf("system() exit status: %d\n", rc);

    void *h = dlopen("libthis_does_not_exist_mega_analyzer_test.so", RTLD_NOW);
    printf("dlopen() result: %p\n", h);
    if (h) dlclose(h);

    return 0;
}
