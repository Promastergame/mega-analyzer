/*
 * evasion_sample.c — Mega-Analyzer test fixture
 *
 * Purpose: sandbox/VM-detection strings are one of the strongest static
 * signals that a sample is trying to notice it's being analyzed. This
 * binary just checks for and PRINTS whether common VM markers are
 * present on the host — it never changes its own behavior based on the
 * result, so it stays a detection signal only, not real evasion.
 */
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

static const char *vm_markers[] = {
    "VirtualBox",
    "VMware",
    "QEMU",
    "innotek GmbH",
};

int main(void) {
    long rc = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    printf("self-trace check returned %ld\n", rc);

    FILE *f = fopen("/sys/class/dmi/id/product_name", "r");
    char line[128] = {0};
    if (f) {
        if (fgets(line, sizeof(line), f) == NULL) line[0] = '\0';
        fclose(f);
    }

    printf("dmi product_name: %s\n", line[0] ? line : "(unavailable)");

    for (size_t i = 0; i < sizeof(vm_markers) / sizeof(vm_markers[0]); i++) {
        if (strstr(line, vm_markers[i])) {
            printf("marker matched: %s\n", vm_markers[i]);
        }
    }

    printf("(informational only — behavior is unchanged either way)\n");
    return 0;
}
