/*
 * clean_control.c — Mega-Analyzer test fixture
 *
 * Purpose: a false-positive control. No secrets, no dangerous APIs, no
 * evasion tricks — just arithmetic and stdio. A good analyzer should
 * report this one clean (or very low risk).
 */
#include <stdio.h>

static long fib(int n) {
    long a = 0, b = 1;
    for (int i = 0; i < n; i++) {
        long t = a + b;
        a = b;
        b = t;
    }
    return a;
}

int main(void) {
    for (int i = 0; i < 10; i++) {
        printf("fib(%d) = %ld\n", i, fib(i));
    }
    return 0;
}
