/*
 * weak_crypto_sample.c — Mega-Analyzer test fixture
 *
 * Purpose: a hand-rolled single-byte XOR "cipher" is one of the most
 * common weak-crypto patterns malware/obfuscators use instead of a
 * real algorithm. Operates only on a local in-memory buffer — no I/O,
 * no network, nothing persisted.
 */
#include <stdio.h>
#include <string.h>

static void xor_cipher(unsigned char *buf, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

int main(void) {
    unsigned char msg[] = "mega-analyzer weak crypto test payload";
    size_t len = strlen((char *)msg);
    unsigned char key = 0x5A;

    xor_cipher(msg, len, key);
    printf("xor-\"encrypted\" bytes: ");
    for (size_t i = 0; i < len; i++) printf("%02x", msg[i]);
    printf("\n");

    xor_cipher(msg, len, key); /* xor is its own inverse */
    printf("round-trip decrypted: %s\n", msg);

    return 0;
}
