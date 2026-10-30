/*
 * secrets_sample.c — Mega-Analyzer test fixture
 *
 * Purpose: exercise pkg/internal/secrets provider rules by embedding
 * well-known, publicly-documented PLACEHOLDER credentials as string
 * literals. None of these are live/working credentials:
 *   - AWS key is Amazon's own published example key (docs.aws.amazon.com)
 *   - JWT is the canonical example token from jwt.io's homepage
 *   - Slack token / private key are structurally-valid but fabricated
 *
 * Expected findings (see providers.go):
 *   secret/aws-access-key, secret/slack-token, secret/jwt-token,
 *   secret/private-key
 */
#include <stdio.h>

static const char *aws_key      = "AKIAIOSFODNN7EXAMPLE";
static const char *slack_token  = "xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWX";
static const char *jwt_example  =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
static const char *fake_privkey =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEF\n"
    "AKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
    "-----END RSA PRIVATE KEY-----\n";

int main(void) {
    /* Simulates a badly-written app that dumps its config to stdout —
     * the exact pattern the secret scanner is meant to catch before
     * this ever ships in a real release build. */
    printf("config dump (do not do this in real apps):\n");
    printf("aws_key=%s\n", aws_key);
    printf("slack_token=%s\n", slack_token);
    printf("jwt=%s\n", jwt_example);
    printf("private_key=%s\n", fake_privkey);
    return 0;
}
