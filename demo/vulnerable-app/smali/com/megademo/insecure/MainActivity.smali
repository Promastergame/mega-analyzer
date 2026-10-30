# Intentionally vulnerable smali for demonstrating Mega-Analyzer.
# Hand-written (not produced by baksmali) and deliberately minimal: it exercises
# reflection, runtime exec, native library loading, weak crypto and hardcoded
# secrets so the scanner has something concrete to report.

.class public Lcom/megademo/insecure/MainActivity;
.super Landroid/app/Activity;

# --- Hardcoded secrets (should be flagged by the secret detector) ---
.field private static final AWS_KEY:Ljava/lang/String; = "AKIAIOSFODNN7EXAMPLE"
.field private static final GH_TOKEN:Ljava/lang/String; = "ghp_wWPw5k4aXcaT4fNP0UcnZwJUVFk6LO0pZZZZ"
.field private static final API_BASE:Ljava/lang/String; = "http://api.megademo.example/v1"

.method public onCreate(Landroid/os/Bundle;)V
    .locals 6

    # Load a native library by name (native-load surface)
    const-string v0, "megademo-native"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    # Reflection: resolve and invoke a method by name at runtime
    const-string v1, "com.megademo.insecure.Hidden"
    invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v2

    # Runtime.exec of an attacker-influenced command (command-injection surface)
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    move-result-object v3
    const-string v4, "sh -c id"
    invoke-virtual {v3, v4}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;

    # Weak cipher (ECB / DES) — should be flagged as weak crypto
    const-string v5, "DES/ECB/PKCS5Padding"
    invoke-static {v5}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    return-void
.end method
