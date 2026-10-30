.class public final Lcom/megademo/testapp/IntegrityGate;
.super Ljava/lang/Object;
.source "IntegrityGate.java"

.method public constructor <init>()V
    .registers 1
    .param p0    # this: Lcom/megademo/testapp/IntegrityGate;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public isTrustedDevice()Z
    .registers 2
    .param p0    # this: Lcom/megademo/testapp/IntegrityGate;

    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z
    move-result v0
    xor-int/lit8 v0, v0, 1
    return v0
.end method

