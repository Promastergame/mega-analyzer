.class public final Lcom/megademo/testapp/NativeLabBridge;
.super Ljava/lang/Object;
.source "NativeLabBridge.java"

.field private static loaded:Z

.method static constructor <clinit>()V
    .registers 1

    :try_start_0
    const-string v0, "demo_lab"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    const/4 v0, 1
    sput-boolean v0, Lcom/megademo/testapp/NativeLabBridge;->loaded:Z
    :try_end_0
    goto +5
    :catch_0_9
    move-exception v0
    const/4 v0, 0
    sput-boolean v0, Lcom/megademo/testapp/NativeLabBridge;->loaded:Z
    return-void
    .catch Ljava/lang/UnsatisfiedLinkError; {:try_start_0 .. :try_end_0} :catch_0_9
.end method

.method private constructor <init>()V
    .registers 1
    .param p0    # this: Lcom/megademo/testapp/NativeLabBridge;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static isAvailable()Z
    .registers 2

    sget-boolean v0, Lcom/megademo/testapp/NativeLabBridge;->loaded:Z
    const/4 v1, 0
    if-nez v0, +3
    return v1
    :try_start_0
    invoke-static {}, Lcom/megademo/testapp/NativeLabBridge;->nativePing()Z
    move-result v0
    :try_end_0
    return v0
    :catch_0_b
    move-exception v0
    return v1
    .catch Ljava/lang/UnsatisfiedLinkError; {:try_start_0 .. :try_end_0} :catch_0_b
.end method

.method public static native nativeCoinsFromLab()I
    # abstract or native
.end method

.method public static native nativePing()Z
    # abstract or native
.end method

