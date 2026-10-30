.class public final Lcom/megademo/testapp/AgeGate;
.super Ljava/lang/Object;
.source "AgeGate.java"

.field private final context:Landroid/content/Context;

.method public constructor <init>(Landroid/content/Context;)V
    .registers 2
    .param p0    # this: Lcom/megademo/testapp/AgeGate;
    .param p1    # Landroid/content/Context;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V
    iput-object v1, v0, Lcom/megademo/testapp/AgeGate;->context:Landroid/content/Context;
    return-void
.end method

.method public canOpenMatureSection(Ljava/lang/String;)Z
    .registers 5
    .param p0    # this: Lcom/megademo/testapp/AgeGate;
    .param p1    # Ljava/lang/String;

    new-instance v0, Lcom/megademo/testapp/AgeVerificationClient;
    invoke-direct {v0}, Lcom/megademo/testapp/AgeVerificationClient;-><init>()V
    invoke-virtual {v0, v4}, Lcom/megademo/testapp/AgeVerificationClient;->isAdult(Ljava/lang/String;)Z
    move-result v4
    iget-object v0, v3, Lcom/megademo/testapp/AgeGate;->context:Landroid/content/Context;
    const-string v1, "demo_age"
    const/4 v2, 0
    invoke-virtual {v0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0
    const-string v1, "adult"
    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z
    move-result v0
    nop
    if-eqz v4, +6
    if-eqz v0, +4
    const/4 v4, 1
    return v4
    return v2
.end method

