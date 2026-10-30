.class public final Lcom/megademo/testapp/AuthGate;
.super Ljava/lang/Object;
.source "AuthGate.java"

.field private final context:Landroid/content/Context;

.method public constructor <init>(Landroid/content/Context;)V
    .registers 2
    .param p0    # this: Lcom/megademo/testapp/AuthGate;
    .param p1    # Landroid/content/Context;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V
    iput-object v1, v0, Lcom/megademo/testapp/AuthGate;->context:Landroid/content/Context;
    return-void
.end method

.method public isAuthenticated()Z
    .registers 5
    .param p0    # this: Lcom/megademo/testapp/AuthGate;

    iget-object v0, v4, Lcom/megademo/testapp/AuthGate;->context:Landroid/content/Context;
    const-string v1, "demo_session"
    const/4 v2, 0
    invoke-virtual {v0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0
    const-string v1, "token"
    const-string v3, string@0000
    invoke-interface {v0, v1, v3}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    invoke-virtual {v0}, Ljava/lang/String;->length()I
    move-result v0
    if-lez v0, +4
    const/4 v0, 1
    return v0
    return v2
.end method

