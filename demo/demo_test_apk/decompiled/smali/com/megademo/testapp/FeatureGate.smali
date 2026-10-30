.class public final Lcom/megademo/testapp/FeatureGate;
.super Ljava/lang/Object;
.source "FeatureGate.java"

.field private final flags:Landroid/content/SharedPreferences;

.method public constructor <init>(Landroid/content/Context;)V
    .registers 4
    .param p0    # this: Lcom/megademo/testapp/FeatureGate;
    .param p1    # Landroid/content/Context;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V
    const-string v0, "demo_flags"
    const/4 v1, 0
    invoke-virtual {v3, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v3
    iput-object v3, v2, Lcom/megademo/testapp/FeatureGate;->flags:Landroid/content/SharedPreferences;
    return-void
.end method

.method public isFeatureEnabled(Ljava/lang/String;)Z
    .registers 4
    .param p0    # this: Lcom/megademo/testapp/FeatureGate;
    .param p1    # Ljava/lang/String;

    const-string v0, "premium_store"
    invoke-virtual {v0, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-eqz v0, +12
    new-instance v3, Lcom/megademo/testapp/SubscriptionClient;
    invoke-direct {v3}, Lcom/megademo/testapp/SubscriptionClient;-><init>()V
    invoke-virtual {v3}, Lcom/megademo/testapp/SubscriptionClient;->hasPremium()Z
    move-result v3
    return v3
    iget-object v0, v2, Lcom/megademo/testapp/FeatureGate;->flags:Landroid/content/SharedPreferences;
    const/4 v1, 0
    invoke-interface {v0, v3, v1}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z
    move-result v3
    return v3
.end method

