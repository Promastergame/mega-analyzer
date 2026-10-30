.class public final Lcom/megademo/testapp/MainActivity;
.super Landroid/app/Activity;
.source "MainActivity.java"

.method public constructor <init>()V
    .registers 1
    .param p0    # this: Lcom/megademo/testapp/MainActivity;

    invoke-direct {v0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .registers 6
    .param p0    # this: Lcom/megademo/testapp/MainActivity;
    .param p1    # Landroid/os/Bundle;

    invoke-super {v4, v5}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    new-instance v5, Lcom/megademo/testapp/WalletService;
    invoke-direct {v5, v4}, Lcom/megademo/testapp/WalletService;-><init>(Landroid/content/Context;)V
    new-instance v0, Lcom/megademo/testapp/FeatureGate;
    invoke-direct {v0, v4}, Lcom/megademo/testapp/FeatureGate;-><init>(Landroid/content/Context;)V
    new-instance v1, Lcom/megademo/testapp/AgeGate;
    invoke-direct {v1, v4}, Lcom/megademo/testapp/AgeGate;-><init>(Landroid/content/Context;)V
    new-instance v2, Ljava/lang/StringBuilder;
    const-string v3, "coins="
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    invoke-virtual {v5}, Lcom/megademo/testapp/WalletService;->getCoins()I
    move-result v5
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    move-result-object v5
    const-string v2, " premium="
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v5
    new-instance v2, Lcom/megademo/testapp/SubscriptionClient;
    invoke-direct {v2}, Lcom/megademo/testapp/SubscriptionClient;-><init>()V
    invoke-virtual {v2}, Lcom/megademo/testapp/SubscriptionClient;->hasPremium()Z
    move-result v2
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;
    move-result-object v5
    const-string v2, " ads="
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v5
    new-instance v2, Lcom/megademo/testapp/PseudoAdController;
    invoke-direct {v2}, Lcom/megademo/testapp/PseudoAdController;-><init>()V
    invoke-virtual {v2}, Lcom/megademo/testapp/PseudoAdController;->shouldShowAd()Z
    move-result v2
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;
    move-result-object v5
    const-string v2, " age18="
    invoke-virtual {v5, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v5
    const-string v2, "demo-profile"
    invoke-virtual {v1, v2}, Lcom/megademo/testapp/AgeGate;->canOpenMatureSection(Ljava/lang/String;)Z
    move-result v1
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;
    move-result-object v5
    const-string v1, " lab="
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v5
    invoke-static {}, Lcom/megademo/testapp/NativeLabBridge;->isAvailable()Z
    move-result v1
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;
    move-result-object v5
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v5
    const-string v1, "premium_store"
    invoke-virtual {v0, v1}, Lcom/megademo/testapp/FeatureGate;->isFeatureEnabled(Ljava/lang/String;)Z
    move-result v0
    if-eqz v0, +21
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-static {v5}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;
    move-result-object v5
    invoke-direct {v0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    const-string v5, " store=enabled"
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v5
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v5
    nop
    new-instance v0, Landroid/widget/TextView;
    invoke-direct {v0, v4}, Landroid/widget/TextView;-><init>(Landroid/content/Context;)V
    invoke-virtual {v0, v5}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
    invoke-virtual {v4, v0}, Lcom/megademo/testapp/MainActivity;->setContentView(Landroid/view/View;)V
    return-void
.end method

