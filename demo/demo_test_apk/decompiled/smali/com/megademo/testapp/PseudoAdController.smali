.class public final Lcom/megademo/testapp/PseudoAdController;
.super Ljava/lang/Object;
.source "PseudoAdController.java"

.field private adLoaded:Z

.method public constructor <init>()V
    .registers 1
    .param p0    # this: Lcom/megademo/testapp/PseudoAdController;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public createAdView(Landroid/content/Context;)Lcom/megademo/testapp/PseudoAdView;
    .registers 3
    .param p0    # this: Lcom/megademo/testapp/PseudoAdController;
    .param p1    # Landroid/content/Context;

    invoke-virtual {v1}, Lcom/megademo/testapp/PseudoAdController;->shouldShowAd()Z
    move-result v0
    if-nez v0, +4
    const/4 v2, 0
    return-object v2
    invoke-virtual {v1}, Lcom/megademo/testapp/PseudoAdController;->loadAd()V
    new-instance v0, Lcom/megademo/testapp/PseudoAdView;
    invoke-direct {v0, v2}, Lcom/megademo/testapp/PseudoAdView;-><init>(Landroid/content/Context;)V
    return-object v0
.end method

.method public loadAd()V
    .registers 2
    .param p0    # this: Lcom/megademo/testapp/PseudoAdController;

    const/4 v0, 1
    iput-boolean v0, v1, Lcom/megademo/testapp/PseudoAdController;->adLoaded:Z
    return-void
.end method

.method public shouldShowAd()Z
    .registers 3
    .param p0    # this: Lcom/megademo/testapp/PseudoAdController;

    new-instance v0, Lcom/megademo/testapp/PseudoAdController$WalletServiceHolder;
    const/4 v1, 0
    invoke-direct {v0, v1}, Lcom/megademo/testapp/PseudoAdController$WalletServiceHolder;-><init>(Lcom/megademo/testapp/PseudoAdController$WalletServiceHolder;)V
    invoke-virtual {v0}, Lcom/megademo/testapp/PseudoAdController$WalletServiceHolder;->isAdFree()Z
    move-result v0
    xor-int/lit8 v0, v0, 1
    return v0
.end method

.method public showRewardedAd()Z
    .registers 3
    .param p0    # this: Lcom/megademo/testapp/PseudoAdController;

    iget-boolean v0, v2, Lcom/megademo/testapp/PseudoAdController;->adLoaded:Z
    const/4 v1, 0
    if-eqz v0, +13
    invoke-virtual {v2}, Lcom/megademo/testapp/PseudoAdController;->shouldShowAd()Z
    move-result v0
    if-nez v0, +3
    goto +5
    iput-boolean v1, v2, Lcom/megademo/testapp/PseudoAdController;->adLoaded:Z
    const/4 v0, 1
    return v0
    return v1
.end method

