.class public final Lcom/megademo/testapp/WalletService;
.super Ljava/lang/Object;
.source "WalletService.java"

.field private static final COINS:Ljava/lang/String;
.field private static final PREFS:Ljava/lang/String;
.field private final prefs:Landroid/content/SharedPreferences;

.method public constructor <init>(Landroid/content/Context;)V
    .registers 4
    .param p0    # this: Lcom/megademo/testapp/WalletService;
    .param p1    # Landroid/content/Context;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V
    const-string v0, "demo_wallet"
    const/4 v1, 0
    invoke-virtual {v3, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v3
    iput-object v3, v2, Lcom/megademo/testapp/WalletService;->prefs:Landroid/content/SharedPreferences;
    return-void
.end method

.method public canAfford(I)Z
    .registers 3
    .param p0    # this: Lcom/megademo/testapp/WalletService;
    .param p1    # I

    invoke-virtual {v1}, Lcom/megademo/testapp/WalletService;->getCoins()I
    move-result v0
    if-lt v0, v2, +4
    const/4 v2, 1
    return v2
    const/4 v2, 0
    return v2
.end method

.method public getCoins()I
    .registers 4
    .param p0    # this: Lcom/megademo/testapp/WalletService;

    iget-object v0, v3, Lcom/megademo/testapp/WalletService;->prefs:Landroid/content/SharedPreferences;
    const-string v1, "coins"
    const/16 v2, 250
    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I
    move-result v0
    return v0
.end method

.method public getGemCost()I
    .registers 2
    .param p0    # this: Lcom/megademo/testapp/WalletService;

    const/16 v0, 50
    return v0
.end method

.method public spendCoins(I)Z
    .registers 4
    .param p0    # this: Lcom/megademo/testapp/WalletService;
    .param p1    # I

    invoke-virtual {v2, v3}, Lcom/megademo/testapp/WalletService;->canAfford(I)Z
    move-result v0
    if-nez v0, +4
    const/4 v3, 0
    return v3
    iget-object v0, v2, Lcom/megademo/testapp/WalletService;->prefs:Landroid/content/SharedPreferences;
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;
    move-result-object v0
    invoke-virtual {v2}, Lcom/megademo/testapp/WalletService;->getCoins()I
    move-result v1
    sub-int/2addr v1, v3
    const-string v3, "coins"
    invoke-interface {v0, v3, v1}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;
    move-result-object v3
    invoke-interface {v3}, Landroid/content/SharedPreferences$Editor;->apply()V
    const/4 v3, 1
    return v3
.end method

