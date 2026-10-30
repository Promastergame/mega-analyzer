.class public final Lcom/megademo/testapp/SubscriptionClient;
.super Ljava/lang/Object;
.source "SubscriptionClient.java"

.field private static final STATUS_URL:Ljava/lang/String;

.method public constructor <init>()V
    .registers 1
    .param p0    # this: Lcom/megademo/testapp/SubscriptionClient;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public hasPremium()Z
    .registers 7
    .param p0    # this: Lcom/megademo/testapp/SubscriptionClient;

    nop
    const/4 v0, 0
    const/4 v1, 0
    :try_start_0
    new-instance v2, Ljava/net/URL;
    const-string v3, "http://127.0.0.1:5555/subscription/status"
    invoke-direct {v2, v3}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v2}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v2
    check-cast v2, Ljava/net/HttpURLConnection;
    :try_end_0
    const/16 v1, 250
    :try_start_1
    invoke-virtual {v2, v1}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V
    invoke-virtual {v2, v1}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V
    const-string v1, "GET"
    invoke-virtual {v2, v1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getResponseCode()I
    move-result v1
    :try_end_1
    const/16 v3, 200
    if-eq v1, v3, +8
    if-eqz v2, +5
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->disconnect()V
    return v0
    const/16 v1, 256
    :try_start_2
    new-array v1, v1, [B
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;
    move-result-object v3
    invoke-virtual {v3, v1}, Ljava/io/InputStream;->read([B)I
    move-result v3
    new-instance v4, Ljava/lang/String;
    invoke-static {v0, v3}, Ljava/lang/Math;->max(II)I
    move-result v3
    const-string v5, "UTF-8"
    invoke-direct {v4, v1, v0, v3, v5}, Ljava/lang/String;-><init>([BIILjava/lang/String;)V
    const-string v1, "\"active\":true"
    invoke-virtual {v4, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v0
    :try_end_2
    if-eqz v2, +5
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->disconnect()V
    return v0
    :catchall_1
    :catchall_2
    move-exception v0
    move-object v1, v2
    goto +5
    :catch_1_51
    :catch_2_51
    move-exception v1
    move-object v1, v2
    goto +9
    :catchall_0
    move-exception v0
    if-eqz v1, +5
    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->disconnect()V
    throw v0
    :catch_0_5b
    move-exception v2
    if-eqz v1, +5
    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->disconnect()V
    return v0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0_5b
    .catchall {:try_start_0 .. :try_end_0} :catchall_0
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1_51
    .catchall {:try_start_1 .. :try_end_1} :catchall_1
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2_51
    .catchall {:try_start_2 .. :try_end_2} :catchall_2
.end method

