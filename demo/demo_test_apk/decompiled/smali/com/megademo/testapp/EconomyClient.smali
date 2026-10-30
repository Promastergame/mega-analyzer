.class public final Lcom/megademo/testapp/EconomyClient;
.super Ljava/lang/Object;
.source "EconomyClient.java"

.field private static final ECONOMY_URL:Ljava/lang/String;

.method public constructor <init>()V
    .registers 1
    .param p0    # this: Lcom/megademo/testapp/EconomyClient;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method private parseCoins(Ljava/lang/String;)I
    .registers 5
    .param p0    # this: Lcom/megademo/testapp/EconomyClient;
    .param p1    # Ljava/lang/String;

    const/4 v0, 0
    if-nez v4, +3
    return v0
    const-string v1, "\"coins\""
    invoke-virtual {v4, v1}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I
    move-result v1
    if-gez v1, +3
    return v0
    const/16 v2, 58
    invoke-virtual {v4, v2, v1}, Ljava/lang/String;->indexOf(II)I
    move-result v1
    if-gez v1, +3
    return v0
    add-int/lit8 v1, v1, 1
    invoke-virtual {v4, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;
    move-result-object v4
    const-string v1, "[^0-9]"
    const-string v2, string@0000
    invoke-virtual {v4, v1, v2}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    move-result-object v4
    invoke-virtual {v4}, Ljava/lang/String;->length()I
    move-result v1
    if-nez v1, +3
    goto +5
    invoke-static {v4}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I
    move-result v0
    return v0
.end method

.method public fetchCoins()I
    .registers 7
    .param p0    # this: Lcom/megademo/testapp/EconomyClient;

    nop
    const/4 v0, 0
    const/4 v1, 0
    :try_start_0
    new-instance v2, Ljava/net/URL;
    const-string v3, "http://127.0.0.1:5555/economy/coins"
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
    :try_start_2
    new-instance v1, Ljava/io/BufferedReader;
    new-instance v3, Ljava/io/InputStreamReader;
    invoke-virtual {v2}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;
    move-result-object v4
    const-string v5, "UTF-8"
    invoke-direct {v3, v4, v5}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/lang/String;)V
    invoke-direct {v1, v3}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    invoke-virtual {v1}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;
    move-result-object v3
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V
    invoke-direct {v6, v3}, Lcom/megademo/testapp/EconomyClient;->parseCoins(Ljava/lang/String;)I
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
    :catch_1_4f
    :catch_2_4f
    move-exception v1
    move-object v1, v2
    goto +9
    :catchall_0
    move-exception v0
    if-eqz v1, +5
    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->disconnect()V
    throw v0
    :catch_0_59
    move-exception v2
    if-eqz v1, +5
    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->disconnect()V
    return v0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0_59
    .catchall {:try_start_0 .. :try_end_0} :catchall_0
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1_4f
    .catchall {:try_start_1 .. :try_end_1} :catchall_1
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2_4f
    .catchall {:try_start_2 .. :try_end_2} :catchall_2
.end method

