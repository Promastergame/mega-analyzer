.class public final Lcom/megademo/testapp/AgeVerificationClient;
.super Ljava/lang/Object;
.source "AgeVerificationClient.java"

.field private static final AGE_URL:Ljava/lang/String;

.method public constructor <init>()V
    .registers 1
    .param p0    # this: Lcom/megademo/testapp/AgeVerificationClient;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public isAdult(Ljava/lang/String;)Z
    .registers 7
    .param p0    # this: Lcom/megademo/testapp/AgeVerificationClient;
    .param p1    # Ljava/lang/String;

    nop
    const/4 v0, 0
    const/4 v1, 0
    :try_start_0
    new-instance v2, Ljava/net/URL;
    new-instance v3, Ljava/lang/StringBuilder;
    const-string v4, "http://127.0.0.1:5555/age/verify?profile="
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v6
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v6
    invoke-direct {v2, v6}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v2}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    move-result-object v6
    check-cast v6, Ljava/net/HttpURLConnection;
    :try_end_0
    const/16 v1, 250
    :try_start_1
    invoke-virtual {v6, v1}, Ljava/net/HttpURLConnection;->setConnectTimeout(I)V
    invoke-virtual {v6, v1}, Ljava/net/HttpURLConnection;->setReadTimeout(I)V
    const-string v1, "GET"
    invoke-virtual {v6, v1}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getResponseCode()I
    move-result v1
    :try_end_1
    const/16 v2, 200
    if-eq v1, v2, +8
    if-eqz v6, +5
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->disconnect()V
    return v0
    :try_start_2
    new-instance v1, Ljava/io/BufferedReader;
    new-instance v2, Ljava/io/InputStreamReader;
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;
    move-result-object v3
    const-string v4, "UTF-8"
    invoke-direct {v2, v3, v4}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/lang/String;)V
    invoke-direct {v1, v2}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    invoke-virtual {v1}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;
    move-result-object v2
    invoke-virtual {v1}, Ljava/io/BufferedReader;->close()V
    if-eqz v2, +11
    const-string v1, "\"adult\":true"
    invoke-virtual {v2, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z
    move-result v1
    :try_end_2
    if-eqz v1, +3
    const/4 v0, 1
    if-eqz v6, +5
    invoke-virtual {v6}, Ljava/net/HttpURLConnection;->disconnect()V
    return v0
    :catchall_1
    :catchall_2
    move-exception v0
    move-object v1, v6
    goto +5
    :catch_1_63
    :catch_2_63
    move-exception v1
    move-object v1, v6
    goto +9
    :catchall_0
    move-exception v0
    if-eqz v1, +5
    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->disconnect()V
    throw v0
    :catch_0_6d
    move-exception v6
    if-eqz v1, +5
    invoke-virtual {v1}, Ljava/net/HttpURLConnection;->disconnect()V
    return v0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0_6d
    .catchall {:try_start_0 .. :try_end_0} :catchall_0
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1_63
    .catchall {:try_start_1 .. :try_end_1} :catchall_1
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2_63
    .catchall {:try_start_2 .. :try_end_2} :catchall_2
.end method

