.method public find(Ljava/lang/String;)Z
    .registers 4
    const-string v0, "pro"
    invoke-virtual {p1, v0}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I
    move-result v1
    const/4 v2, -0x1
    if-eq v1, v2, :cond_0
    const/4 v0, 0x1
    return v0
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
