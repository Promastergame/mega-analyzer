.method public canAdd(I)Z
    .registers 4
    const/16 v0, 0x64
    move v1, v0
    if-ge p1, v1, :cond_0
    const/4 v0, 0x1
    return v0
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
