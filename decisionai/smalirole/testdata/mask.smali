.method public static check(I)Z
    .registers 3
    const v0, 0xFFFFFFFF
    and-int v1, p0, v0
    if-eqz v1, :cond_0
    const/4 v0, 0x1
    return v0
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
