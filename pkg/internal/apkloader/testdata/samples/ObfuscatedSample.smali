.class public Lcom/example/ObfuscatedSample;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

# Opaque predicate sample
.method public static checkFlag(I)Z
    .registers 3
    const/16 v0, 0xa
    const/16 v1, 0x14
    add-int/2addr v0, v1
    const/16 v1, 0x1e
    if-ne v0, v1, :cond_a
    const/4 v0, 0x1
    return v0
    :cond_a
    const/4 v0, 0x0
    return v0
.end method

# Reflection-based networking sample
.method public static download()V
    .registers 5
    const-string v0, "java.net.URL"
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v0
    const-string v1, "openConnection"
    const/4 v2, 0x0
    new-array v2, v2, [Ljava/lang/Class;
    invoke-virtual {v0, v1, v2}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    move-result-object v0
    return-void
.end method
