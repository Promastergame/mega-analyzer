.method private scheduleRetry()V
    .registers 5
    new-instance v0, Lcom/app/RetryTask;
    invoke-direct {v0, p0}, Lcom/app/RetryTask;-><init>(Lcom/app/Main;)V
    iget-object v1, p0, Lcom/app/Main;->handler:Landroid/os/Handler;
    const-wide/16 v2, 0x1388
    invoke-virtual {v1, v0, v2, v3}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z
    return-void
.end method
