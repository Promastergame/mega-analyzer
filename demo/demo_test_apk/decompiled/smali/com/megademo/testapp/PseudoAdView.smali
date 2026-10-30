.class public final Lcom/megademo/testapp/PseudoAdView;
.super Landroid/view/View;
.source "PseudoAdView.java"

.field private final paint:Landroid/graphics/Paint;

.method public constructor <init>(Landroid/content/Context;)V
    .registers 3
    .param p0    # this: Lcom/megademo/testapp/PseudoAdView;
    .param p1    # Landroid/content/Context;

    invoke-direct {v1, v2}, Landroid/view/View;-><init>(Landroid/content/Context;)V
    new-instance v2, Landroid/graphics/Paint;
    const/4 v0, 1
    invoke-direct {v2, v0}, Landroid/graphics/Paint;-><init>(I)V
    iput-object v2, v1, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    return-void
.end method

.method protected onDraw(Landroid/graphics/Canvas;)V
    .registers 14
    .param p0    # this: Lcom/megademo/testapp/PseudoAdView;
    .param p1    # Landroid/graphics/Canvas;

    invoke-super {v12, v13}, Landroid/view/View;->onDraw(Landroid/graphics/Canvas;)V
    invoke-virtual {v12}, Lcom/megademo/testapp/PseudoAdView;->getWidth()I
    move-result v0
    int-to-float v8, v0
    invoke-virtual {v12}, Lcom/megademo/testapp/PseudoAdView;->getHeight()I
    move-result v0
    int-to-float v9, v0
    iget-object v0, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    const/16 v1, 31
    const/16 v2, 45
    const/16 v3, 24
    invoke-static {v3, v1, v2}, Landroid/graphics/Color;->rgb(III)I
    move-result v1
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setColor(I)V
    const/high16 v1, 0x41800000
    const/high16 v2, 0x41800000
    const/high16 v0, 0x41800000
    sub-float v3, v8, v0
    sub-float v4, v9, v0
    const/high16 v5, 0x41a00000
    const/high16 v6, 0x41a00000
    iget-object v7, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    move-object v0, v13
    invoke-virtual/range {v0 .. v7}, Landroid/graphics/Canvas;->drawRoundRect(FFFFFFLandroid/graphics/Paint;)V
    iget-object v0, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    const/16 v1, 193
    const/4 v2, 7
    const/16 v3, 255
    invoke-static {v3, v1, v2}, Landroid/graphics/Color;->rgb(III)I
    move-result v1
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setColor(I)V
    const/high16 v0, 0x42680000
    sub-float v1, v8, v0
    const/high16 v2, 0x41e00000
    iget-object v3, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    invoke-virtual {v13, v1, v0, v2, v3}, Landroid/graphics/Canvas;->drawCircle(FFFLandroid/graphics/Paint;)V
    iget-object v1, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    const/4 v10, -1
    invoke-virtual {v1, v10}, Landroid/graphics/Paint;->setColor(I)V
    iget-object v1, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    const/high16 v2, 0x41b00000
    invoke-virtual {v1, v2}, Landroid/graphics/Paint;->setTextSize(F)V
    iget-object v1, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    const-string v2, "PSEUDO AD"
    const/high16 v3, 0x42080000
    invoke-virtual {v13, v2, v3, v0, v1}, Landroid/graphics/Canvas;->drawText(Ljava/lang/String;FFLandroid/graphics/Paint;)V
    iget-object v0, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    const/high16 v1, 0x41c80000
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setTextSize(F)V
    const/high16 v0, 0x42e00000
    iget-object v1, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    const-string v2, "Купи гараж за 9฿"
    invoke-virtual {v13, v2, v3, v0, v1}, Landroid/graphics/Canvas;->drawText(Ljava/lang/String;FFLandroid/graphics/Paint;)V
    iget-object v0, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    const/high16 v11, 0x41900000
    invoke-virtual {v0, v11}, Landroid/graphics/Paint;->setTextSize(F)V
    const/high16 v0, 0x43100000
    iget-object v1, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    const-string v2, "в Сан-Марино"
    invoke-virtual {v13, v2, v3, v0, v1}, Landroid/graphics/Canvas;->drawText(Ljava/lang/String;FFLandroid/graphics/Paint;)V
    iget-object v0, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    const/16 v1, 175
    const/16 v2, 80
    const/16 v4, 76
    invoke-static {v4, v1, v2}, Landroid/graphics/Color;->rgb(III)I
    move-result v1
    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setColor(I)V
    const/high16 v1, 0x42080000
    const/high16 v0, 0x42940000
    sub-float v2, v9, v0
    sub-float v3, v8, v3
    const/high16 v0, 0x41f00000
    sub-float v4, v9, v0
    const/high16 v5, 0x41400000
    const/high16 v6, 0x41400000
    iget-object v7, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    move-object v0, v13
    invoke-virtual/range {v0 .. v7}, Landroid/graphics/Canvas;->drawRoundRect(FFFFFFLandroid/graphics/Paint;)V
    iget-object v0, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    invoke-virtual {v0, v10}, Landroid/graphics/Paint;->setColor(I)V
    iget-object v0, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    invoke-virtual {v0, v11}, Landroid/graphics/Paint;->setTextSize(F)V
    const/high16 v0, 0x42340000
    sub-float/2addr v9, v0
    iget-object v0, v12, Lcom/megademo/testapp/PseudoAdView;->paint:Landroid/graphics/Paint;
    const-string v1, "ОТКРЫТЬ ПРЕДЛОЖЕНИЕ"
    const/high16 v2, 0x42580000
    invoke-virtual {v13, v1, v2, v9, v0}, Landroid/graphics/Canvas;->drawText(Ljava/lang/String;FFLandroid/graphics/Paint;)V
    return-void
.end method

