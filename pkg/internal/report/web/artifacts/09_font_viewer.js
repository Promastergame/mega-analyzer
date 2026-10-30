  // ──────────── FONT viewer ────────────
  function renderFontShell(item){
    var sub = escapeHtml(item.mime || 'font/*') + ' · ' + humanSize(item.size||0);
    return '<div class="art-shell" data-kind="font">'
      + shellHead(item, sub)
      + '<div class="art-shell-body" style="padding:24px;overflow:auto">'
      +   '<div class="art-font-preview" data-font-preview>'
      +     '<div class="art-font-sizes"></div>'
      +   '</div>'
      + '</div>'
      + shellFoot()
      + '</div>';
  }

  function bindFont(dlg, item){
    var src = item.embedded_data_uri || item.external_path;
    if(!src) return;
    var fontName = 'art-font-' + item.id;
    var style = document.createElement('style');
    style.textContent = '@font-face{font-family:"'+fontName+'";src:url("'+src.replace(/"/g,'\\"')+'");}';
    document.head.appendChild(style);
    var preview = dlg.querySelector('[data-font-preview]');
    if(!preview) return;
    var sizes = [12, 16, 20, 24, 32, 48, 64, 80];
    var sampleText = 'The quick brown fox jumps over the lazy dog 0123456789';
    var html = '';
    sizes.forEach(function(sz){
      html += '<div style="margin-bottom:16px">'
        + '<div style="font-size:11px;color:#7d92a8;margin-bottom:4px">'+sz+'px</div>'
        + '<div style="font-family:\''+fontName+'\',sans-serif;font-size:'+sz+'px;color:#dbe9f6;line-height:1.3;word-break:break-word">'+escapeHtml(sampleText)+'</div>'
        + '</div>';
    });
    html += '<div style="margin-top:24px">'
      + '<div style="font-size:11px;color:#7d92a8;margin-bottom:4px">Glyphs (48px)</div>'
      + '<div style="font-family:\''+fontName+'\',sans-serif;font-size:48px;color:#dbe9f6;line-height:1.4;word-break:break-word">ABCDEFGHIJKLMNOPQRSTUVWXYZ<br>abcdefghijklmnopqrstuvwxyz<br>0123456789 !@#$%^&amp;*()+-=[]{}|;:,./&lt;&gt;?</div>'
      + '</div>';
    preview.innerHTML = html;
    var exp = dlg.querySelector('[data-export]');
    if(exp) exp.addEventListener('click', function(){ requestExport(item); });
    // Cleanup font-face on close.
    dlg.addEventListener('close', function(){ try{document.head.removeChild(style);}catch(e){} });
  }

