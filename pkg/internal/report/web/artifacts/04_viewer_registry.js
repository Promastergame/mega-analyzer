  // ──────────── Viewers ────────────
  function openViewer(item){
    if(!item) return;
    var kind = pickKind(item);
    var html = '';
    if(kind === 'image')     html = renderImageShell(item);
    else if(kind === 'audio') html = renderAudioShell(item);
    else if(kind === 'video') html = renderVideoShell(item);
    else if(kind === 'font')  html = renderFontShell(item);
    else if(kind === 'code')  html = renderCodeShell(item);
    else if(kind === 'archive') html = renderArchiveShell(item);
    else                       html = renderFallbackShell(item);

    var dlg = openDialog(html, kind);
    if(!dlg) return;
    if(kind === 'image')     bindImage(dlg, item);
    else if(kind === 'audio') bindMedia(dlg, item, 'audio');
    else if(kind === 'video') bindMedia(dlg, item, 'video');
    else if(kind === 'font')  bindFont(dlg, item);
    else if(kind === 'code')  bindCode(dlg, item);
    else if(kind === 'archive') bindArchive(dlg, item);
  }

  function openDetails(item){
    if(!item) return;
    var html = renderDetailsShell(item);
    var dlg = openDialog(html, 'details');
    if(dlg){
      var copyBtn = dlg.querySelector('[data-copy]');
      if(copyBtn){
        copyBtn.addEventListener('click', function(){
          navigator.clipboard.writeText(JSON.stringify(item, null, 2)).then(function(){
            copyBtn.innerHTML = iconCheckSvg;
            setTimeout(function(){ copyBtn.innerHTML = iconCopySvg; }, 1500);
          });
        });
      }
    }
  }

  // What viewer to use. Falls back to a structured "no preview" panel
  // when we have no embedded URL.
  function pickKind(item){
    if(item.type === 'image' && (item.embedded_data_uri || item.external_path)) return 'image';
    if(item.type === 'audio' && (item.embedded_data_uri || item.external_path)) return 'audio';
    if(item.type === 'video' && (item.embedded_data_uri || item.external_path)) return 'video';
    if(item.type === 'font'  && (item.embedded_data_uri || item.external_path)) return 'font';
    if(item.type === 'code') return 'code';
    if(item.type === 'archive') return 'archive';
    return 'fallback';
  }

