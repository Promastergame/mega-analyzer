  // ──────────── Export warning modal ────────────
  function requestExport(item){
    if(!item || !allowExport) return;
    var modal = document.getElementById('art-warning-modal');
    if(!modal) return;
    var msg = item.type === 'native'
      ? 'Native-библиотека .so может содержать опасный код. Не запускай и не загружай её вне безопасной среды.'
      : 'Файл извлечён из APK и может быть опасен. Даже если проверка ничего не нашла, открывай его только в безопасной среде.';
    modal.innerHTML = '<div class="art-warning-box">'+
      '<h3>Export warning</h3>'+
      '<p>'+escapeHtml(msg)+'</p>'+
      '<label><input type="checkbox" id="art-warn-ok"> I understand the risk.</label>'+
      '<div class="art-warning-actions">'+
        '<button type="button" data-cancel>Cancel</button>'+
        '<button type="button" data-confirm disabled>Download</button>'+
      '</div></div>';
    modal.hidden = false;
    var ok = modal.querySelector('#art-warn-ok');
    var btn = modal.querySelector('[data-confirm]');
    var cancel = modal.querySelector('[data-cancel]');
    ok.addEventListener('change', function(){ btn.disabled = !ok.checked; });
    cancel.addEventListener('click', function(){ modal.hidden = true; });
    btn.addEventListener('click', function(){
      if(!ok.checked) return;
      var url = item.embedded_data_uri || item.external_path;
      if(!url){ modal.hidden = true; return; }
      var a = document.createElement('a');
      a.href = url; a.download = (item.path || item.id).split('/').pop();
      a.rel = 'noopener'; a.click();
      modal.hidden = true;
    });
    // Also Esc closes the warning.
    modal.addEventListener('keydown', function(e){
      if(e.key === 'Escape'){ modal.hidden = true; }
    });
  }

