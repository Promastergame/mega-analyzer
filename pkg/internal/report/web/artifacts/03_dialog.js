  // ──────────── Dialog plumbing ────────────
  // Single source of truth: every viewer routes Close button + Esc + backdrop
  // through here so we never have a "dead Close" again.
  var lastScrollY = 0;
  function showCenterToast(text){
    var el = document.createElement('div');
    el.className = 'art-center-toast';
    el.textContent = text;
    document.body.appendChild(el);
    requestAnimationFrame(function(){ el.classList.add('is-visible'); });
    setTimeout(function(){
      el.classList.remove('is-visible');
      setTimeout(function(){ el.remove(); }, 200);
    }, 1100);
  }

  function openDialog(html, kind){
    lastScrollY = window.scrollY;
    var dlg = document.getElementById('artifact-viewer');
    if(!dlg) return null;
    dlg.dataset.kind = kind || '';
    dlg.innerHTML = html;
    if(typeof dlg.showModal === 'function'){
      try { dlg.showModal(); } catch(_){ dlg.setAttribute('open',''); }
    } else {
      dlg.setAttribute('open','');
    }
    document.body.classList.add('art-dialog-open');
    bindDialogChrome(dlg);
    return dlg;
  }

  function closeDialog(dlg){
    if(!dlg) dlg = document.getElementById('artifact-viewer');
    if(!dlg) return;
    if(typeof dlg.close === 'function'){
      try { dlg.close(); } catch(_){ dlg.removeAttribute('open'); }
    } else { dlg.removeAttribute('open'); }
    document.body.classList.remove('art-dialog-open');
    window.scrollTo(0, lastScrollY);
    // Stop any media that was playing.
    dlg.querySelectorAll('audio,video').forEach(function(m){ try { m.pause(); } catch(_){} });
    // Let media bindings release their AudioContext / RAF loops.
    try { dlg.dispatchEvent(new Event('art-media-cleanup')); } catch(_){}
    dlg.innerHTML = '';
  }

  function bindDialogChrome(dlg){
    // Close buttons.
    dlg.querySelectorAll('[data-close]').forEach(function(b){
      b.addEventListener('click', function(){ closeDialog(dlg); });
    });
    // Backdrop click — only when the click hits the dialog itself (not children).
    dlg.addEventListener('click', function(e){
      if(e.target === dlg) closeDialog(dlg);
    });
    // Esc anywhere inside the dialog.
    dlg.addEventListener('keydown', function(e){
      if(e.key === 'Escape'){ e.preventDefault(); closeDialog(dlg); }
    });
    // Native dialog "cancel" event (Esc on <dialog>).
    dlg.addEventListener('cancel', function(e){ e.preventDefault(); closeDialog(dlg); });
  }

