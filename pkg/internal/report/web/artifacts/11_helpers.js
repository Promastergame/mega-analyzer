  // ──────────── Helpers ────────────
  function escapeHtml(s){
    return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
    });
  }
  function baseName(p){ p = String(p||''); var i = p.lastIndexOf('/'); return i>=0 ? p.substring(i+1) : p; }
  // atob gives bytes; decode them as UTF-8. The old escape()/decodeURIComponent
  // pair threw URIError on some byte sequences and lost the whole source.
  function decodeBase64Utf8(b64){
    var bin = atob(b64);
    if(typeof TextDecoder === 'undefined') return bin;
    var bytes = new Uint8Array(bin.length);
    for(var i=0;i<bin.length;i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder('utf-8').decode(bytes);
  }
  function humanSize(n){
    n = Number(n)||0;
    if(n < 1024) return n + 'B';
    if(n < 1048576) return (n/1024).toFixed(1) + 'KB';
    if(n < 1073741824) return (n/1048576).toFixed(1) + 'MB';
    return (n/1073741824).toFixed(2) + 'GB';
  }
