  // ──────────── Tabs + live search (shared filter) ────────────
  var activeTab = 'all';
  var searchQuery = '';

  function cardMatchesSearch(card){
    if(!searchQuery) return true;
    var it = items[card.getAttribute('data-id')];
    if(!it) return card.textContent.toLowerCase().indexOf(searchQuery) !== -1;
    var hay = [it.path, it.type, it.mime, it.sha256];
    if(it.code){
      hay.push(it.code.language);
      (it.code.findings||[]).forEach(function(f){ hay.push(f.title); hay.push(f.category); });
    }
    if(it.native){
      hay.push(it.native.arch); hay.push(it.native.verdict);
      (it.native.suspicious_strings||[]).forEach(function(s){ hay.push(s); });
      (it.native.crack_points||[]).forEach(function(s){ hay.push(s); });
    }
    if(it.forensic){
      hay.push(it.forensic.verdict);
      (it.forensic.reasons||[]).forEach(function(s){ hay.push(s); });
    }
    return hay.join('  ').toLowerCase().indexOf(searchQuery) !== -1;
  }

  function applyFilter(){
    var shown = 0;
    document.querySelectorAll('.art-card').forEach(function(card){
      var okTab = (activeTab === 'all' || card.getAttribute('data-type') === activeTab);
      var okSearch = cardMatchesSearch(card);
      if(okTab && okSearch){ card.style.display = ''; shown++; }
      else { card.style.display = 'none'; }
    });
    var nores = document.getElementById('art-noresults');
    if(nores) nores.hidden = shown !== 0;
    var cnt = document.getElementById('art-search-count');
    if(cnt) cnt.textContent = (searchQuery || activeTab !== 'all') ? (shown + ' shown') : '';
    return shown;
  }

  var tabs = document.querySelectorAll('[data-art-tab]');
  tabs.forEach(function(tab){
    tab.addEventListener('click', function(){
      activeTab = tab.getAttribute('data-art-tab');
      tabs.forEach(function(x){ x.classList.remove('is-active'); });
      tab.classList.add('is-active');
      applyFilter();
    });
  });

  var searchInput = document.getElementById('art-search-input');
  var searchClear = document.getElementById('art-search-clear');
  if(searchInput){
    searchInput.addEventListener('input', function(){
      searchQuery = searchInput.value.trim().toLowerCase();
      if(searchClear) searchClear.hidden = searchQuery === '';
      applyFilter();
    });
  }
  if(searchClear){
    searchClear.addEventListener('click', function(){
      if(searchInput){ searchInput.value = ''; searchInput.focus(); }
      searchQuery = ''; searchClear.hidden = true; applyFilter();
    });
  }

