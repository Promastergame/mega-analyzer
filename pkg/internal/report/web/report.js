
(() => {
  'use strict';

  // ═══════════════════════════════════════════════════════════════════════════
  // Configuration
  // ═══════════════════════════════════════════════════════════════════════════

  const CONFIG = {
    enableFilters: __ENABLE_FILTERS__,
    enableHighlight: __ENABLE_HIGHLIGHT__
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // State
  // ═══════════════════════════════════════════════════════════════════════════

  const state = {
    sortColumn: null,
    sortDirection: 'asc',
    theme: localStorage.getItem('theme') || 'dark',
    hintsVisible: false
  };

  const sectionDefaults = {
    overview: true,
    stats: true,
    actions: true,
    comparative: true,
    risk: true,
    heatmap: true,
    'signal-chain': true,
    detections: true,
    'pattern-tree': true,
    hotspots: true,
    matches: true,
    piracy: true,
    'confidence-chart': true,
    recommendations: true
  };

  const sectionVisibility = Object.assign(
    {},
    sectionDefaults,
    safeJson(localStorage.getItem('sectionVisibility')) || {}
  );

  // ═══════════════════════════════════════════════════════════════════════════
  // DOM Helpers
  // ═══════════════════════════════════════════════════════════════════════════

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));

  const el = {
    sidebar: $('#sidebar'),
    sidebarToggle: $('#sidebar-toggle'),
    themeToggle: $('#theme-toggle'),
    settingsToggle: $('#settings-toggle'),
    settingsPanel: $('#settings-panel'),
    main: $('main'),
    modal: $('#modal'),
    modalBody: $('#modal-body'),
    modalClose: $('#modal-close'),
    exportModal: $('#export-modal'),
    matchesBody: $('#matches-body'),
    counter: $('#match-counter'),
    filterSearch: $('#filter-search'),
    filterGroup: $('#filter-group'),
    filterCategory: $('#filter-category'),
    filterSeverity: $('#filter-severity'),
    filterContext: $('#filter-context'),
    filterReset: $('#filter-reset'),
    tooltip: $('#tooltip'),
    feedbackShowHidden: $('#filter-show-hidden'),
    feedbackDashboardBtn: $('#feedback-dashboard-btn'),
    feedbackModal: $('#feedback-modal'),
    feedbackRelevantCount: $('#feedback-relevant-count'),
    feedbackDecentCount: $('#feedback-decent-count'),
    feedbackNoiseCount: $('#feedback-noise-count'),
    feedbackDownloadBtn: $('#feedback-download-btn'),
    toastContainer: $('#toast-container')
  };

  const rows = $$('#matches-body tr');

  // ML Feedback State
  const apkPackage = (document.title.split(' - ').slice(1).join(' - ') || 'default-apk').trim();
  const feedbackStorageKey = 'feedback_store:' + apkPackage;
  const feedbackStore = safeJson(localStorage.getItem(feedbackStorageKey)) || {};

  // ═══════════════════════════════════════════════════════════════════════════
  // Utilities
  // ═══════════════════════════════════════════════════════════════════════════

  function safeJson(value) {
    if (!value) return null;
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }

  function debounce(fn, delay) {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => fn(...args), delay);
    };
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function selectText(el) {
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    if (!sel) return;
    sel.removeAllRanges();
    sel.addRange(range);
  }

  function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function csvEscape(val) {
    if (!val) return '';
    val = String(val);
    if (val.includes(',') || val.includes('"') || val.includes('\n')) {
      return '"' + val.replace(/"/g, '""') + '"';
    }
    return val;
  }

  function xmlEscape(val) {
    if (!val) return '';
    return String(val)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Theme
  // ═══════════════════════════════════════════════════════════════════════════

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    state.theme = theme;
    localStorage.setItem('theme', theme);
    if (el.themeToggle) {
      const iconId = theme === 'dark' ? 'sun' : 'moon';
      const label = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
      const use = el.themeToggle.querySelector('use');
      if (use) use.setAttribute('href', '#icon-' + iconId);
      const svg = el.themeToggle.querySelector('svg');
      if (svg) svg.setAttribute('class', 'icon icon-' + iconId);
      const labelEl = el.themeToggle.querySelector('.btn-label');
      if (labelEl) labelEl.textContent = label;
    }
  }

  function toggleTheme() {
    applyTheme(state.theme === 'dark' ? 'light' : 'dark');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Section Visibility
  // ═══════════════════════════════════════════════════════════════════════════

  function applySectionVisibility() {
    Object.keys(sectionDefaults).forEach((id) => {
      const visible = sectionVisibility[id] !== false;
      const section = document.getElementById(id);
      const navItem = document.querySelector('.nav-item[data-section="' + id + '"]');
      if (section) section.hidden = !visible;
      if (navItem) navItem.hidden = !visible;
      const checkbox = document.querySelector('.settings-item input[data-section="' + id + '"]');
      if (checkbox) checkbox.checked = visible;
    });
  }

  function persistSectionVisibility() {
    localStorage.setItem('sectionVisibility', JSON.stringify(sectionVisibility));
  }

  function bindSectionToggles() {
    $$('#settings-panel input[data-section]').forEach(input => {
      const id = input.dataset.section;
      input.addEventListener('change', () => {
        sectionVisibility[id] = input.checked;
        persistSectionVisibility();
        applySectionVisibility();
      });
    });
  }

  function syncSettingsPanel() {
    $$('#settings-panel .settings-item').forEach(item => {
      const id = item.querySelector('input')?.dataset.section;
      if (!id) return;
      const exists = document.getElementById(id);
      item.hidden = !exists;
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Sidebar
  // ═══════════════════════════════════════════════════════════════════════════

  function toggleSidebar() {
    el.sidebar?.classList.toggle('open');
    el.main?.classList.toggle('expanded');
  }

  function updateActiveNav() {
    const sections = $$('.section, .hero');
    const navItems = $$('.nav-item');

    let currentSection = '';
    const scrollY = window.scrollY + 100;

    sections.forEach(section => {
      if (section.hidden) return;
      if (section.offsetTop <= scrollY) {
        currentSection = section.id;
      }
    });

    navItems.forEach(item => {
      item.classList.toggle('active', item.dataset.section === currentSection);
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Filtering (enhanced with context filter #6)
  // ═══════════════════════════════════════════════════════════════════════════

  function applyFilters() {
    if (!CONFIG.enableFilters) return;

    const search = (el.filterSearch?.value || '').toLowerCase().trim();
    const group = (el.filterGroup?.value || '').toLowerCase();
    const category = (el.filterCategory?.value || '').toLowerCase();
    const severity = el.filterSeverity?.value || '';
    const context = (el.filterContext?.value || '').toLowerCase();

    let visible = 0;

    rows.forEach(row => {
      const d = row.dataset;
      const matchSearch = !search ||
        (d.pattern || '').includes(search) ||
        (d.file || '').includes(search) ||
        (d.category || '').includes(search);
      const matchGroup = !group || d.group === group;
      const matchCategory = !category || d.category === category;
      const matchSeverity = !severity ||
        (severity === 'critical' && d.critical === '1') ||
        (severity === 'normal' && d.critical === '0');
      const matchContext = !context || d.context === context;

      const isHiddenNoise = row.classList.contains('row-noise') && !document.body.classList.contains('show-noise-matches');
      const show = matchSearch && matchGroup && matchCategory && matchSeverity && matchContext && !isHiddenNoise;
      row.style.display = show ? '' : 'none';
      if (show) visible++;
    });

    updateCounter(visible);
  }

  function resetFilters() {
    if (el.filterSearch) el.filterSearch.value = '';
    if (el.filterGroup) el.filterGroup.value = '';
    if (el.filterCategory) el.filterCategory.value = '';
    if (el.filterSeverity) el.filterSeverity.value = '';
    if (el.filterContext) el.filterContext.value = '';
    applyFilters();
  }

  function updateCounter(visible) {
    if (el.counter) {
      el.counter.textContent = visible + ' / ' + rows.length + ' matches';
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Sorting
  // ═══════════════════════════════════════════════════════════════════════════

  function sortTable(column) {
    if (state.sortColumn === column) {
      state.sortDirection = state.sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      state.sortColumn = column;
      state.sortDirection = 'asc';
    }

    const sortedRows = [...rows].sort((a, b) => {
      let aVal, bVal;

      if (column === 'line') {
        aVal = parseInt(a.dataset.line) || 0;
        bVal = parseInt(b.dataset.line) || 0;
      } else {
        aVal = a.dataset[column] || '';
        bVal = b.dataset[column] || '';
      }

      if (aVal < bVal) return state.sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return state.sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    sortedRows.forEach(row => el.matchesBody?.appendChild(row));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Code Context Modal
  // ═══════════════════════════════════════════════════════════════════════════

  function openModal(matchId) {
    const template = $('[id="ctx-' + matchId + '"]');
    if (!template || !el.modal || !el.modalBody) return;

    el.modalBody.innerHTML = template.innerHTML;
    el.modal.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';

    const codeBlock = el.modalBody.querySelector('.code-block');
    if (codeBlock) {
      codeBlock.setAttribute('tabindex', '0');
      codeBlock.focus();
    }

    if (CONFIG.enableHighlight) {
      highlightCode();
    }
  }

  function closeModal() {
    if (!el.modal) return;
    el.modal.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    if (el.modalBody) el.modalBody.innerHTML = '';
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Export Modal (#10)
  // ═══════════════════════════════════════════════════════════════════════════

  window.openExportModal = () => {
    if (el.exportModal) {
      el.exportModal.setAttribute('aria-hidden', 'false');
    }
  };

  window.closeExportModal = () => {
    if (el.exportModal) {
      el.exportModal.setAttribute('aria-hidden', 'true');
    }
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // Syntax Highlighting
  // ═══════════════════════════════════════════════════════════════════════════

  function highlightCode() {
    const patterns = [
      {
        regex: /\b(invoke-[a-z0-9\/-]+|if-[a-z0-9-]+|const(?:\/[a-z0-9]+)?|move(?:-[a-z0-9]+)?|return(?:-[a-z0-9]+)?|[si]get(?:-[a-z0-9]+)?|[si]put(?:-[a-z0-9]+)?|goto(?:\/[0-9]+)?|new-instance|check-cast|throw|monitor-[a-z]+)\b/gi,
        class: 'kw'
      },
      { regex: /"[^"]*"/g, class: 'str' },
      { regex: /\b0x[0-9a-f]+\b/gi, class: 'num' },
      { regex: /#.*/g, class: 'cmt' }
    ];

    $$('.code-line-content').forEach(el => {
      let html = escapeHtml(el.textContent || '');
      patterns.forEach(p => {
        html = html.replace(p.regex, '<span class="' + p.class + '">$&</span>');
      });
      el.innerHTML = html;
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Tooltip System (#7)
  // ═══════════════════════════════════════════════════════════════════════════

  function showTooltip(e) {
    const target = e.target.closest('[data-explanation]');
    if (!target || !el.tooltip) return;

    const text = target.dataset.explanation;
    if (!text || text === 'No additional information available') return;

    el.tooltip.textContent = text;
    el.tooltip.hidden = false;

    const rect = target.getBoundingClientRect();
    const tipRect = el.tooltip.getBoundingClientRect();

    let left = rect.left + (rect.width / 2) - (tipRect.width / 2);
    let top = rect.bottom + 8;

    // Keep within viewport
    if (left < 8) left = 8;
    if (left + tipRect.width > window.innerWidth - 8) {
      left = window.innerWidth - tipRect.width - 8;
    }
    if (top + tipRect.height > window.innerHeight - 8) {
      top = rect.top - tipRect.height - 8;
    }

    el.tooltip.style.left = left + 'px';
    el.tooltip.style.top = top + 'px';
  }

  function hideTooltip() {
    if (el.tooltip) el.tooltip.hidden = true;
  }

  window.toggleAllTooltips = () => {
    state.hintsVisible = !state.hintsVisible;
    $$('[data-explanation]').forEach(el => {
      if (state.hintsVisible) {
        el.classList.add('has-tooltip');
      } else {
        el.classList.remove('has-tooltip');
      }
    });
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // Heatmap Click Handler (#5)
  // ═══════════════════════════════════════════════════════════════════════════

  function initHeatmapClicks() {
    $$('.hm-cell').forEach(cell => {
      cell.addEventListener('click', () => {
        const file = cell.dataset.file;
        if (!file || !el.filterSearch) return;

        // Set search filter to this file
        el.filterSearch.value = file;
        applyFilters();

        // Scroll to matches section
        const matchesSection = document.getElementById('matches');
        if (matchesSection) {
          matchesSection.scrollIntoView({ behavior: 'smooth' });
        }
      });
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Global Functions
  // ═══════════════════════════════════════════════════════════════════════════

  window.expandAll = () => {
    $$('details').forEach(d => d.open = true);
  };

  window.collapseAll = () => {
    $$('details').forEach(d => d.open = false);
  };

  // ── Export JSON (#10) ──
  window.exportJSON = () => {
    const data = {
      meta: {
        exported: new Date().toISOString(),
        format: 'json',
        generator: 'APK Analyzer HTML Report'
      },
      matches: rows.map(r => ({
        category: r.dataset.category,
        file: r.dataset.file,
        pattern: r.dataset.pattern,
        line: parseInt(r.dataset.line),
        critical: r.dataset.critical === '1',
        context: r.dataset.context || 'unknown',
        group: r.dataset.group
      }))
    };

    downloadFile(
      JSON.stringify(data, null, 2),
      'analysis-export.json',
      'application/json'
    );
    closeExportModal();
  };

  // ── Export CSV (#10) ──
  window.exportCSV = () => {
    const headers = ['Category', 'Pattern', 'File', 'Line', 'Critical', 'Context', 'Group'];
    const csvRows = [headers.join(',')];

    rows.forEach(r => {
      const d = r.dataset;
      csvRows.push([
        csvEscape(d.category),
        csvEscape(d.pattern),
        csvEscape(d.file),
        d.line,
        d.critical === '1' ? 'YES' : 'NO',
        csvEscape(d.context || 'unknown'),
        csvEscape(d.group)
      ].join(','));
    });

    downloadFile(
      csvRows.join('\n'),
      'analysis-export.csv',
      'text/csv'
    );
    closeExportModal();
  };

  // ── Export XML (#10) ──
  window.exportXML = () => {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<analysis>\n';
    xml += '  <meta>\n';
    xml += '    <exported>' + new Date().toISOString() + '</exported>\n';
    xml += '    <generator>APK Analyzer HTML Report</generator>\n';
    xml += '  </meta>\n';
    xml += '  <matches>\n';

    rows.forEach(r => {
      const d = r.dataset;
      xml += '    <match>\n';
      xml += '      <category>' + xmlEscape(d.category) + '</category>\n';
      xml += '      <pattern>' + xmlEscape(d.pattern) + '</pattern>\n';
      xml += '      <file>' + xmlEscape(d.file) + '</file>\n';
      xml += '      <line>' + d.line + '</line>\n';
      xml += '      <critical>' + (d.critical === '1') + '</critical>\n';
      xml += '      <context>' + xmlEscape(d.context || 'unknown') + '</context>\n';
      xml += '      <group>' + xmlEscape(d.group) + '</group>\n';
      xml += '    </match>\n';
    });

    xml += '  </matches>\n';
    xml += '</analysis>';

    downloadFile(
      xml,
      'analysis-export.xml',
      'application/xml'
    );
    closeExportModal();
  };

  // ── Copy Stats ──
  window.copyStats = () => {
    const stats = $$('.stat-card').map(c => {
      const label = c.querySelector('.stat-label')?.textContent || '';
      const value = c.querySelector('.stat-value')?.textContent || '';
      return label + ': ' + value;
    }).join('\n');

    navigator.clipboard.writeText(stats).then(() => {
      alert('Stats copied to clipboard!');
    });
  };

  // ── Copy Code from Modal ──
  window.copyCode = (matchId) => {
    const code = $$('#modal-body .code-line-content')
      .map(el => el.textContent)
      .join('\n');

    navigator.clipboard.writeText(code).then(() => {
      const btn = $('#modal-body .code-btn');
      if (btn) {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = orig, 1500);
      }
    });
  };

  // ── ML Feedback Dashboard & Actions ──
  function closeFeedbackModal() {
    if (el.feedbackModal) {
      el.feedbackModal.setAttribute('aria-hidden', 'true');
      el.feedbackModal.style.display = 'none';
    }
  }

  function openFeedbackModal() {
    if (!el.feedbackModal) return;
    let relevant = 0, decent = 0, noise = 0;
    Object.values(feedbackStore).forEach(v => {
      if (v === 'relevant') relevant++;
      else if (v === 'decent') decent++;
      else if (v === 'noise') noise++;
    });
    if (el.feedbackRelevantCount) el.feedbackRelevantCount.textContent = relevant;
    if (el.feedbackDecentCount) el.feedbackDecentCount.textContent = decent;
    if (el.feedbackNoiseCount) el.feedbackNoiseCount.textContent = noise;

    el.feedbackModal.setAttribute('aria-hidden', 'false');
    el.feedbackModal.style.display = 'flex';
  }

  function showToast(message, type, onUndo) {
    if (!el.toastContainer) return;

    const toast = document.createElement('div');
    toast.className = 'toast';
    
    // Choose sleek color-coded icon
    let iconHtml = '';
    if (type === 'relevant') {
      iconHtml = '<span class="toast-icon relevant"><svg class="icon icon-check-circle-feedback" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><use href="#icon-check-circle-feedback"></use></svg></span>';
    } else if (type === 'decent') {
      iconHtml = '<span class="toast-icon decent" style="color: var(--info);"><svg class="icon icon-neutral-circle-feedback" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><use href="#icon-neutral-circle-feedback"></use></svg></span>';
    } else {
      iconHtml = '<span class="toast-icon noise"><svg class="icon icon-x-circle-feedback" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><use href="#icon-x-circle-feedback"></use></svg></span>';
    }

    toast.innerHTML = iconHtml +
      '<div class="toast-message">' + escapeHtml(message) + '</div>' +
      (onUndo ? '<a class="toast-undo">Undo</a>' : '');

    el.toastContainer.appendChild(toast);

    // Slide up animation
    setTimeout(() => toast.classList.add('show'), 50);

    let autoClose = setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, 4500);

    if (onUndo) {
      toast.querySelector('.toast-undo')?.addEventListener('click', (e) => {
        e.preventDefault();
        clearTimeout(autoClose);
        onUndo();
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
      });
    }
  }

  function downloadFeedbackJson() {
    const entries = [];
    const seenPatterns = new Set();

    rows.forEach(row => {
      const matchId = row.getAttribute('data-id');
      const feedbackVal = feedbackStore[matchId];
      const noteVal = feedbackStore[matchId + '_note'] || '';
      if (feedbackVal || noteVal) {
        const rawPattern = row.getAttribute('data-pattern-raw') || row.getAttribute('data-pattern');
        if (rawPattern && !seenPatterns.has(rawPattern)) {
          seenPatterns.add(rawPattern);
          let outcome = 'neutral';
          if (feedbackVal === 'relevant') outcome = 'true_positive';
          else if (feedbackVal === 'noise') outcome = 'false_positive';
          const entry = {
            pattern_id: rawPattern,
            outcome: outcome
          };
          if (noteVal) {
            entry.note = noteVal;
          }
          entries.push(entry);
        }
      }
    });

    if (entries.length === 0) {
      showToast('No feedback recorded to download yet!', 'noise');
      return;
    }

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(entries, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", "feedback.json");
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    showToast('Feedback JSON downloaded successfully!', 'relevant');
  }

  function applyFeedbackOnLoad() {
    rows.forEach(row => {
      const matchId = row.getAttribute('data-id');
      const feedbackVal = feedbackStore[matchId];
      if (feedbackVal === 'relevant') {
        row.classList.add('row-relevant');
        const btnRel = row.querySelector('.btn-relevant');
        if (btnRel) btnRel.classList.add('active');
      } else if (feedbackVal === 'decent') {
        row.classList.add('row-decent');
        const btnDecent = row.querySelector('.btn-decent');
        if (btnDecent) btnDecent.classList.add('active');
      } else if (feedbackVal === 'noise') {
        row.classList.add('row-noise');
        const btnNoise = row.querySelector('.btn-noise');
        if (btnNoise) btnNoise.classList.add('active');
      }

      // Check notes
      const noteVal = feedbackStore[matchId + '_note'];
      if (noteVal) {
        const noteContainer = row.querySelector('.row-note-container');
        const noteInput = row.querySelector('.row-note-input');
        const btnNote = row.querySelector('.btn-note');
        if (noteContainer) noteContainer.hidden = false;
        if (noteInput) noteInput.value = noteVal;
        if (btnNote) btnNote.classList.add('active');
      }
    });

    const showHidden = localStorage.getItem('feedback_show_hidden:' + apkPackage) === 'true';
    if (el.feedbackShowHidden) {
      el.feedbackShowHidden.checked = showHidden;
      if (showHidden) {
        document.body.classList.add('show-noise-matches');
      } else {
        document.body.classList.remove('show-noise-matches');
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Initialization
  // ═══════════════════════════════════════════════════════════════════════════

  function init() {
    // ── Theme ──
    applyTheme(state.theme);
    el.themeToggle?.addEventListener('click', toggleTheme);

    // ── Settings Panel ──
    el.settingsToggle?.addEventListener('click', () => {
      if (!el.settingsPanel) return;
      el.settingsPanel.hidden = !el.settingsPanel.hidden;
    });

    // ── Sidebar ──
    el.sidebarToggle?.addEventListener('click', toggleSidebar);
    window.addEventListener('scroll', debounce(updateActiveNav, 100));

    // Smooth scroll for nav + auto-close on mobile
    $$('.nav-item').forEach(item => {
      item.addEventListener('click', () => {
        if (window.innerWidth <= 1024) toggleSidebar();
      });
    });

    // ── Filters ──
    if (CONFIG.enableFilters) {
      el.filterSearch?.addEventListener('input', debounce(applyFilters, 200));
      el.filterGroup?.addEventListener('change', applyFilters);
      el.filterCategory?.addEventListener('change', applyFilters);
      el.filterSeverity?.addEventListener('change', applyFilters);
      el.filterContext?.addEventListener('change', applyFilters);
      el.filterReset?.addEventListener('click', resetFilters);
      applyFilters();
    } else {
      updateCounter(rows.length);
    }

    // ── Sorting ──
    $$('.th-sortable').forEach(th => {
      th.addEventListener('click', () => sortTable(th.dataset.sort));
    });

    // ── Code Context Modal ──
    $$('.btn-context').forEach(btn => {
      btn.addEventListener('click', () => openModal(btn.dataset.id));
    });

    el.modalClose?.addEventListener('click', closeModal);
    el.modal?.querySelector('.modal-backdrop')?.addEventListener('click', closeModal);

    // ── Keyboard shortcuts ──
    document.addEventListener('keydown', (e) => {
      // Ctrl+A in modal selects code block
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a') {
        const modalOpen = el.modal?.getAttribute('aria-hidden') === 'false';
        if (modalOpen) {
          const codeBlock = el.modalBody?.querySelector('.code-block');
          if (codeBlock) {
            e.preventDefault();
            selectText(codeBlock);
            return;
          }
        }
      }
    });

    // ── Section Visibility ──
    syncSettingsPanel();
    bindSectionToggles();
    applySectionVisibility();

    // ── Initial Nav State ──
    updateActiveNav();

    // ── ML Feedback Event Handlers ──
    applyFeedbackOnLoad();

    $$('.btn-feedback').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const matchId = btn.getAttribute('data-id');
        const row = btn.closest('.match-row');
        if (!row) return;

        // If it's the note button, toggle comment input visibility
        if (btn.classList.contains('btn-note')) {
          const container = row.querySelector('.row-note-container');
          const input = row.querySelector('.row-note-input');
          if (container && input) {
            container.hidden = !container.hidden;
            if (!container.hidden) {
              input.focus();
              btn.classList.add('active');
            } else if (!input.value.trim()) {
              btn.classList.remove('active');
            }
          }
          return;
        }

        const isRelevantBtn = btn.classList.contains('btn-relevant');
        const isDecentBtn = btn.classList.contains('btn-decent');

        const currentStatus = feedbackStore[matchId];
        let newStatus = null;

        if (isRelevantBtn) {
          newStatus = currentStatus === 'relevant' ? null : 'relevant';
        } else if (isDecentBtn) {
          newStatus = currentStatus === 'decent' ? null : 'decent';
        } else {
          newStatus = currentStatus === 'noise' ? null : 'noise';
        }

        const previousStatus = currentStatus;

        function updateFeedbackState(targetId, targetStatus) {
          const targetRow = $('.match-row[data-id="' + targetId + '"]');
          const relBtn = targetRow?.querySelector('.btn-relevant');
          const decentBtn = targetRow?.querySelector('.btn-decent');
          const noiseBtn = targetRow?.querySelector('.btn-noise');

          // Reset classes
          targetRow?.classList.remove('row-relevant', 'row-decent', 'row-noise');
          relBtn?.classList.remove('active');
          decentBtn?.classList.remove('active');
          noiseBtn?.classList.remove('active');

          if (targetStatus === 'relevant') {
            feedbackStore[targetId] = 'relevant';
            targetRow?.classList.add('row-relevant');
            relBtn?.classList.add('active');
          } else if (targetStatus === 'decent') {
            feedbackStore[targetId] = 'decent';
            targetRow?.classList.add('row-decent');
            decentBtn?.classList.add('active');
          } else if (targetStatus === 'noise') {
            feedbackStore[targetId] = 'noise';
            targetRow?.classList.add('row-noise');
            noiseBtn?.classList.add('active');
          } else {
            delete feedbackStore[targetId];
          }

          localStorage.setItem(feedbackStorageKey, JSON.stringify(feedbackStore));
          
          if (CONFIG.enableFilters) {
            applyFilters();
          }
          if (typeof updateConsoleCommands === 'function') {
            updateConsoleCommands();
          }
        }

        updateFeedbackState(matchId, newStatus);

        if (newStatus === 'relevant') {
          showToast('Match marked as Relevant!', 'relevant', () => {
            updateFeedbackState(matchId, previousStatus);
          });
        } else if (newStatus === 'decent') {
          showToast('Match marked as Decent!', 'decent', () => {
            updateFeedbackState(matchId, previousStatus);
          });
        } else if (newStatus === 'noise') {
          showToast('Match marked as Noise!', 'noise', () => {
            updateFeedbackState(matchId, previousStatus);
          });
        } else {
          showToast('Feedback cleared.', 'relevant');
        }
      });
    });

    // Note Input Handlers
    $$('.row-note-input').forEach(input => {
      const matchId = input.getAttribute('data-id');
      const row = input.closest('.match-row');
      const btnNote = row?.querySelector('.btn-note');

      const saveNote = () => {
        const val = input.value.trim();
        if (val) {
          feedbackStore[matchId + '_note'] = val;
          btnNote?.classList.add('active');
        } else {
          delete feedbackStore[matchId + '_note'];
          // Only remove active style if the container is also hidden
          const container = row?.querySelector('.row-note-container');
          if (container && container.hidden) {
            btnNote?.classList.remove('active');
          }
        }
        localStorage.setItem(feedbackStorageKey, JSON.stringify(feedbackStore));
        if (typeof updateConsoleCommands === 'function') {
          updateConsoleCommands();
        }
      };

      input.addEventListener('input', saveNote);
      input.addEventListener('change', saveNote);
    });

    el.feedbackShowHidden?.addEventListener('change', (e) => {
      const checked = e.target.checked;
      localStorage.setItem('feedback_show_hidden:' + apkPackage, checked);
      if (checked) {
        document.body.classList.add('show-noise-matches');
      } else {
        document.body.classList.remove('show-noise-matches');
      }
      if (CONFIG.enableFilters) {
        applyFilters();
      }
    });

    el.feedbackDashboardBtn?.addEventListener('click', openFeedbackModal);
    el.feedbackDownloadBtn?.addEventListener('click', downloadFeedbackJson);

    // Expose feedback modal actions to global scope for inline onclicks
    window.closeFeedbackModal = closeFeedbackModal;
    window.openFeedbackModal = openFeedbackModal;

    function copyCliCommand(flag, pattern) {
      const cmd = './analyzer.exe ' + flag + ' "' + pattern + '"';
      navigator.clipboard.writeText(cmd).then(() => {
        showToast('Copied CLI command to clipboard!', 'relevant');
      }).catch(err => {
        console.error('Failed to copy: ', err);
      });
    }
    window.copyCliCommand = copyCliCommand;

    function updateConsoleCommands() {
      const consoleOutput = $('#console-output');
      if (!consoleOutput) return;

      const commands = [];
      const processedPatterns = new Set();

      rows.forEach(row => {
        const matchId = row.getAttribute('data-id');
        const pattern = row.getAttribute('data-pattern-raw') || row.getAttribute('data-pattern');
        const status = feedbackStore[matchId];
        const note = feedbackStore[matchId + '_note'] || '';

        if ((status || note) && pattern) {
          const uniqueKey = pattern + '||' + status + '||' + note;
          if (processedPatterns.has(uniqueKey)) return;
          processedPatterns.add(uniqueKey);

          let cmd = '';
          if (status === 'relevant') {
            cmd = './analyzer.exe --mark-relevant "' + pattern + '"';
          } else if (status === 'noise') {
            cmd = './analyzer.exe --mark-noise "' + pattern + '"';
          } else {
            cmd = '# Pattern: "' + pattern + '"';
          }

          if (note) {
            cmd += ' # Note: ' + note;
          }

          if (cmd) {
            commands.push(cmd);
          }
        }
      });

      const copyBtn = $('#copy-console-btn');
      const downloadBtn = $('#download-console-btn');

      if (commands.length === 0) {
        consoleOutput.textContent = 'No items marked yet. Click checkmark (relevant) or cross (noise), or add triage notes in the action column above to dynamically generate CLI commands here.';
        consoleOutput.style.color = 'var(--text-secondary)';
        if (copyBtn) copyBtn.disabled = true;
        if (downloadBtn) downloadBtn.disabled = true;
      } else {
        consoleOutput.textContent = commands.join('\\n');
        consoleOutput.style.color = 'var(--accent-primary)';
        if (copyBtn) copyBtn.disabled = false;
        if (downloadBtn) downloadBtn.disabled = false;
      }
    }
    window.updateConsoleCommands = updateConsoleCommands;

    window.copyConsoleCommands = () => {
      const text = $('#console-output')?.textContent;
      if (!text || text.startsWith('No items marked')) return;

      navigator.clipboard.writeText(text).then(() => {
        showToast('Commands copied to clipboard!', 'relevant');
      }).catch(err => {
        console.error('Failed to copy commands: ', err);
      });
    };

    window.downloadConsoleScript = () => {
      const text = $('#console-output')?.textContent;
      if (!text || text.startsWith('No items marked')) return;

      downloadFile(text, 'feedback_commands.bat', 'text/plain');
      showToast('Commands script downloaded!', 'relevant');
    };

    updateConsoleCommands();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Start
  // ═══════════════════════════════════════════════════════════════════════════

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
