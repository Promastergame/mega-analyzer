/* Persistent local workspace explorer. Files are previewed as text, never executed. */
(function () {
  "use strict";
  function byId(id) { return document.getElementById(id); }
  var dialog = byId("workspaceDialog"), entriesEl = byId("wsEntries"), previewEl = byId("wsPreview");
  var current = "", entries = [], next = 0, more = false, request = 0, previewRequest = 0;
  var activeScan = null, busy = false, selected = null, filter = "all";
  var listController = null, previewController = null, folderPending = false;
  var renderer = window.WorkspacePreview;
  var STR = {
    ru: {app:"Мой компьютер",sub:"Результаты анализа. Всё под рукой.",local:"Локальное хранилище",files:"Файлы",byName:"По имени",byDate:"Сначала новые",bySize:"По размеру",sortAria:"Сортировка загруженных файлов",searchPh:"Найти в этой папке…",searchAria:"Поиск среди загруженных файлов",filterAria:"Тип файла",filterAll:"Все файлы",more:"Загрузить ещё",newFolder:"Новая папка",saveHere:"Сохранять сюда",folderName:"Имя папки",folderPh:"Например, Мои проекты",create:"Создать",cancel:"Отмена",up:"На уровень выше",refresh:"Обновить папку",crumbs:"Путь в хранилище",filesSec:"Файлы и папки",previewSec:"Просмотр файла",close:"Закрыть мой компьютер",expand:"Развернуть окно",collapse:"Обычный размер окна",toFiles:"К файлам",download:"Скачать",view:"Просмотр",source:"Исходник",wrap:"Перенос",wrapTitle:"Перенос длинных строк",copy:"Копировать",viewModes:"Режим просмотра",contentAria:"Содержимое файла",loading:"Загружаем содержимое…",folder:"Папка",retry:"Повторить",resetFilters:"Сбросить фильтры",done:"Выполнено",notDone:"Не выполнено",timeout:"Сервер не ответил вовремя. Попробуйте ещё раз.",loadingFiles:"Загружаем файлы…",openFail:"Не удалось открыть папку. ",folderNA:"Папка недоступна",copyNA:"Копирование недоступно. Выделите текст в исходнике.",copied:"Скопирован исходный текст: ",copyFail:"Не удалось скопировать. Выделите текст в исходнике.",dlReady:"Файл готов к скачиванию",overCap:"Предпросмотр доступен для файлов до 2 МиБ. Скачайте оригинал, чтобы открыть его целиком.",wrongFmt:"Для этого формата доступно скачивание. Используйте кнопку сверху.",jsonBad:"В JSON ошибка синтаксиса. Ниже исходный текст, его можно скачать без изменений.",complexDoc:"Сложный документ показан исходным текстом, чтобы сохранить быстрый просмотр.",bigDoc:"Большой документ показан исходным текстом. Скачать можно полный оригинал.",openFileFail:"Не удалось открыть файл",htmlNote:"HTML: скрипты и внешние ресурсы отключены.",expandBtn:"Развернуть",collapseBtn:"Свернуть",emptyT:"Ваши отчёты здесь",emptyD:"Выбери файл слева, чтобы прочитать отчёт или исходник.",formats:"MARKDOWN / JSON / ТЕКСТ",noResults:"Ничего не найдено",noResultsD:"Попробуйте другое имя или тип файла.",noFiles:"Пока нет файлов",noFilesD:"Результаты появятся после анализа. Здесь также можно создавать папки.",folderErr:"Укажите имя папки без слешей и точки в начале.",objects:" объектов",loadMore:" · поиск и сортировка по загруженным; загрузите ещё",logCut:" · журнал сокращён",truncated:" сокращён",unitB:" Б",unitKB:" КиБ",unitMB:" МиБ",stRunning:"Анализ идёт",stQueued:"В очереди",stCompleted:"Готово",stFailed:"Ошибка",stStopped:"Остановлен",stInterrupted:"Прерван",allScans:"Все сканы",allScansTitle:"Перейти ко всем отчётам и сканам",results:"Результаты",sandbox:"Песочница"},
    en: {app:"My Computer",sub:"Analysis results. Everything at hand.",local:"Local storage",files:"Files",byName:"By name",byDate:"Newest first",bySize:"By size",sortAria:"Sort loaded files",searchPh:"Search this folder…",searchAria:"Search loaded files",filterAria:"File type",filterAll:"All files",more:"Load more",newFolder:"New folder",saveHere:"Save here",folderName:"Folder name",folderPh:"e.g. My projects",create:"Create",cancel:"Cancel",up:"Go up one level",refresh:"Refresh folder",crumbs:"Storage path",filesSec:"Files and folders",previewSec:"File preview",close:"Close My Computer",expand:"Expand window",collapse:"Normal window size",toFiles:"Back to files",download:"Download",view:"Preview",source:"Source",wrap:"Wrap",wrapTitle:"Wrap long lines",copy:"Copy",viewModes:"View mode",contentAria:"File contents",loading:"Loading contents…",folder:"Folder",retry:"Retry",resetFilters:"Reset filters",done:"Done",notDone:"Not done",timeout:"Server did not respond in time. Try again.",loadingFiles:"Loading files…",openFail:"Could not open folder. ",folderNA:"Folder unavailable",copyNA:"Copy unavailable. Select the source text.",copied:"Copied source text: ",copyFail:"Could not copy. Select the source text.",dlReady:"File ready to download",overCap:"Preview is available for files up to 2 MiB. Download the original to open it fully.",wrongFmt:"Download is available for this format. Use the button above.",jsonBad:"JSON has a syntax error. The source text is below; it can be downloaded unchanged.",complexDoc:"A complex document is shown as source text to keep preview fast.",bigDoc:"A large document is shown as source text. The full original can be downloaded.",openFileFail:"Could not open file",htmlNote:"HTML: scripts and external resources are disabled.",expandBtn:"Expand",collapseBtn:"Collapse",emptyT:"Your reports live here",emptyD:"Select a file on the left to read a report or its source.",formats:"MARKDOWN / JSON / TEXT",noResults:"Nothing found",noResultsD:"Try a different name or file type.",noFiles:"No files yet",noFilesD:"Results appear after analysis. You can also create folders here.",folderErr:"Enter a folder name without slashes or a leading dot.",objects:" items",loadMore:" · search and sort loaded entries; load more",logCut:" · log truncated",truncated:" truncated",unitB:" B",unitKB:" KB",unitMB:" MB",stRunning:"Running",stQueued:"Queued",stCompleted:"Completed",stFailed:"Failed",stStopped:"Stopped",stInterrupted:"Interrupted",allScans:"All Scans",allScansTitle:"Go to all reports and scans",results:"Results",sandbox:"Sandbox"}
  };
  if(window.MegaWasm){
    Object.assign(STR.ru,{app:"Файлы этой вкладки",sub:"Скачайте результаты перед закрытием или обновлением страницы.",local:"В памяти вкладки",timeout:"Не удалось открыть результат. Попробуйте ещё раз."});
    Object.assign(STR.en,{app:"Files in this tab",sub:"Download results before closing or reloading this page.",local:"In tab memory",timeout:"Cannot open the result. Try again."});
  }
  function lang() { return (typeof window.uiLang === "string" && window.uiLang === "en") ? "en" : "ru"; }
  function t(key) { var l = lang(); return (STR[l] && STR[l][key] !== undefined) ? STR[l][key] : (STR.ru[key] !== undefined ? STR.ru[key] : key); }
  var icons = {
    folder:"M3 7V5h6l2 2h10v13H3V7Z", download:"M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5",
    back:"m14 5-7 7 7 7", copy:"M9 3h12v14H9V3ZM5 7H3v14h12v-2"
  };
  function node(tag, value, cls) {
    var el = document.createElement(tag);
    if (value !== undefined) el.textContent = value;
    if (cls) el.className = cls;
    return el;
  }
  function icon(name) {
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("aria-hidden", "true");
    var path = document.createElementNS(svg.namespaceURI, "path"); path.setAttribute("d", icons[name]); svg.appendChild(path);
    return svg;
  }
  function button(label, fn, cls) {
    var b = node("button", label, cls || "ws-button"); b.type = "button"; b.addEventListener("click", fn); return b;
  }
  function message(value, isError) { byId("wsStatus").textContent = value; byId("wsStatus").classList.toggle("ws-error", !!isError); }
  function error(r) {
    return r.text().then(function (value) { try { value = JSON.parse(value).message || value; } catch (_) {} throw new Error(value || "HTTP " + r.status); });
  }
  function get(url, type, controller, opts) {
    opts = opts || {}; opts.signal = controller.signal;
    var timer = setTimeout(function () { controller.abort(); }, 15000);
    return fetch(url, opts).then(function (r) { if (!r.ok) return error(r); return type === "text" ? r.text() : r.json(); }).finally(function () { clearTimeout(timer); });
  }
  function reason(e) { return e.name === "AbortError" ? t("timeout") : e.message; }
  function size(n) { if (n < 1024) return n + t("unitB"); if (n < 1048576) return (n / 1024).toFixed(1) + t("unitKB"); return (n / 1048576).toFixed(1) + t("unitMB"); }
  function date(value, full) {
    var d = new Date(value);
    return isNaN(d.getTime()) ? "" : d.toLocaleString(lang() === "en" ? "en-US" : "ru-RU", full ? {day:"numeric",month:"short",year:"numeric",hour:"2-digit",minute:"2-digit"} : {day:"numeric",month:"short"});
  }
  function kind(entry) { return entry.directory ? "folder" : (entry.name.match(/\.([^.]+)$/) || ["", "file"])[1].toLowerCase(); }
  function fileIcon(type) {
    var el = node("span", undefined, "ws-file-icon"); el.dataset.kind = type; el.setAttribute("aria-hidden", "true");
    if (type === "folder") el.appendChild(icon("folder")); else el.textContent = type === "json" ? "{ }" : type.toUpperCase().slice(0, 4);
    return el;
  }
  function fileURL(path, preview) { return "/api/workspace/file?path=" + encodeURIComponent(path) + (preview ? "&preview=1" : ""); }
  function scanStatus(scan) {
    return ({running:t("stRunning"),queued:t("stQueued"),completed:t("stCompleted"),failed:t("stFailed"),stopped:t("stStopped"),interrupted:t("stInterrupted")})[scan.status] || scan.status;
  }
  function insideScan() { return current.split("/").some(function (s) { return /^\d{4}-\d{2}-\d{2}_\d{6}_[a-f0-9]{32}$/.test(s); }); }
  function controls() {
    byId("wsUseFolder").disabled = busy || !!activeScan || !current || insideScan();
    byId("wsNewFolder").disabled = busy || !!activeScan || insideScan() || folderPending;
    byId("wsUp").disabled = !current;
    byId("wsMore").hidden = !more; byId("wsMore").disabled = busy;
    entriesEl.setAttribute("aria-busy", String(busy));
  }
  function crumbLabel(part) {
    if (part === "Scans") return t("allScans");
    if (/^\d{4}-\d{2}-\d{2}_\d{6}_[a-f0-9]{32}$/.test(part)) {
      if (activeScan && activeScan.name) return activeScan.name;
      return part.slice(0, 10);
    }
    if (part === "results") return t("results");
    if (part === "sandbox") return t("sandbox");
    if (part.indexOf("vmware-") === 0) return "VMware";
    return part;
  }
  function crumbs() {
    var el = byId("wsCrumbs"); el.replaceChildren();
    el.appendChild(button(t("app"), function () { load(""); }));
    var parts = current ? current.split("/") : [];
    parts.forEach(function (part, i) {
      el.appendChild(node("span", "›"));
      var b = button(crumbLabel(part), function () { load(parts.slice(0, i + 1).join("/")); }); b.title = part; el.appendChild(b);
    });
    if (el.lastElementChild) el.lastElementChild.setAttribute("aria-current", "page");
    el.scrollLeft = el.scrollWidth;
  }
  function empty(parent, title, description, art) {
    var el = node("div", undefined, "ws-empty");
    if (art) {
      var drawing = node("div", undefined, "ws-empty-art");
      drawing.append(fileIcon("md"), fileIcon("json")); el.appendChild(drawing);
    }
    el.append(node("h3", title), node("p", description)); parent.appendChild(el); return el;
  }
  function emptyPreview() {
    previewEl.replaceChildren();
    var el = empty(previewEl, t("emptyT"), t("emptyD"), true);
    el.appendChild(node("span", t("formats"), "ws-empty-formats"));
    dialog.classList.remove("ws-show-preview");
  }
  function markSelection() {
    entriesEl.querySelectorAll(".ws-entry").forEach(function (el) {
      if (el.dataset.directory !== "true") el.setAttribute("aria-pressed", String(!!selected && el.dataset.path === selected.path));
    });
  }
  function setFilter(value) {
    filter = value;
    dialog.querySelectorAll("[data-ws-filter]").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.wsFilter === filter)); });
  }
  function render() {
    var query = byId("wsSearch").value.trim().toLocaleLowerCase(), sort = sortVal;
    var visible = entries.filter(function (entry) {
      var label = entry.scan ? entry.scan.name : entry.name;
      return (filter === "all" || kind(entry) === filter) && (label + " " + entry.name).toLocaleLowerCase().indexOf(query) >= 0;
    }).sort(function (a, b) {
      if (a.directory !== b.directory) return a.directory ? -1 : 1;
      var diff = sort === "date" ? new Date(b.modified) - new Date(a.modified) : sort === "size" ? b.size - a.size : 0;
      return diff || (a.scan ? a.scan.name : a.name).localeCompare(b.scan ? b.scan.name : b.name, lang(), {numeric:true,sensitivity:"base"});
    });
    entriesEl.replaceChildren();
    visible.forEach(function (entry) {
      var card = button("", function () {
        if (!busy) {
          if (entry.directory) {
            if (entry.scan && entry.scan.report_dir) load(entry.scan.report_dir);
            else load(entry.path);
          } else preview(entry, true);
        }
      }, "ws-entry");
      card.dataset.path = entry.path; card.dataset.directory = String(entry.directory);
      card.appendChild(fileIcon(kind(entry)));
      var copy = node("span", undefined, "ws-entry-copy");
      copy.appendChild(node("strong", entry.scan ? entry.scan.name : entry.name));
      copy.appendChild(node("small", entry.scan ? scanStatus(entry.scan) + " · " + date(entry.modified) : (entry.directory ? t("folder") : size(entry.size)) + " · " + date(entry.modified)));
      card.appendChild(copy);
      if (entry.directory) card.appendChild(node("span", "›", "ws-entry-arrow"));
      card.title = entry.path; entriesEl.appendChild(card);
    });
    if (!visible.length) {
      var filtered = query || filter !== "all";
      var el = empty(entriesEl, filtered ? t("noResults") : t("noFiles"), filtered ? t("noResultsD") : t("noFilesD"));
      if (filtered) el.appendChild(button(t("resetFilters"), function () { byId("wsSearch").value = ""; setFilter("all"); render(); byId("wsSearch").focus(); }));
    }
    byId("wsCount").textContent = visible.length + (visible.length !== entries.length ? " / " + entries.length : "") + (more ? "+" : "");
    controls(); markSelection();
  }
  function cancelPreview() { previewRequest++; if (previewController) previewController.abort(); }
  function load(path, append) {
    var serial = ++request, oldSelection = selected;
    if (listController) listController.abort();
    listController = new AbortController();
    busy = true; controls(); message(t("loadingFiles"));
    get("/api/workspace/list?path=" + encodeURIComponent(path) + "&offset=" + (append ? next : 0), "json", listController).then(function (data) {
      if (serial !== request) return;
      var moved = current !== path;
      if (!append) {
        cancelPreview(); entries = []; selected = null; emptyPreview(); byId("wsFolderForm").hidden = true;
        if (moved) { byId("wsSearch").value = ""; setFilter("all"); }
      }
      current = path; entries = entries.concat(data.entries || []); next = data.next_offset; more = data.has_more; activeScan = data.scan; busy = false;
      crumbs(); render();
      message(activeScan ? activeScan.name + " · " + scanStatus(activeScan) + (activeScan.log_truncated ? t("logCut") : "") : entries.length + t("objects") + (more ? t("loadMore") : ""));
      if (!append) {
        var preferred = entries.find(function (e) { return !e.directory && oldSelection && oldSelection.path === e.path; }) ||
          entries.find(function (e) { return /^sandbox_report\.md$/i.test(e.name); }) ||
          entries.find(function (e) { return /^report\.md$/i.test(e.name); }) ||
          entries.find(function (e) { return kind(e) === "md"; }) ||
          entries.find(function (e) { return /^sandbox_report\.json$/i.test(e.name); }) ||
          entries.find(function (e) { return kind(e) === "json" && !/^\.?scan\.json$/i.test(e.name); });
        if (preferred && window.matchMedia("(min-width: 701px)").matches) preview(preferred, false);
      }
    }).catch(function (e) {
      if (serial !== request) return;
      busy = false; controls(); message(t("openFail") + reason(e), true);
      if (!entries.length) {
        entriesEl.replaceChildren();
        empty(entriesEl, t("folderNA"), reason(e)).appendChild(button(t("retry"), function () { load(path, append); }));
      }
    });
  }
  function backToFiles() {
    dialog.classList.remove("ws-show-preview");
    var card = Array.from(entriesEl.querySelectorAll(".ws-entry")).find(function (el) { return selected && el.dataset.path === selected.path; });
    (card || byId("wsSearch")).focus();
  }
  function preview(entry, reveal) {
    cancelPreview(); var serial = previewRequest;
    previewController = new AbortController(); selected = entry; markSelection(); previewEl.replaceChildren();
    var selectedCard = entriesEl.querySelector('[aria-pressed="true"]');
    if (selectedCard) selectedCard.scrollIntoView({block:"nearest"});
    if (reveal) dialog.classList.add("ws-show-preview");
    var head = node("div", undefined, "ws-preview-head"), back = button(t("toFiles"), backToFiles, "ws-button ws-mobile-back");
    back.prepend(icon("back")); head.append(back, fileIcon(kind(entry)));
    var title = node("div", undefined, "ws-preview-title"), heading = node("h3", entry.name);
    heading.tabIndex = -1; title.append(heading, node("p", kind(entry).toUpperCase() + " · " + size(entry.size) + " · " + date(entry.modified, true))); head.appendChild(title);
    var download = node("a", t("download"), "ws-button ws-primary");
    download.href = fileURL(entry.path, false); download.download = entry.name; download.prepend(icon("download")); head.appendChild(download);
    previewEl.append(head, node("div", entry.path, "ws-preview-path"));
    var toolbar = node("div", undefined, "ws-preview-tools"), modes = node("div", undefined, "ws-view-modes");
    modes.setAttribute("role", "group"); modes.setAttribute("aria-label", t("viewModes"));
    var raw = false, wrap = true, data = null, rich = null, formatNote = "";
    var viewButton = button(t("view"), function () { raw = false; draw(); });
    var sourceButton = button(t("source"), function () { raw = true; draw(); });
    var wrapButton = button(t("wrap"), function () { wrap = !wrap; draw(); });
    wrapButton.title = t("wrapTitle");
    var copyButton = button(t("copy"), function () {
      if (data === null) return;
      if (!navigator.clipboard) { message(t("copyNA"), true); return; }
      navigator.clipboard.writeText(data).then(function () {
        if (serial === previewRequest && dialog.open) message(t("copied") + entry.name);
      }).catch(function () { if (serial === previewRequest) message(t("copyFail"), true); });
    });
    copyButton.prepend(icon("copy")); modes.append(viewButton, sourceButton); toolbar.append(modes, wrapButton, copyButton);
    [viewButton, sourceButton, wrapButton, copyButton].forEach(function (b) { b.disabled = true; });
    viewButton.setAttribute("aria-pressed", "true"); sourceButton.setAttribute("aria-pressed", "false");
    previewEl.appendChild(toolbar);
    var content = node("div", undefined, "ws-preview-content"); content.tabIndex = 0; content.setAttribute("aria-label", t("contentAria")); previewEl.appendChild(content);
    if (reveal && window.matchMedia("(max-width: 700px)").matches) heading.focus();
    function notice(value) { content.appendChild(node("p", value, "ws-notice")); }
    function draw() {
      if (data === null) return;
      content.replaceChildren();
      viewButton.setAttribute("aria-pressed", String(!raw)); sourceButton.setAttribute("aria-pressed", String(raw));
      wrapButton.setAttribute("aria-pressed", String(wrap));
      wrapButton.hidden = !raw && (kind(entry) === "md" && rich || /^html?$/.test(kind(entry)));
      if (!raw && formatNote) notice(formatNote);
      if (!raw && rich) {
        content.appendChild(rich);
        if (rich.tagName === "PRE") rich.classList.toggle("ws-wrap", wrap);
      } else if (!raw && /^html?$/.test(kind(entry))) {
        notice(t("htmlNote"));
        var frame = document.createElement("iframe"); frame.title = entry.name; frame.setAttribute("sandbox", ""); frame.referrerPolicy = "no-referrer";
        frame.srcdoc = '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; img-src data:; form-action &#39;none&#39;; base-uri &#39;none&#39;">' + data;
        content.appendChild(frame);
      } else content.appendChild(node("pre", data, "ws-code" + (wrap ? " ws-wrap" : "")));
      content.scrollTop = 0;
    }
    if (!/\.(json|txt|log|md|csv|html?|xml|svg|ya?ml|properties|java|smali)$/i.test(entry.name) || entry.size > 2097152) {
      toolbar.hidden = true;
      empty(content, t("dlReady"), entry.size > 2097152 ? t("overCap") : t("wrongFmt"), true); return;
    }
    content.appendChild(node("p", t("loading"), "ws-notice")); content.setAttribute("aria-busy", "true");
    get(fileURL(entry.path, true), "text", previewController).then(function (value) {
      if (serial !== previewRequest) return;
      data = value;
      if (data.length <= renderer.richLimit) {
        try {
          if (kind(entry) === "md") rich = renderer.markdown(data);
          else if (kind(entry) === "json") rich = renderer.json(renderer.formatJSON(data));
        } catch (e) {
          formatNote = e instanceof SyntaxError ? t("jsonBad") : t("complexDoc");
        }
      } else if (/^(md|json)$/.test(kind(entry))) formatNote = t("bigDoc");
      [viewButton, sourceButton, wrapButton, copyButton].forEach(function (b) { b.disabled = false; });
      content.removeAttribute("aria-busy"); draw();
    }).catch(function (e) {
      if (serial !== previewRequest) return;
      toolbar.hidden = true; content.removeAttribute("aria-busy"); content.replaceChildren();
      empty(content, t("openFileFail"), reason(e)).appendChild(button(t("retry"), function () { preview(entry, reveal); }));
    });
  }
  byId("workspaceOpen").addEventListener("click", function () {
    if (typeof closeMenu === "function") closeMenu();
    if (!dialog.open) dialog.showModal();
    load(current);
  });
  byId("workspaceClose").addEventListener("click", function () { dialog.close(); });
  dialog.addEventListener("close", function () { request++; if (listController) listController.abort(); cancelPreview(); busy = false; });
  byId("wsExpand").addEventListener("click", function () {
    var expanded = dialog.classList.toggle("ws-expanded");
    this.setAttribute("aria-pressed", String(expanded)); this.setAttribute("aria-label", expanded ? t("collapse") : t("expand"));
  });
  byId("wsAllScans").addEventListener("click", function () { load("Scans"); });
  byId("wsRefresh").addEventListener("click", function () { load(current); });
  byId("wsUp").addEventListener("click", function () { load(current.split("/").slice(0, -1).join("/")); });
  byId("wsMore").addEventListener("click", function () { if (!busy) load(current, true); });
  byId("wsSearch").addEventListener("input", render);
  var sortVal = "name";
  (function () {
    var btn = byId("wsSortBtn"), menu = byId("wsSortMenu"), label = byId("wsSortLabel");
    function close(focus) { menu.hidden = true; btn.setAttribute("aria-expanded", "false"); if (focus) btn.focus(); }
    function open() { menu.hidden = false; btn.setAttribute("aria-expanded", "true"); var cur = menu.querySelector('[data-value="' + sortVal + '"]'); if (cur) cur.focus(); }
    btn.addEventListener("click", function () { if (menu.hidden) open(); else close(false); });
    menu.addEventListener("click", function (e) {
      var opt = e.target.closest("[data-value]"); if (!opt) return;
      sortVal = opt.dataset.value; label.textContent = opt.textContent;
      menu.querySelectorAll("[data-value]").forEach(function (o) { o.setAttribute("aria-selected", String(o === opt)); });
      close(false); render();
    });
    menu.addEventListener("keydown", function (e) {
      var opts = Array.from(menu.querySelectorAll("[data-value]"));
      var i = opts.indexOf(document.activeElement);
      if (e.key === "Escape") { close(true); }
      else if (e.key === "ArrowDown") { e.preventDefault(); (opts[i + 1] || opts[0]).focus(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); (opts[i - 1] || opts[opts.length - 1]).focus(); }
    });
    document.addEventListener("click", function (e) { if (!byId("wsSort").contains(e.target) && !menu.hidden) close(false); });
  })();
  dialog.querySelectorAll("[data-ws-filter]").forEach(function (b) { b.addEventListener("click", function () { setFilter(b.dataset.wsFilter); render(); }); });
  byId("wsNewFolder").addEventListener("click", function () {
    byId("wsFolderForm").hidden = false; byId("wsFolderName").value = ""; byId("wsFolderError").textContent = ""; byId("wsFolderName").focus();
  });
  byId("wsFolderCancel").addEventListener("click", function () { byId("wsFolderForm").hidden = true; byId("wsNewFolder").focus(); });
  byId("wsFolderForm").addEventListener("submit", function (event) {
    event.preventDefault();
    if (folderPending || busy || activeScan || insideScan()) return;
    var name = byId("wsFolderName").value.trim(), path = current, form = this;
    if (!name || name.indexOf("/") >= 0 || name.indexOf("\\") >= 0 || name.charAt(0) === ".") {
      byId("wsFolderError").textContent = t("folderErr"); return;
    }
    folderPending = true; controls(); form.querySelector("[type=submit]").disabled = true;
    get("/api/workspace/mkdir", "json", new AbortController(), {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path:path ? path + "/" + name : name})}).then(function () {
      if (current === path && dialog.open) { form.hidden = true; load(current); }
    }).catch(function (e) {
      if (current === path && dialog.open) { form.hidden = false; byId("wsFolderError").textContent = reason(e); }
    }).finally(function () { folderPending = false; form.querySelector("[type=submit]").disabled = false; controls(); });
  });
  byId("wsUseFolder").addEventListener("click", function () {
    byId("outdir").value = current; byId("outdir").dispatchEvent(new Event("input", {bubbles:true})); dialog.close();
  });
  window.addEventListener("mega:scan-created", function (e) {
    if (e.detail && e.detail.path) { if (dialog.open) load(e.detail.path); else current = e.detail.path; }
  });
  function setBtnText(id, text) {
    var b = byId(id); if (!b) return;
    for (var i = 0; i < b.childNodes.length; i++) {
      if (b.childNodes[i].nodeType === 3 && b.childNodes[i].textContent.trim()) { b.childNodes[i].textContent = text; return; }
    }
    b.appendChild(document.createTextNode(text));
  }
  function applyWsLang() {
    byId("wsTitle").textContent = t("app");
    document.querySelector(".ws-title p").textContent = t("sub");
    var local = document.querySelector(".ws-local");
    if (local) { for (var i = 0; i < local.childNodes.length; i++) { if (local.childNodes[i].nodeType === 3) local.childNodes[i].textContent = t("local"); } }
    byId("workspaceClose").setAttribute("aria-label", t("close"));
    byId("wsExpand").setAttribute("aria-label", dialog.classList.contains("ws-expanded") ? t("collapse") : t("expand"));
    byId("wsUp").setAttribute("aria-label", t("up"));
    byId("wsCrumbs").setAttribute("aria-label", t("crumbs"));
    byId("wsAllScans").setAttribute("aria-label", t("allScans"));
    byId("wsAllScans").setAttribute("title", t("allScansTitle"));
    byId("wsAllScansLabel").textContent = t("allScans");
    byId("wsRefresh").setAttribute("aria-label", t("refresh"));
    setBtnText("wsNewFolder", t("newFolder"));
    byId("wsUseFolder").textContent = t("saveHere");
    var fl = document.querySelector('label[for="wsFolderName"]'); if (fl) fl.textContent = t("folderName");
    byId("wsFolderName").placeholder = t("folderPh");
    var submit = document.querySelector('#wsFolderForm [type="submit"]'); if (submit) submit.textContent = t("create");
    byId("wsFolderCancel").textContent = t("cancel");
    document.querySelector(".ws-files").setAttribute("aria-label", t("filesSec"));
    var head = document.querySelector(".ws-files-head h3");
    if (head && head.firstChild) head.firstChild.textContent = t("files") + " ";
    var sortNames = {name: t("byName"), date: t("byDate"), size: t("bySize")};
    document.querySelectorAll("#wsSortMenu [data-value]").forEach(function (o) { o.textContent = sortNames[o.dataset.value] || o.textContent; });
    byId("wsSortMenu").setAttribute("aria-label", t("sortAria"));
    byId("wsSortLabel").textContent = sortNames[sortVal] || sortNames.name;
    byId("wsSearch").placeholder = t("searchPh");
    byId("wsSearch").setAttribute("aria-label", t("searchAria"));
    document.querySelector(".ws-filters").setAttribute("aria-label", t("filterAria"));
    var filterNames = {all: t("filterAll"), md: ".md", json: ".json"};
    document.querySelectorAll("[data-ws-filter]").forEach(function (b) { b.textContent = filterNames[b.dataset.wsFilter] || b.textContent; });
    byId("wsMore").textContent = t("more");
    byId("wsPreview").setAttribute("aria-label", t("previewSec"));
    if (!busy && !entries.length) byId("wsStatus").textContent = t("loadingFiles");
    render();
    if (selected) preview(selected, false); else emptyPreview();
  }
  window.WorkspaceI18n = {apply: applyWsLang};
  applyWsLang();
})();
