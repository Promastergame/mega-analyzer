// ── tool config ──
var MODES={
  "minecraft":{t:"Minecraft Mods & Packs",s:"Java mods, texture packs and Bedrock add-ons: metadata, dependencies, nested archives and static risk indicators.",panel:"none",report:true,accept:".jar,.zip,.mcpack,.mcaddon",fmts:["JAR","ZIP","MCPACK","MCADDON"],info:"Reads package content without launching Minecraft. Supports Fabric, Forge, NeoForge, Quilt and Bedrock manifests. A complete report does not guarantee safety."},
  "full":{t:"Full Static Analysis",s:"APK/DEX and JS/Hermes bundles — static findings, readable exports and downloadable files.",panel:"full",report:true,accept:".apk,.dex,.jar,.war,.zip,.aab,.ipa,.xapk,.apks,.apkm,.bundle,.hbc,.jsbundle,.js,.mjs,.cjs",fmts:["APK","DEX","AAB","JAR","IPA","ZIP","XAPK","APKS","JS","Hermes"],ico:"M22 12A10 10 0 1 1 12 2|M12 12L18.5 7.5|c3"},
  "decode":{t:"Decode APK",s:"Decode APK/DEX into Smali and editable resources using the built-in engine.",panel:"decode",report:false,btn:"Decode APK",accept:".apk,.dex,.jar,.zip,.xapk",fmts:["APK","DEX","JAR","XAPK"],info:"Runs without Java, apktool or baksmali. Download the result ZIP, edit the project, then upload it in Build APK. Keep hidden project files for rebuilding. Java view is pseudocode, not compilable source."},
  "build":{t:"Build APK",s:"Build an APK from a project ZIP with the built-in assembler, resource compiler and signer.",panel:"build",report:false,btn:"Build APK",accept:".zip",fmts:["PROJECT ZIP"],info:"ZIP must contain AndroidManifest.xml at the root or in one project folder, with Smali or existing DEX and supported resources. No aapt2, android.jar, d8 or Java is required. Java/Kotlin/Gradle source projects are not supported; unsupported resource features produce an error. The APK uses a debug signing key, not the original publisher's key."},
  "machine-code":{t:"Machine Code Forensics",s:"Raw PE / ELF / .so binary forensics via OmniSec.",panel:"tune",report:true,accept:".exe,.dll,.so,.elf,.bin",fmts:["EXE","DLL","ELF",".so"]},
  "firmware":{t:"Firmware / IoT",s:"Rootfs, archive and firmware image analysis.",panel:"tune",report:true,accept:".bin,.img,.zip,.tar,.gz",fmts:["BIN","IMG","rootfs","archive"]},
  "version-diff":{t:"Version Diff",s:"Compare an old build against a new build.",panel:"diff",report:false,accept:".apk,.dex,.zip",fmts:["APK","DEX"],info:"Drop the OLD build in the first zone and the NEW build in the second to compare them."},
  "sandbox":{t:"Dynamic analysis",s:"Run a sample in a selected VMware Windows guest or Android target and collect observed activity.",panel:"sandbox",report:false,btn:"Start analysis",accept:".apk,.xapk,.apks,.exe,.com,.bat,.cmd,.ps1",fmts:["APK","XAPK","APKS","EXE","COM","BAT","CMD","PS1"],info:"Choose a detected analysis target. VMware sessions use disconnected virtual network adapters and save their reports on this PC."},
  "web-scan":{t:"Server Scan",s:"Active web vulnerability scan against a URL you are authorised to test.",panel:"webscan",report:false,fileless:true,btn:"Scan server",info:"Active scanning — only run it against servers you own or are explicitly authorised to test."},
  "intercept":{t:"MITM Proxy",s:"Intercept and inspect app / game traffic through a local proxy.",panel:"mitm",report:false,fileless:true,longRunning:true,btn:"Start proxy",info:"The proxy listens on the port and forwards to the real server. Point your device/app at this machine on that port, then press Stop when finished — the captured traffic is saved automatically."}
};
var TOOL_ICO={
  "minecraft":"<path d='M3 7l9-5 9 5v10l-9 5-9-5V7zM3 7l9 5 9-5M12 12v10'/>",
  "full":"<circle cx='12' cy='12' r='3'/><path d='M12 2a10 10 0 1 0 10 10'/><path d='M12 12l6-5'/>",
  "decode":"<path d='M3 7l9-4 9 4-9 4-9-4z'/><path d='M3 7v10l9 4 9-4V7'/><path d='M12 11v10'/>",
  "build":"<path d='M3 7l9-4 9 4-9 4-9-4zM3 7v10l9 4 9-4V7M12 11v10'/><path d='M16 2v6M13 5h6'/>",
  "machine-code":"<rect x='6' y='6' width='12' height='12' rx='1.5'/><rect x='9.5' y='9.5' width='5' height='5'/><path d='M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3'/>",
  "firmware":"<rect x='2' y='5' width='20' height='14' rx='2'/><line x1='2' y1='12' x2='22' y2='12'/><circle cx='7' cy='15.5' r='1'/><circle cx='7' cy='8.5' r='1'/>",
  "version-diff":"<circle cx='6' cy='6' r='2.4'/><circle cx='18' cy='18' r='2.4'/><path d='M6 8.4V14a4 4 0 0 0 4 4h4M18 15.6V10a4 4 0 0 0-4-4h-4'/>",
  "sandbox":"<rect x='3' y='4' width='18' height='13' rx='2'/><path d='M3 11h4l2-3 3 6 2-3h7M8 21h8M12 17v4'/>",
  "web-scan":"<rect x='3' y='4' width='18' height='6' rx='1.5'/><rect x='3' y='14' width='12' height='6' rx='1.5'/><path d='M7 7h.01M7 17h.01'/><circle cx='19' cy='18' r='2.4'/><path d='M22 21l-1.4-1.4'/>",
  "intercept":"<path d='M3 7h12'/><path d='M12 4l3 3-3 3'/><path d='M21 17H9'/><path d='M12 14l-3 3 3 3'/>"
};

var curMode="full",sf=null,sf2=null,jid=null,ptmr=null,curOut="",running=false;
var uploadAbort=null; // AbortController for the /api/scan upload: Stop during upload cancels it
var scanGeneration=0,resultRequest=0,resultAbort=null,artifactAbort=null,closeScanStream=null;
function scanIsCurrent(generation,id,mode){return generation===scanGeneration&&(!id||jid===id)&&(!mode||curMode===mode);}
function invalidateScanView(){
  scanGeneration++;resultRequest++;jid=null;
  [uploadAbort,resultAbort,artifactAbort].forEach(function(c){if(c)c.abort();});
  uploadAbort=resultAbort=artifactAbort=null;
  if(closeScanStream){closeScanStream();closeScanStream=null;}
  clearInterval(ptmr);ptmr=null;
}
var curEnv="",curDepth="basic",curOri="";

// ── target environment (OS / VM / device) picker ──
// ENV is the detected environment from /api/env; curTarget is the selected row.
var ENV=null,envState="loading",envError="",hostError="",envFresh=false;
var curTarget=null,selectedTargetKey="",selectionExplicit=false;
var osMenuOpen=false;

// Map a file extension to the OS family that can run it.
function familyForFile(name){
  var ext=(String(name||"").toLowerCase().match(/\.[a-z0-9]+$/)||[""])[0];
  if(ext===".apk"||ext===".dex"||ext===".aab"||ext===".xapk"||ext===".apks")return "android";
  if(ext===".exe"||ext===".com"||ext===".dll"||ext===".msi"||ext===".scr"||ext===".bat"||ext===".cmd"||ext===".ps1")return "windows";
  if(ext===".elf"||ext===".so"||ext===".bin"||ext===".out"||ext===".run")return "linux";
  if(ext===".app"||ext===".dmg"||ext===".macho")return "macos";
  return "any";
}

// Small inline SVGs keyed by os family / provider.
var OS_ICONS={
  win:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 5.5 10.5 4.4v7.1H3zM10.5 12.5v7.1L3 18.5v-6zM11.8 4.2 21 3v8.5h-9.2zM21 12.5V21l-9.2-1.3v-7.2z"/></svg>',
  android:'<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m7 6-2-3m12 3 2-3" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/><path fill="currentColor" fill-rule="evenodd" d="M3 18a9 9 0 0 1 18 0H3Zm5-6a1 1 0 1 0 2 0 1 1 0 0 0-2 0Zm6 0a1 1 0 1 0 2 0 1 1 0 0 0-2 0Z"/></svg>',
  linux:'<svg viewBox="0 0 24 24" fill="currentColor"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 1.7 c -2.45 0 -4.05 1.85 -4.05 4.4 0 .95 .06 1.7 .06 2.3 0 .78 -.5 1.55 -1.18 2.6 C 5.85 12.5 5 14.15 5 15.7 c 0 1.02 .36 1.88 1.02 2.48 l -1.4 2.12 c -.3 .46 .02 1.05 .57 1.05 h 3.94 c .38 0 .7 -.27 .76 -.64 .5 .12 1.2 .2 2.11 .2 s 1.61 -.08 2.11 -.2 c .06 .37 .38 .64 .76 .64 h 3.94 c .55 0 .87 -.59 .57 -1.05 l -1.4 -2.12 c .66 -.6 1.02 -1.46 1.02 -2.48 0 -1.55 -.85 -3.2 -1.83 -4.7 -.68 -1.05 -1.18 -1.82 -1.18 -2.6 0 -.6 .06 -1.35 .06 -2.3 0 -2.55 -1.6 -4.4 -4.05 -4.4 z M 10.3 4.5 c .53 0 .95 .6 .95 1.35 s -.42 1.35 -.95 1.35 s -.95 -.6 -.95 -1.35 s .42 -1.35 .95 -1.35 z M 13.7 4.5 c .53 0 .95 .6 .95 1.35 s -.42 1.35 -.95 1.35 s -.95 -.6 -.95 -1.35 s .42 -1.35 .95 -1.35 z M 12 7.55 c .94 0 1.7 .47 1.7 1.05 s -.76 1.05 -1.7 1.05 s -1.7 -.47 -1.7 -1.05 s .76 -1.05 1.7 -1.05 z"/></svg>',
  macos:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M16 3c0 2-2 4-4 4 0-2 2-4 4-4zM18 17c-1 2-2 4-4 4-1 0-2-1-3-1s-2 1-3 1c-2 0-4-3-5-6-1-4 1-8 4-8 1 0 2 1 3 1s2-1 3-1c2 0 3 1 4 3-3 2-3 6 1 7z"/></svg>',
  vbox:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/><circle cx="12" cy="10" r="2.4"/></svg>',
  vmware:'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 605 604" width="20" height="20"><g transform="matrix(2.014,0,0,2.014,-5.5,0)"><path fill="currentColor" d="M168.45 116.9Q181.4 120.85 185.4 133.85L185.4 182.3 230.2 182.15 230.2 99.95Q223.6 78.5 202.25 71.95L30.6 71.95Q9.25 78.475 2.65 99.95L2.65 272.75Q9.25 294.2 31.2 299.9L201.65 299.9Q223.6 294.2 230.2 272.75L230.2 227.7 185.4 227.7 185.4 238.55Q181.4 251.55 168.1 255L64.8 255Q51.5 251.55 47.5 238.55L47.5 133.85Q51.5 120.85 64.45 116.9Z"/><path fill="currentColor" opacity="0.75" d="M303.25 28Q296.65 6.55 275.3 0L103.65 0Q82.3 6.55 75.7 28L75.7 71.95 120.5 71.95 120.5 61.9Q124.5 48.9 137.45 44.95L241.45 44.95Q254.4 48.9 258.4 61.9L258.4 166.6Q254.4 179.6 241.1 183.05L137.8 183.05Q124.5 179.6 120.5 166.6L120.5 116.9 75.7 116.9 75.7 200.8Q82.3 222.25 104.25 227.95L274.7 227.95Q296.65 222.25 303.25 200.8Z"/></g></svg>',
  other:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="9"/><path d="M9.1 9a3 3 0 1 1 4.6 3.2c-.9.6-1.7 1-1.7 2.3M12 17h.01"/></svg>'
};
function selDepth(b){curDepth=b.dataset.p;document.querySelectorAll("#sbxWinConfigOpts .pbtn").forEach(function(x){x.classList.toggle("on",x===b);});}
function selOri(b){curOri=b.dataset.ori;document.querySelectorAll("#sbxOriSeg .pbtn").forEach(function(x){x.classList.toggle("on",x===b);});}

// Navigation groups reflect the workflow rather than repeating long page titles.
var TOOL_GROUPS=[
  {name:"Analyze",items:["full","minecraft","machine-code","firmware","sandbox"]},
  {name:"Transform",items:["decode","build","version-diff"]},
  {name:"Network",items:["web-scan","intercept"]}
];
if(window.MegaWasm){
  ["machine-code","firmware"].forEach(function(k){MODES[k].report=false;});
  TOOL_GROUPS=TOOL_GROUPS.map(function(group){return {name:group.name,items:group.items.filter(function(k){return window.MegaWasm.allowed.has(k);})};}).filter(function(group){return group.items.length;});
}
var TOOL_LABELS={minecraft:"Minecraft mods & packs",full:"Static analysis","machine-code":"Binary forensics",firmware:"Firmware & IoT",sandbox:"Dynamic analysis",decode:"Decode APK",build:"Build APK","version-diff":"Version diff","web-scan":"Server scan",intercept:"MITM proxy"};
// Interface language: nav + chrome only (page bodies stay English).
var TOOL_LABELS_RU={minecraft:"Майнкрафт-моды и паки",full:"Статический анализ","machine-code":"Анализ бинарей",firmware:"Прошивки и IoT",sandbox:"Динамический анализ",decode:"Декодировать APK",build:"Собрать APK","version-diff":"Сравнение версий","web-scan":"Сканирование сервера",intercept:"MITM-прокси"};
var GROUP_NAMES_RU={Analyze:"Анализ",Transform:"Преобразование",Network:"Сеть"};
var CHROME_RU={"New Analysis":"Новый анализ",Workspace:"Рабочая область"};
var uiLang="en";
try{uiLang=localStorage.getItem("ma-lang")||"en";}catch(err){}
if(uiLang!=="ru")uiLang="en";
function toolLabel(k){return uiLang==="ru"?(TOOL_LABELS_RU[k]||TOOL_LABELS[k]):TOOL_LABELS[k];}
function groupLabel(n){return uiLang==="ru"?(GROUP_NAMES_RU[n]||n):n;}
var MODE_RU={
  minecraft:{t:"Майнкрафт-моды и паки",s:"Java-моды, текстур-паки и дополнения Bedrock: метаданные, зависимости, вложенные архивы и статические индикаторы риска."},
  full:{t:"Полный статический анализ",s:"APK/DEX и JS/Hermes-бандлы: статический анализ, экспорт кода и файлы."},
  decode:{t:"Декодировать APK",s:"Декодирование APK/DEX в Smali и редактируемые ресурсы."},
  build:{t:"Собрать APK",s:"Сборка APK из ZIP проекта встроенным ассемблером и ресурсами."},
  "machine-code":{t:"Форенсика машинного кода",s:"Форенсика PE / ELF / .so бинарей через OmniSec."},
  firmware:{t:"Прошивки / IoT",s:"Анализ rootfs, архивов и образов прошивок."},
  "version-diff":{t:"Сравнение версий",s:"Сравнить старую сборку с новой."},
  sandbox:{t:"Динамический анализ",s:"Реальное выполнение и наблюдаемая активность на явно выбранном хосте или Android-устройстве."},
  "web-scan":{t:"Сканирование сервера",s:"Активное сканирование уязвимостей URL, который вам разрешено тестировать."},
  intercept:{t:"MITM-прокси",s:"Перехват и просмотр трафика приложения / игры через локальный прокси."}
};
function modeTitle(k){var m=MODES[k];if(!m)return k;return uiLang==="ru"?((MODE_RU[k]||{}).t||m.t):m.t;}
function modeSub(k){var m=MODES[k];if(!m)return "";return uiLang==="ru"?((MODE_RU[k]||{}).s||m.s):m.s;}
var MODE_BTN_RU={Decompile:"Декодировать APK",Decode:"Декодировать APK","Decode APK":"Декодировать APK","Build APK":"Собрать APK","Start analysis":"Начать анализ","Scan server":"Сканировать сервер","Start proxy":"Запустить прокси",Analyze:"Анализировать",Stop:"Стоп"};
function modeBtn(k){var m=MODES[k];var b=(m&&m.btn)||"Analyze";return uiLang==="ru"?(MODE_BTN_RU[b]||b):b;}
var MODE_INFO_RU={
  minecraft:"Читает содержимое пакета без запуска Minecraft. Поддерживает манифесты Fabric, Forge, NeoForge, Quilt и Bedrock. Полный отчёт не гарантирует безопасность.",
  decode:"Работает без Java, apktool и baksmali. Скачай ZIP результата, отредактируй проект и загрузи его в «Собрать APK». Сохрани скрытые файлы проекта для повторной сборки. Представление Java — псевдокод, а не компилируемые исходники.",
  build:"В ZIP нужен AndroidManifest.xml, Smali или готовый DEX и ресурсы. aapt2, android.jar, d8 и Java не требуются. Исходники Java/Kotlin не поддерживаются. APK получает отладочную подпись.",
  "version-diff":"Перетащи СТАРУЮ сборку в первую зону, а НОВУЮ во вторую, чтобы сравнить их.",
  sandbox:"Не виртуальная машина. Нативные файлы выполняются на хосте анализатора, Android-приложения на выбранном устройстве. Используй одноразовое внешне изолированное лабораторное окружение.",
  "web-scan":"Активное сканирование: запускай только против серверов, которыми владеешь или разрешено тестировать.",
  intercept:"Прокси слушает порт и перенаправляет на реальный сервер. Направь устройство/приложение на эту машину и этот порт, затем нажми Стоп: захваченный трафик сохранится автоматически."
};
function modeInfo(k){var m=MODES[k];if(!m||!m.info)return "";return uiLang==="ru"?(MODE_INFO_RU[k]||m.info):m.info;}
function applyLang(){
  document.documentElement.lang=uiLang==="ru"?"ru":"en";
  var lbl=document.getElementById("langLabel");if(lbl)lbl.textContent=uiLang==="ru"?"RU":"EN";
  document.querySelectorAll("#nav .tool").forEach(function(b){
    var k=b.dataset.mode,t=toolLabel(k);
    b.title=t;b.setAttribute("aria-label",t);
    var n=b.querySelector(".tool-n");if(n)n.textContent=t;
  });
  document.querySelectorAll("#nav .nav-lbl").forEach(function(el){el.textContent=groupLabel(el.dataset.group||el.textContent);});
  var na=document.querySelector("#sidebar .new-btn:not(#workspaceOpen) .new-btn-label");if(na)na.textContent=uiLang==="ru"?"Новый анализ":"New Analysis";
  var wsBtn=document.querySelector("#workspaceOpen .new-btn-label");if(wsBtn)wsBtn.textContent=uiLang==="ru"?"Мой компьютер":"My Computer";
  var ws=document.querySelector(".workspace-name");if(ws)ws.textContent=uiLang==="ru"?"Рабочая область":"Workspace";
  if(window.MegaWasm){
    if(wsBtn)wsBtn.textContent=uiLang==="ru"?"Файлы вкладки":"Tab files";
    if(window.MegaBrowserNotice)window.MegaBrowserNotice.setLanguage(uiLang);
  }
  var m=MODES[curMode];if(m){uiText("toolTitle",modeTitle(curMode));uiText("toolSub",modeSub(curMode));uiText("sbtn-t",modeBtn(curMode));if(m.info)uiText("minfo-t",modeInfo(curMode));}
  applyPageLang();
  var netMirror=document.getElementById("sbxNetToggle");if(netMirror)uiText("sbxNetToggleState",pageT(netMirror.checked?"on":"off"));
  if(window.WorkspaceI18n&&window.WorkspaceI18n.apply)window.WorkspaceI18n.apply();
  syncWorkspaceUI();
}
function cycleLang(){uiLang=uiLang==="ru"?"en":"ru";try{localStorage.setItem("ma-lang",uiLang);}catch(err){}applyLang();}
// Static page strings: data-i18n="key" in index.html. Sandbox workbench
// internals stay English for now (separate task).
var PAGE_I18N={
  activityTitle:{en:"Activity",ru:"Активность"},
  activityCategory:{en:"Category",ru:"Категория"},
  activityAll:{en:"All",ru:"Всё"},
  activityFiles:{en:"Files",ru:"Файлы"},
  activityFolders:{en:"Folders",ru:"Папки"},
  activityProcesses:{en:"Processes",ru:"Процессы"},
  activityNetwork:{en:"Network",ru:"Сеть"},
  activitySession:{en:"Session",ru:"Сессия"},
  activityCoverage:{en:"Coverage",ru:"Покрытие"},
  activityPause:{en:"Pause view",ru:"Пауза просмотра"},
  activityResume:{en:"Resume view",ru:"Продолжить просмотр"},
  activityPreview:{en:"Latest 1,000 observations. Full journal: activity.jsonl in the session folder, up to 64 MiB.",ru:"Последние 1 000 наблюдений. Журнал: activity.jsonl в папке сессии, до 64 МиБ."},
  activityEmpty:{en:"Real observations appear here during analysis.",ru:"Здесь появятся реальные наблюдения во время анализа."},
  sessionDuration:{en:"Session duration",ru:"Длительность сессии"},
  untilStopped:{en:"Until stopped",ru:"До остановки"},
  optionalTimer:{en:"With a timer",ru:"С таймером"},
  vmwareScreenWaiting:{en:"Waiting for the VMware screen",ru:"Ожидаю экран VMware"},
  vmwareScreenHelp:{en:"Click the guest screen to use the mouse and keyboard. Switching to Output releases control.",ru:"Нажмите на экран гостя для управления мышью и клавиатурой. Переход в Output освобождает управление."},
  durationSeconds:{en:"Seconds",ru:"Секунды"},
  durationManualHint:{en:"Observation continues after the sample exits, until you press Stop. If the guest shuts down or collection is interrupted, received events remain saved on the host. Resource limits still apply.",ru:"Наблюдение продолжается после выхода образца до нажатия «Стоп». При выключении гостя или прерывании сбора полученные события остаются на основном ПК. Лимиты ресурсов остаются."},
  durationTimedHint:{en:"Auto-stop after the selected number of seconds. No 10-minute cap.",ru:"Автоостановка через указанное число секунд. Потолка в 10 минут нет."},
  decodeOptions:{en:"Decoded project",ru:"Декодированный проект"},
  nativeJavaViewD:{en:"Add readable Java pseudocode alongside Smali; for inspection only",ru:"Добавить читаемый псевдокод Java рядом со Smali для изучения"},
  buildOptions:{en:"APK packaging",ru:"Упаковка APK"},
  buildNameHint:{en:"Letters, numbers, _ and -; up to 80 characters. Spaces and other symbols become _. Add .xapk for an XAPK.",ru:"Буквы, цифры, _ и -; до 80 символов. Пробелы и другие знаки заменяются на _. Для XAPK укажи расширение .xapk."},
  buildCompression:{en:"Compression",ru:"Сжатие"},
  compressionFast:{en:"Fast",ru:"Быстрое"},
  compressionBalanced:{en:"Balanced",ru:"Сбалансированное"},
  compressionBest:{en:"Smallest file",ru:"Минимальный размер"},
  buildUnsigned:{en:"Skip signing",ru:"Не подписывать"},
  buildUnsignedD:{en:"Create an unsigned APK for a separate signing step; it cannot be installed directly",ru:"Создать неподписанный APK для отдельной подписи; сразу установить его нельзя"},
  buildProject:{en:"Project ZIP",ru:"ZIP проекта"},
  buildChoose:{en:"Choose a project ZIP to build",ru:"Выбери ZIP проекта для сборки"},
  decodeChoose:{en:"Choose an APK or DEX to decode",ru:"Выбери APK или DEX для декодирования"},
  buildHint:{en:"AndroidManifest.xml · Smali / DEX · resources",ru:"AndroidManifest.xml · Smali / DEX · ресурсы"},
  buildReady:{en:"Ready to build APK",ru:"Готово к сборке APK"},
  decodeReady:{en:"Ready to decode",ru:"Готово к декодированию"},
  bundleT:{en:"JS / Hermes bundles",ru:"JS / Hermes-бандлы"},
  bundleBudget:{en:"Hermes export budget",ru:"Бюджет экспорта Hermes"},
  budgetLarge:{en:"Large: 100k functions / 512 MiB text",ru:"Большой: 100 тыс. функций / 512 МиБ текста"},
  budgetCompact:{en:"Compact: 5k functions / 64 MiB text",ru:"Компактный: 5 тыс. функций / 64 МиБ текста"},
  bundleExport:{en:"Export bundle code / disassembly",ru:"Экспорт кода / дизассемблирования бандлов"},
  bundleExportD:{en:"Text JS → deobfuscated.js; Hermes → disassembly + metadata, NOT original JS",ru:"Текстовый JS → deobfuscated.js; Hermes → дизассемблирование и метаданные, НЕ исходный JS"},
  bundlePatches:{en:"JS patch candidates (dry-run)",ru:"Кандидаты JS-патчей (без применения)"},
  bundlePatchesD:{en:"Download Markdown + JSON; Hermes scan-only, original never modified",ru:"Скачать Markdown и JSON; Hermes — только сканирование, оригинал не меняется"},
  saveDecoded:{en:"Save decoded APK / DEX",ru:"Сохранить декодированный APK / DEX"},
  saveDecodedD:{en:"Write Smali + decoded resources to decoded/ alongside reports; APK/DEX input only",ru:"Smali и декодированные ресурсы в decoded/ рядом с отчётами; только APK/DEX и архивы"},
  javaView:{en:"Java pseudocode view",ru:"Псевдокод Java"},
  javaViewD:{en:"Requires Save decoded APK or Decode mode; not original Java source",ru:"Требует сохранения декодированного APK или режима Декодировать APK; не исходный Java"},
  noResources:{en:"Skip resource decoding",ru:"Не декодировать ресурсы"},
  noResourcesD:{en:"For decoded output only; analysis is unchanged",ru:"Только для декодированного вывода; не меняет анализ"},
  copyOriginal:{en:"Copy original APK metadata",ru:"Копировать исходные метаданные APK"},
  copyOriginalD:{en:"Include original META-INF / unknown files in decoded output",ru:"Включить исходные META-INF и прочие файлы в декодированный вывод"},
  dzSample:{en:"Start with a sample",ru:"Начни с образца"},
  dzChoose:{en:"Choose a file to analyze",ru:"Выбери файл для анализа"},
  dzDrag:{en:"Drag it here, or browse your files.",ru:"Перетащи его сюда или выбери файлы."},
  dzBrowse:{en:"Browse files",ru:"Выбрать файлы"},
  dzFormats:{en:"Supported formats listed above",ru:"Поддерживаемые форматы выше"},
  dzMax:{en:"Maximum 512 MB",ru:"Максимум 512 МБ"},
  dzTarget:{en:"Target file",ru:"Целевой файл"},
  dzOriginal:{en:"Original build",ru:"Исходная сборка"},
  dzNew:{en:"Drop the new build",ru:"Перетащи новую сборку"},
  dzNewSub:{en:"the updated APK / DEX to diff against",ru:"обновлённый APK / DEX для сравнения"},
  dzNewLbl:{en:"New build (compare against)",ru:"Новая сборка (для сравнения)"},
  targetUrl:{en:"Target URL",ru:"Целевой URL"},
  authLbl:{en:"I am authorised to scan this target",ru:"Я вправе сканировать эту цель"},
  authDesc:{en:"Required — only scan servers you own or have permission to test",ru:"Обязательно: сканируй только серверы, которыми владеешь или разрешено тестировать"},
  labLbl:{en:"Lab Mode",ru:"Лабораторный режим"},
  labDesc:{en:"Destructive lab-only features (OAST, request smuggling)",ru:"Разрушительные функции только для лаборатории (OAST, request smuggling)"},
  proxyLbl:{en:"Proxy settings",ru:"Настройки прокси"},
  listenLbl:{en:"Listen port",ru:"Порт прослушивания"},
  realLbl:{en:"Real server",ru:"Реальный сервер"},
  profilesLbl:{en:"Analysis profile",ru:"Профиль анализа"},
  depthNote:{en:"Depth & estimated time",ru:"Глубина и примерное время"},
  profQuick:{en:"Quick",ru:"Quick"},
  profQuickD:{en:"Critical patterns only",ru:"Только критические паттерны"},
  profBal:{en:"Balanced",ru:"Balanced"},
  profBalD:{en:"Recommended default",ru:"Рекомендуется по умолчанию"},
  profDeep:{en:"Deep",ru:"Deep"},
  profDeepD:{en:"Call graph + full pass",ru:"Граф вызовов и полный проход"},
  profPar:{en:"Paranoid",ru:"Paranoid"},
  profParD:{en:"Maximum depth",ru:"Максимальная глубина"},
  modulesT:{en:"Modules & output",ru:"Модули и вывод"},
  modulesS:{en:"Engines, MobSF, insights and export options",ru:"Движки, MobSF, инсайты и экспорт"},
  enginesT:{en:"Analysis Engines",ru:"Движки анализа"},
  mCallgraph:{en:"Call Graph",ru:"Граф вызовов"},
  mCallgraphD:{en:"Method call tree for deeper detection",ru:"Дерево вызовов методов для глубокого детекта"},
  mCorr:{en:"Cross-file Correlations",ru:"Межфайловые корреляции"},
  mCorrD:{en:"Patterns spanning multiple files",ru:"Паттерны на несколько файлов"},
  mDeep:{en:"Deep Bytecode Scan",ru:"Глубокое сканирование байткода"},
  mDeepD:{en:"Instruction-level analysis pass",ru:"Проход на уровне инструкций"},
  mBundle:{en:"Medium Bundle",ru:"Средний набор"},
  mBundleD:{en:"Play Store, SBOM, certs, perms, NIAP",ru:"Play Store, SBOM, сертификаты, права, NIAP"},
  mobsfT:{en:"MobSF Suite",ru:"Набор MobSF"},
  mAll:{en:"Enable All MobSF",ru:"Включить весь MobSF"},
  mAllD:{en:"Turns on the 5 modules below",ru:"Включает 5 модулей ниже"},
  mSast:{en:"SAST Rules",ru:"SAST-правила"},
  mSastD:{en:"CWE / OWASP / MASVS findings",ru:"Находки CWE / OWASP / MASVS"},
  mTrack:{en:"Trackers",ru:"Трекеры"},
  mTrackD:{en:"Exodus Privacy database",ru:"База Exodus Privacy"},
  mNsc:{en:"NSC Audit",ru:"NSC-аудит"},
  mManifest:{en:"Manifest Audit",ru:"Аудит манифеста"},
  mManifestD:{en:"Exported components, debuggable",ru:"Экспортированные компоненты, debuggable"},
  mApkid:{en:"APKiD",ru:"APKiD"},
  mApkidD:{en:"Packer / obfuscator fingerprint",ru:"Отпечаток упаковщика / обфускатора"},
  insT:{en:"Insight Modules",ru:"Модули инсайтов"},
  mTop5:{en:"Top-5 Bundle",ru:"Набор Топ-5"},
  mTop5D:{en:"JNI + privacy + graph in one",ru:"JNI, приватность и граф в одном"},
  mJni:{en:"JNI Bridge",ru:"JNI-мост"},
  mJniD:{en:"Java / DEX to native mapping",ru:"Связь Java / DEX с нативом"},
  mPriv:{en:"Privacy Score",ru:"Оценка приватности"},
  mPrivD:{en:"Sources / sinks, tracker SDKs",ru:"Источники / стоки, трекерные SDK"},
  mGraph:{en:"Graph Explorer",ru:"Обозреватель графа"},
  mGraphD:{en:"Interactive dependency graph",ru:"Интерактивный граф зависимостей"},
  mPatch:{en:"ML Smali Patcher",ru:"ML-патчер Smali"},
  mPatchD:{en:"Auto patch-point candidates",ru:"Автокандидаты точек патча"},
  outT:{en:"Output Options",ru:"Опции вывода"},
  mSarif:{en:"SARIF Output",ru:"Вывод SARIF"},
  mSarifD:{en:"For GitHub / GitLab scanning",ru:"Для сканирования GitHub / GitLab"},
  mArt:{en:"Artifacts Panel",ru:"Панель артефактов"},
  mArtD:{en:"Extract images / models / .so",ru:"Извлечение картинок / моделей / .so"},
  mFp:{en:"FP Strict Mode",ru:"Строгий режим FP"},
  mFpD:{en:"Confirmed app / SDK risks only",ru:"Только подтверждённые риски приложения / SDK"},
  mBlur:{en:"No Image Blur",ru:"Без блюра картинок"},
  mBlurD:{en:"Disable blur on sensitive images",ru:"Отключить блюр чувствительных картинок"},
  mGame:{en:"Game Mode",ru:"Игровой режим"},
  mGameD:{en:"XP, threat scoring, ranks",ru:"XP, оценка угроз, ранги"},
  repT:{en:"Report & performance",ru:"Отчёт и производительность"},
  repS:{en:"Format, workers and execution limits",ru:"Формат, воркеры и лимиты выполнения"},
  repFmt:{en:"Report Format",ru:"Формат отчёта"},
  workers:{en:"Workers",ru:"Воркеры"},
  workersD:{en:"0 = auto (CPU cores)",ru:"0 = авто (ядра CPU)"},
  timeout:{en:"Timeout",ru:"Таймаут"},
  timeoutD:{en:"0 = no limit",ru:"0 = без лимита"},
  fpMin:{en:"FP Min Score",ru:"Мин. скор FP"},
  fpMinD:{en:"-1 = profile default",ru:"-1 = default профиля"},
  saveT:{en:"Save results",ru:"Сохранить результаты"},
  saveS:{en:"Each scan gets its own persistent folder",ru:"Каждое сканирование получает свою папку"},
  resName:{en:"Result name",ru:"Имя результата"},
  resNamePh:{en:"e.g. minecraft (display name; scans never overwrite each other)",ru:"например minecraft (имя для показа; сканы не перезаписывают друг друга)"},
  apkNamePh:{en:"e.g. minecraft.apk or minecraft.xapk",ru:"например minecraft.apk или minecraft.xapk"},
  wsFolder:{en:"Workspace folder",ru:"Папка воркспейса"},
  wsFolderPh:{en:"Scans (default) — or a relative folder such as Projects/MyMod",ru:"Scans (по умолчанию) или относительная папка вроде Projects/MyMod"},
  noFile:{en:"No file selected",ru:"Файл не выбран"},
  chooseTarget:{en:"Choose a target file to begin.",ru:"Выбери целевой файл для начала."},
  readyAnalyze:{en:"Ready to analyze",ru:"Готов к анализу"},
  bothBuilds:{en:"Both builds selected · Ready to compare",ru:"Обе сборки выбраны · Готов сравнить"},
  selectBoth:{en:"Select the original and new builds to compare.",ru:"Выбери исходную и новую сборки для сравнения."},
  analyzeBtn:{en:"Analyze",ru:"Анализировать"},
  consent:{en:"I am using a disposable analysis host / device. I understand that execution is real, is not a VM-isolated sandbox, and a malicious sample can crash this machine (including BSOD).",ru:"Я использую одноразовый хост / устройство для анализа. Понимаю, что выполнение реально, это не изолированная ВМ-песочница, и вредоносный сэмпл может уронить эту машину (включая BSOD)."},
  vmwareConsent:{en:"Run this file in the selected disposable Windows VM. Keep the analysis report on this PC.",ru:"Запустить этот файл в выбранной тестовой Windows-ВМ. Сохранить отчёт на основном ПК."},
  internet:{en:"Internet:",ru:"Интернет:"},
  off:{en:"off",ru:"выкл"},
  on:{en:"on",ru:"вкл"},
  defaults:{en:"Defaults",ru:"По умолчанию"},
  defaultReport:{en:"Default report",ru:"Отчёт по умолчанию"},
  wsScans:{en:"Workspace / Scans",ru:"Воркспейс / Сканы"},
  selected:{en:"selected",ru:"выбрано"},
  reportWord:{en:"report",ru:"отчёт"},
  decodeBtn:{en:"Decode APK",ru:"Декодировать APK"},
  scanServerBtn:{en:"Scan server",ru:"Сканировать сервер"},
  startAnalysisBtn:{en:"Start analysis",ru:"Начать анализ"},
  startProxyBtn:{en:"Start proxy",ru:"Запустить прокси"}
};
if(window.MegaWasm){
  PAGE_I18N.dzMax={en:"Maximum 512 MB",ru:"Максимум 512 МБ"};
  PAGE_I18N.saveS={en:"In tab memory — download before reloading",ru:"В памяти вкладки — скачайте перед обновлением"};
  PAGE_I18N.depthNote={en:"Analysis depth",ru:"Глубина анализа"};
  PAGE_I18N.workersD={en:"1–4 browser workers",ru:"1–4 браузерных воркера"};
  PAGE_I18N.timeoutD={en:"Seconds · 0 = no timeout",ru:"Секунды · 0 = без таймаута"};
  document.querySelectorAll(".p-time").forEach(function(el){el.hidden=true;});
  ["w","t"].forEach(function(id){
    var r=document.getElementById(id+"-r"),key="ma-browser-"+(id==="w"?"workers":"timeout"),fallback=id==="w"?2:300;
    r.disabled=false;r.min=id==="w"?"1":"0";r.max=id==="w"?"4":"3600";r.step="1";
    var saved=fallback;try{var stored=localStorage.getItem(key);if(stored!==null)saved=Number(stored);}catch(err){}
    if(!Number.isInteger(saved)||saved<+r.min||saved>+r.max)saved=fallback;r.value=String(saved);
    var number=document.createElement("input");number.type="number";number.id=id+"-d";number.className="rval browser-number";
    number.min=r.min;number.max=r.max;number.step="1";number.value=r.value;number.dataset.i18nAria=id==="w"?"workers":"timeout";number.setAttribute("aria-label",id==="w"?"Browser worker count":"Timeout in seconds");
    document.getElementById(id+"-d").replaceWith(number);
    function save(){try{localStorage.setItem(key,r.value);}catch(err){}}
    number.addEventListener("input",function(){var n=Number(number.value);if(number.value!==""&&Number.isInteger(n)&&n>=+r.min&&n<=+r.max){r.value=number.value;save();syncR(id);}});
    number.addEventListener("change",function(){var n=Number(number.value);r.value=String(Number.isFinite(n)?Math.max(+r.min,Math.min(+r.max,Math.round(n))):fallback);number.value=r.value;save();syncR(id);});
    r.addEventListener("input",save);
  });
}
function pageT(k){var e=PAGE_I18N[k];if(!e)return k;return uiLang==="ru"?e.ru:e.en;}
function applyPageLang(){
  syncSandboxDuration();
  document.querySelectorAll("[data-i18n]").forEach(function(el){el.textContent=pageT(el.dataset.i18n);});
  document.querySelectorAll("[data-i18n-ph]").forEach(function(el){el.placeholder=pageT(el.dataset.i18nPh);});
  document.querySelectorAll("[data-i18n-aria]").forEach(function(el){el.setAttribute("aria-label",pageT(el.dataset.i18nAria));});
}
(function(){
  var nav=document.getElementById("nav");
  TOOL_GROUPS.forEach(function(group){
    var section=document.createElement("div");section.className="nav-group";
    var label=document.createElement("div");label.className="nav-lbl";label.dataset.group=group.name;label.textContent=groupLabel(group.name);section.appendChild(label);
    group.items.forEach(function(k){
      var b=document.createElement("button");b.type="button";
      b.className="tool"+(k==="full"?" on":"");b.dataset.mode=k;
      b.title=toolLabel(k);b.setAttribute("aria-label",toolLabel(k));
      b.innerHTML="<svg viewBox='0 0 24 24' aria-hidden='true'>"+TOOL_ICO[k]+"</svg><span class='tool-n'>"+toolLabel(k)+"</span>";
      b.onclick=function(){selTool(k);};section.appendChild(b);
    });
    nav.appendChild(section);
  });
})();

function show(id,on){var el=document.getElementById(id);if(el)el.style.display=on?"":"none";}

// envRow carries the Detonation Parameters and Target Environment columns, and
// both of them belong to the sandbox tool alone. Three call sites used to put
// the row back with an unconditional truthy show() once a job ended, so ending a
// Full Static Analysis scan revealed the sandbox configuration underneath a
// static report -- and the row then "disappeared" on the next page load, which
// was in fact the only correct state of the two. Visibility is now derived from
// the active tool in exactly one place, so the row can only ever appear where
// it means something.
function syncEnvRow(){var m=MODES[curMode];show("envRow",!!m&&m.panel==="sandbox");}

// Mobile navigation: focus stays inside the drawer; Escape restores the trigger.
var drawerLastFocus=null;
function setMenuOpen(open){
  var side=document.getElementById("sidebar"),main=document.getElementById("mainContent"),trigger=document.getElementById("menuBtn");
  var mobile=window.innerWidth<=880;
  open=!!open&&mobile;
  if(open&&!side.classList.contains("open"))drawerLastFocus=document.activeElement;
  var wasOpen=side.classList.contains("open");
  side.classList.toggle("open",open);
  document.getElementById("overlay").classList.toggle("show",open);
  document.body.classList.toggle("menu-open",open);
  trigger.setAttribute("aria-expanded",String(open));
  trigger.setAttribute("aria-label",open?"Close menu":"Open menu");
  main.inert=open;side.inert=mobile&&!open;
  if(open){var first=side.querySelector(".drawer-close");if(first)first.focus();}
  else if(wasOpen&&mobile&&drawerLastFocus){drawerLastFocus.focus();}
}
function toggleMenu(){setMenuOpen(!document.getElementById("sidebar").classList.contains("open"));}
function closeMenu(){setMenuOpen(false);}

function selTool(k){
  if(window.MegaWasm&&!window.MegaWasm.allowed.has(k))k="full";
  if(running){stopJob();running=false;}
  invalidateScanView();
  if(curMode==="sandbox"){if(sbxTimerInterval){clearInterval(sbxTimerInterval);sbxTimerInterval=null;}document.body.classList.remove("sbx-running");sbxRunSerial++;jid=null;}
  curMode=k;var m=MODES[k],p=m.panel;
  mountSandboxWorkbench(k==="sandbox");
  if(k==="sandbox")sbxSetPhase("setup");
  document.querySelectorAll(".tool").forEach(function(t){t.classList.toggle("on",t.dataset.mode===k);if(t.dataset.mode===k)t.setAttribute("aria-current","page");else t.removeAttribute("aria-current");});
  document.getElementById("toolTitle").textContent=modeTitle(k);
  document.getElementById("toolSub").textContent=modeSub(k);
  if(m.accept){document.getElementById("fi").accept=m.accept;document.getElementById("fi2").accept=m.accept;}
  document.getElementById("dz1lbl").firstChild.textContent=p==="diff"?pageT("dzOriginal")+" ":pageT("dzTarget")+" ";
  var fm=document.getElementById("fmts");fm.innerHTML="";
  (m.fmts||[]).forEach(function(f){var s=document.createElement("span");s.className="dz-fmt";s.textContent=f;fm.appendChild(s);});
  // panels
  show("dz1wrap",!m.fileless);
  show("dz2wrap",p==="diff");
  show("urlRow",p==="webscan");
  show("connRow",p==="mitm");
  syncEnvRow();
  show("profiles",p==="full");
  show("settingsGrid",p==="full");
  show("tuning",p==="full"||p==="tune");
  show("fpWrap",p==="full");
  show("decodeSettings",p==="decode");
  show("buildSettings",p==="build");
  var nameRow=document.getElementById("resultNameRow");
  if(nameRow){
    var nameSlot=document.getElementById(p==="build"?"buildNameSlot":"savedOutputBody");
    nameSlot.insertBefore(nameRow,nameSlot.firstChild);
    var nameInput=document.getElementById("outname");
    nameInput.setAttribute("data-i18n-ph",p==="build"?"apkNamePh":"resNamePh");
    nameInput.placeholder=pageT(p==="build"?"apkNamePh":"resNamePh");
    if(p==="build")nameInput.setAttribute("aria-describedby","buildNameHint");
    else nameInput.removeAttribute("aria-describedby");
  }
  show("outRow",k!=="intercept");
  // info
  var mi=document.getElementById("minfo");
  if(m.info){document.getElementById("minfo-t").textContent=modeInfo(k);mi.classList.add("show");}
  else{mi.classList.remove("show");}
  // button
  document.getElementById("sbtn-t").textContent=modeBtn(k);
  document.getElementById("sbtn").classList.remove("stop");
  clearFile(1);clearFile(2);
  document.getElementById("prog").classList.remove("show");
  document.getElementById("res").classList.remove("show");
  document.getElementById("liveSbxDash").style.display="none";
  liveStop();var _lv=document.getElementById("live");if(_lv)_lv.classList.remove("show");
  if(k==="sandbox"){buildOsMenu();prepareSandboxWorkspace();}
  refreshBtn();
  setTimeout(moveSeg,0);
  if(window.innerWidth<=880)closeMenu();
  // Update browser URL so each tool has its own shareable path.
  var slug=(TOOL_SLUG.hasOwnProperty(k)?TOOL_SLUG[k]:k);
  if(history.pushState){
    var newPath="/"+slug;
    if(location.pathname!==newPath)history.pushState({tool:k},"",newPath);
  }
}

function resetAll(){if(curMode==="sandbox"){sbxNewAnalysis();return;}selTool("full");document.getElementById("outdir").value="";window.scrollTo({top:0,behavior:preferredScrollBehavior()});}

// ── drag & drop ──
var MAX_UPLOAD_BYTES=512*1024*1024; // synced from /api/meta

// Validates a candidate file against the current mode's accepted extensions and
// the server's upload size cap *before* it is ever sent, so drag-and-drop gets
// the same up-front feedback as the native file picker's accept="" filter
// instead of failing only after a full upload with a generic error.
function fileValidationError(f,which){
  var m=MODES[curMode];
  var accept=(m&&m.accept)||"";
  if(accept){
    var exts=accept.split(",").map(function(s){return s.trim().toLowerCase();}).filter(Boolean);
    var name=(f.name||"").toLowerCase();
    var ok=exts.some(function(ext){return name.slice(-ext.length)===ext;});
    if(!ok)return "Unsupported file type \""+(f.name||"")+"\". Accepted: "+exts.join(", ")+".";
  }
  if(f.size>MAX_UPLOAD_BYTES)return "File is "+fb(f.size)+", which exceeds the "+Math.round(MAX_UPLOAD_BYTES/1048576)+" MB upload limit.";
  return null;
}
function dzErrEl(which){return document.getElementById(which===2?"dzErr2":"dzErr");}
function showDzErr(which,msg){
  var el=dzErrEl(which);
  if(!el)return;
  if(msg){el.textContent=msg;el.classList.add("show");}
  else{el.textContent="";el.classList.remove("show");}
}
function tryAcceptFile(f,which){
  var err=fileValidationError(f,which);
  if(err){showDzErr(which,err);return;}
  showDzErr(which,null);
  setf(f,which);
}
function bindDrop(dzId,which){
  var dz=document.getElementById(dzId);
  dz.addEventListener("dragover",function(e){e.preventDefault();dz.classList.add("over");});
  dz.addEventListener("dragleave",function(){dz.classList.remove("over");});
  dz.addEventListener("drop",function(e){e.preventDefault();dz.classList.remove("over");if(e.dataTransfer.files.length)tryAcceptFile(e.dataTransfer.files[0],which);});
}
bindDrop("dz",1);bindDrop("dz2",2);
document.getElementById("fi").addEventListener("change",function(){if(this.files.length)tryAcceptFile(this.files[0],1);});
document.getElementById("fi2").addEventListener("change",function(){if(this.files.length)tryAcceptFile(this.files[0],2);});

function fb(n){if(n<1024)return n+" B";if(n<1048576)return(n/1024).toFixed(1)+" KB";return(n/1048576).toFixed(1)+" MB";}

function setf(f,which){
  if(!running)invalidateScanView();
  if(which===2){sf2=f;document.getElementById("pname2").textContent=f.name;document.getElementById("psize2").textContent=fb(f.size);document.getElementById("fpill2").classList.add("show");}
  else{
    sf=f;document.getElementById("pname").textContent=f.name;document.getElementById("psize").textContent=fb(f.size);document.getElementById("fpill").classList.add("show");
    if(f&&f.name){
      var base=f.name.replace(/\.[^/.]+$/,"");
      ["outname"].forEach(function(id){
        var el=document.getElementById(id);
        if(el&&!el.value)el.placeholder=base;
      });
    }
  }
  document.getElementById("res").classList.remove("show");
  if(curMode==="sandbox"&&which===1){document.getElementById("sbxConsent").checked=false;buildOsMenu();}
  syncStaticOutputFlags();
  refreshBtn();
}
function safeResultBase(value,fallback){
  var chars=Array.from(String(value||"").normalize("NFC").replace(/\.(zip|apk|xapk)$/i,"").replace(/[^\p{L}\p{N}_-]/gu,"_").replace(/_+/g,"_").replace(/^[_-]+|[_-]+$/g,""));
  var base="",bytes=0;
  chars.slice(0,80).some(function(c){var size=encodeURIComponent(c).replace(/%[0-9A-F]{2}|./g,"x").length;if(bytes+size>160)return true;base+=c;bytes+=size;return false;});
  if(!base)base=fallback||"app";
  if(/^(con|prn|aux|nul|com[0-9]|lpt[0-9])$/i.test(base))base="_"+base;
  return base;
}
function buildResultName(){
  var input=document.getElementById("outname"),value=input.value;
  var ext=/\.xapk$/i.test(value)?".xapk":".apk";
  var name=safeResultBase(value||(sf&&sf.name),"app")+ext;
  input.value=name;
  return name;
}
document.getElementById("outname").addEventListener("blur",function(){if(curMode==="build"&&this.value)buildResultName();});
function clearFile(which){
  if(!running)invalidateScanView();
  if(which===2){sf2=null;document.getElementById("fi2").value="";document.getElementById("fpill2").classList.remove("show");}
  else{sf=null;document.getElementById("fi").value="";document.getElementById("fpill").classList.remove("show");}
  showDzErr(which,null);
  syncStaticOutputFlags();
  refreshBtn();
}
function refreshBtn(){
  var m=MODES[curMode],sb=document.getElementById("sbtn");
  if(running){sb.disabled=false;syncWorkspaceUI();return;}
  var ok;
  if(m.fileless){
    if(curMode==="web-scan"){var u=(document.getElementById("scanUrl").value||"").trim();ok=/^https?:\/\//.test(u)&&u.length>10&&document.getElementById("ownChk").checked;}
    else if(curMode==="intercept"){ok=(document.getElementById("mitmUp").value||"").trim().length>0;}
    else ok=true;
  }else{
    ok=!!sf&&(curMode!=="version-diff"||!!sf2);
    if(curMode==="sandbox")ok=ok&&!!curTarget&&curTarget.runnable;
    if(curMode==="sandbox")ok=ok&&sandboxConsentReady()&&Number.isFinite(sandboxDurationSeconds());
    if(curMode==="sandbox"&&isVMwareTarget())ok=ok&&vmwareExecutionReady();
  }
  sb.disabled=!ok;
  syncWorkspaceUI();
}

function selProfile(c){document.querySelectorAll(".pcard").forEach(function(x){x.classList.toggle("on",x===c);x.setAttribute("aria-pressed",String(x===c));});syncWorkspaceUI();}
function selSeg(b){document.querySelectorAll(".sbtn").forEach(function(x){x.classList.remove("on");x.setAttribute("aria-pressed","false");});b.classList.add("on");b.setAttribute("aria-pressed","true");moveSeg();syncWorkspaceUI();}

// Sliding indicator under the active Report-Format segment.
// Animating transform instead of left keeps the whole move on the compositor.
// The segments are flex:1 so the width never actually changes after first
// paint, which means no layout work per frame and no jitter on a phone.
var _segReady=false;
function moveSeg(){
  var on=document.querySelector(".sbtn.on"),ind=document.getElementById("segInd");
  if(!on||!ind||on.offsetWidth===0)return;
  if(!_segReady)ind.style.transition="none"; // never slide in from zero on load
  ind.style.width=on.offsetWidth+"px";
  ind.style.transform="translate3d("+on.offsetLeft+"px,0,0)";
  if(!_segReady){void ind.offsetWidth;ind.style.transition="";_segReady=true;}
}

// 0 is an explicit no-deadline mode, not a missing/default value.
function sandboxDurationSeconds(){
  if(document.getElementById("sbxDurationMode").value==="manual")return 0;
  var raw=document.getElementById("sbx-r").value;
  var n=Number(raw);
  return /^\d+$/.test(raw)&&Number.isSafeInteger(n)&&n>=5&&n<=9223372036?n:NaN;
}
function syncSandboxDuration(){
  var manual=document.getElementById("sbxDurationMode").value==="manual";
  document.getElementById("sbxDurationFields").hidden=manual;
  var input=document.getElementById("sbx-r");input.disabled=manual;
  input.setCustomValidity(manual||Number.isFinite(sandboxDurationSeconds())?"":(uiLang==="ru"?"Введи целое число секунд, не меньше 5.":"Enter a whole number of seconds, at least 5, within the supported duration range."));
  var hint=document.getElementById("sbxDurationHint");
  hint.dataset.i18n=manual?"durationManualHint":"durationTimedHint";hint.textContent=pageT(hint.dataset.i18n);
  if(curMode==="sandbox")refreshBtn();
}
function formatSandboxElapsed(seconds){
  seconds=Math.max(0,Math.floor(seconds));
  var h=Math.floor(seconds/3600),m=Math.floor(seconds/60)%60,s=seconds%60;
  return (h?h+":"+String(m).padStart(2,"0"):String(m).padStart(2,"0"))+":"+String(s).padStart(2,"0");
}
function fillRange(r){var mn=+r.min,mx=+r.max,v=+r.value,p=mx>mn?((v-mn)/(mx-mn))*100:0;r.style.setProperty("--range-progress",p+"%");}
function syncR(id){
  if(id==="sbx"){syncSandboxDuration();return;}
  var r=document.getElementById(id+"-r"),d=document.getElementById(id+"-d"),v=r.value;
  if(d.tagName==="INPUT")d.value=v;
  else if(id==="w")d.textContent=(v==="0")?"auto":v;
  else if(id==="t")d.textContent=(v==="0")?"∞":v+" s";
  else if(id==="fp")d.textContent=(v==="-1")?"auto":v;
  else if(id==="sbx"){var sec=parseInt(v);if(sec<60)d.textContent=sec+" s";else if(sec%60===0)d.textContent=(sec/60)+" min";else d.textContent=Math.floor(sec/60)+"m "+(sec%60)+"s";}
  else if(id==="sbxcpu")d.textContent=(v==="1")?"1 core":v+" cores";
  else if(id==="sbxram")d.textContent=v+" MB";
  fillRange(r);
  r.setAttribute("aria-valuetext",d.tagName==="INPUT"?(id==="t"&&v==="0"?"No timeout":v):d.textContent);
  syncWorkspaceUI();
}

// ── dependency wiring (mobsf-all → 5, top5 → 3) ──
function dep(parent,kids){
  var p=document.querySelector("input.fg[data-f='"+parent+"']");if(!p)return;
  kids.forEach(function(fk){
    var c=document.querySelector("input.fg[data-f='"+fk+"']");if(!c)return;
    var row=c.closest(".tr");
    if(p.checked){c.checked=true;c.disabled=true;if(row)row.classList.add("implied");}
    else{c.disabled=false;if(row)row.classList.remove("implied");}
  });
}
function applyDeps(){
  dep("-mobsf-all",["-sast-rules","-trackers","-nsc-audit","-manifest-audit","-apkid"]);
  dep("-top5",["-jni-bridge","-privacy","-graph-explorer"]);
}

function bldFlags(){
  syncStaticOutputFlags();
  var f=[];
  if(curMode==="decode"){
    if(document.getElementById("decodeJavaView").checked)f.push("-java-view");
    if(document.getElementById("decodeCopyOriginal").checked)f.push("-copy-original");
  }
  if(curMode==="build"){
    f.push("-compression-mode",document.getElementById("buildCompression").value);
    if(document.getElementById("buildNoSign").checked)f.push("-no-sign");
    f.push("-apk-name",buildResultName());
  }
  if(curMode==="full"){
    var budget=document.getElementById("bundleBudget");if(budget)f.push("-bundle-budget",budget.value);
    var pc=document.querySelector(".pcard.on");if(pc)f.push("-profile",pc.dataset.v);
    document.querySelectorAll("input.fg:checked").forEach(function(el){if(!el.disabled)f.push(el.dataset.f);});
  }
  if(curMode==="full"||curMode==="machine-code"||curMode==="firmware"){
    var sg=document.querySelector(".sbtn.on");if(sg&&sg.dataset.v)f.push("-report",sg.dataset.v);
    var w=document.getElementById("w-r").value;if(w!=="0")f.push("-workers",w);
    var t=document.getElementById("t-r").value;if(t!=="300")f.push("-timeout",t);
  }
  if(curMode==="full"){
    var fp=document.getElementById("fp-r").value;if(fp!=="-1")f.push("-fp-min-score",fp);
  }
  if(curMode==="sandbox"){
    var enabled=function(id){var el=document.getElementById(id);return !!el&&!el.disabled&&el.checked;};
    syncSandboxDuration();
    var seconds=sandboxDurationSeconds();
    if(!Number.isFinite(seconds))throw new Error(uiLang==="ru"?"Проверь длительность сессии.":"Check the session duration.");
    f.push("-sandbox-duration",String(seconds));
    if(curEnv==="windows"||(curTarget&&curTarget.kind==="avd")){
      f.push("-sandbox-cpu-cores",document.getElementById("sbxcpu-r").value);
      f.push("-sandbox-memory",document.getElementById("sbxram-r").value);
    }
    if(enabled("netChk"))f.push("-sandbox-allow-net");
    if(curEnv==="windows"){
      var args=document.getElementById("sbxCmdArgs").value.trim();
      if(args)f.push("-sandbox-args",args);
      f.push("-sandbox-profile","basic");
      if(isVMwareTarget())f.push("-sandbox-desktop",document.getElementById("vmwareDesktop").value);
    }else if(curEnv==="android"){
      f.push("-android-sandbox");
      if(curTarget&&curTarget.serial)f.push("-sandbox-device",curTarget.serial);
      else if(curTarget&&curTarget.avd)f.push("-sandbox-avd",curTarget.avd);
      if(enabled("sbxUninstall"))f.push("-sandbox-uninstall-after");
      if(enabled("sbxCapture"))f.push("-sandbox-capture-traffic");
      if(enabled("sbxMITM"))f.push("-sandbox-mitm");
      if(enabled("sbxFrida")){
        f.push("-sandbox-frida");
        var script=document.getElementById("sbxFridaScript").value.trim();
        if(script)f.push("-sandbox-frida-script",script);
      }
      var res=document.getElementById("sbxResolution").value;if(res)f.push("-sandbox-resolution",res);
      if(curOri)f.push("-sandbox-orientation",curOri);
      var loc=document.getElementById("sbxLocale").value;if(loc)f.push("-sandbox-locale",loc);
      var tz=document.getElementById("sbxTimezone").value;if(tz)f.push("-sandbox-timezone",tz);
    }
  }
  if(curMode==="web-scan"){
    if(document.getElementById("ownChk").checked)f.push("-i-own-this-target");
    if(document.getElementById("labChk").checked)f.push("-lab-mode");
  }
  return f;
}

// ── log helpers ──
var log=document.getElementById("log");
function ll(txt,cls){var s=document.createElement("span");s.className="ll"+(cls?" "+cls:"");s.textContent=txt;log.appendChild(s);log.scrollTop=log.scrollHeight;}
// A progress redraw overwrites the previous one instead of stacking up, so a
// 70k-file scan leaves one live row rather than thousands of near-identical
// ones. The server still appends them, which keeps SSE resume by Last-Event-ID
// working after a dropped connection.
function lp(txt){
  var last=log.lastElementChild;
  if(last&&last.classList.contains("lp")){last.textContent=txt;}
  else{var s=document.createElement("span");s.className="ll lp";s.textContent=txt;log.appendChild(s);}
  log.scrollTop=log.scrollHeight;
}
function lc(l){var s=l.toLowerCase();if(/error|fatal|failed|exception|panic/.test(s))return"le";if(/warn/.test(s))return"lw";if(/done|complete|finish|success|written|saved|wrote/.test(s))return"lo";if(/critical|high|finding|detected/.test(s))return"lh";return"";}
function e(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");}

// ── run ──
function primaryAction(){
  if(running){stopJob();return;}
  if(curMode==="sandbox"&&!sandboxConsentReady())return;
  run();
}
function sandboxConsentReady(){var c=document.getElementById("sbxConsent");return !!c&&c.checked;}
function isVMwareTarget(){return !!curTarget&&curTarget.kind==="vm"&&curTarget.ico==="vmware";}
function vmwareExecutionReady(){return isVMwareTarget()&&!vmwarePanelBusy&&!!vmwareReport&&vmwareReport.guestExecution&&vmwareReport.configurationPass&&!vmwareReport.suspended&&!!document.getElementById("vmwareUser").value.trim()&&!!document.getElementById("vmwarePassword").value;}
function vmwareReadinessMessage(){
  if(vmwarePanelBusy)return "Проверяю состояние VMware…";
  if(!vmwareReport)return "Проверьте настройки выбранной ВМ.";
  if(vmwareReport.suspended)return "Возобновите ВМ и штатно выключите гостевую Windows.";
  if(!vmwareReport.configurationPass)return "Подготовьте выключенную ВМ перед запуском.";
  if(!document.getElementById("vmwareUser").value.trim())return "Укажите пользователя гостевой Windows или загрузите логин и пароль из файла.";
  if(!document.getElementById("vmwarePassword").value)return "Введите пароль этой гостевой учётной записи или загрузите его из файла. VMware не принимает пустой пароль.";
  return "Выберите поддерживаемую гостевую Windows.";
}
function stopJob(){if(uploadAbort){try{uploadAbort.abort();}catch(e){}return;}if(jid)fetch("/api/stop/"+jid,{method:"POST"}).catch(function(){});}

// Security software (Kaspersky etc.) sometimes answers for the local server:
// either an HTML block page or a dropped connection mid-upload. Name the
// culprit instead of dumping its whole page into the scan log.
function scanErrorText(status,body){
  var text=body||"";
  var title=/<title[^>]*>([^<]{1,120})<\/title>/i.exec(text);
  var who=title?title[1].trim():"";
  if(who||/^\s*<(!doctype|html|\?xml)/i.test(text)){
    return uiLang==="ru"
      ?"Запрос перехватила не веб-панель анализатора, а "+(who?"«"+who+"»":"сторонняя страница")+" — похоже, веб-защита антивируса или прокси. Добавьте 127.0.0.1 и папку анализатора в исключения антивируса и повторите."
      :"The reply came from "+(who?"\""+who+"\"":"a third-party page")+" instead of the analyzer web UI — likely antivirus web protection or a proxy. Add 127.0.0.1 and the analyzer folder to its exclusions and retry.";
  }
  return text.trim()||("HTTP "+status);
}
function run(){
  if(window.MegaWasm&&(!document.getElementById("w-d").reportValidity()||!document.getElementById("t-d").reportValidity()))return;
  var m=MODES[curMode],sandboxRequest=curMode==="sandbox",requestSerial=sbxRunSerial;
  if(curMode==="sandbox"&&(!sf||!curTarget||!curTarget.runnable||!sandboxConsentReady()||sbxBusy()))return;
  if(curMode==="sandbox"&&isVMwareTarget()&&!vmwareExecutionReady())return;
  if(!m.fileless&&!sf)return;
  if(sandboxRequest&&!Number.isFinite(sandboxDurationSeconds())){document.getElementById("sbx-r").reportValidity();return;}
  // Belt-and-suspenders size check before any byte is sent: a rejected
  // over-limit upload used to abort mid-flight and surface as an opaque
  // "Failed to fetch" instead of the server's 413 message.
  var totalBytes=(sf?sf.size:0)+((curMode==="version-diff"&&sf2)?sf2.size:0);
  if(totalBytes>MAX_UPLOAD_BYTES){
    showDzErr(1,"File is "+fb(totalBytes)+", which exceeds the "+Math.round(MAX_UPLOAD_BYTES/1048576)+" MB upload limit.");
    return;
  }
  invalidateScanView();
  var generation=scanGeneration,requestMode=curMode;
  var prog=document.getElementById("prog"),res=document.getElementById("res"),pb=document.getElementById("pb"),pt=document.getElementById("pt"),ps=document.getElementById("ps"),sbxDash=document.getElementById("liveSbxDash");
  log.innerHTML="";pb.classList.remove("indet");pb.style.width="5%";
  pt.textContent=m.longRunning?"Starting…":"Uploading…";ps.style.display="block";
  res.classList.remove("show");
  if(curMode==="sandbox"){
    _sbxStopped=false;
    _sbxResultLoading=false;
    prog.classList.remove("show");
    sbxDash.style.display="flex";
    document.body.classList.add("sbx-running");
    jid=null;
    initSbxDashboard();
    sbxSetPhase("starting");
  } else {
    prog.classList.add("show");
    sbxDash.style.display="none";
  }
  document.getElementById("sbtn").disabled=false;
  document.getElementById("sbtn").classList.add("stop");
  document.getElementById("sbtn-t").textContent="Stop";
  running=true;
  syncWorkspaceUI();
  if(curMode==="sandbox") {
    if(window.innerWidth<=880)document.getElementById("liveSbxDash").scrollIntoView({behavior:preferredScrollBehavior(),block:"start"});
  } else {
    prog.scrollIntoView({behavior:preferredScrollBehavior(),block:"start"});
  }

  var fd=new FormData();
  fd.append("mode",curMode);
  if(window.MegaWasm){fd.append("workers",document.getElementById("w-r").value);fd.append("timeout",document.getElementById("t-r").value);}
  if(sandboxRequest){
    fd.append("sandbox-target",isVMwareTarget()?curTarget.key:curTarget.kind+":"+(curTarget.serial||curTarget.avd||"host"));
    fd.append("sandbox-consent",sandboxConsentReady()?"yes":"no");
    if(isVMwareTarget()){fd.append("vmware-user",document.getElementById("vmwareUser").value.trim());fd.append("vmware-password",document.getElementById("vmwarePassword").value);}
  }
  if(!m.fileless){fd.append("file",sf);if(curMode==="version-diff"&&sf2)fd.append("file2",sf2);}
  if(curMode==="web-scan")fd.append("url",document.getElementById("scanUrl").value.trim());
  if(curMode==="intercept"){fd.append("port",document.getElementById("mitmPort").value.trim());fd.append("upstream",document.getElementById("mitmUp").value.trim());}
  fd.append("flags",JSON.stringify(bldFlags()));
  var od=document.getElementById("outdir").value.trim();if(od&&curMode!=="intercept")fd.append("output",od);
  var on=document.getElementById("outname").value.trim();if(on&&curMode!=="intercept")fd.append("outname",on);

  var controller=new AbortController();uploadAbort=controller;
  fetch("/api/scan",{method:"POST",body:fd,signal:controller.signal})
    .then(function(r){if(!r.ok)return r.text().then(function(t){throw new Error(scanErrorText(r.status,t));});return r.json();})
    .then(function(d){
      if(!scanIsCurrent(generation,null,requestMode)||(sandboxRequest&&requestSerial!==sbxRunSerial)){
        if(d.id)fetch("/api/stop/"+d.id,{method:"POST"}).catch(function(){});
        return;
      }
      uploadAbort=null;
      if(sandboxRequest&&isVMwareTarget()){document.getElementById("vmwarePassword").value="";vmwareCredentialsChanged("Для следующего запуска введите пароль заново или загрузите тот же файл.");}
      jid=d.id;curOut=d.output||"";running=true;
      window.dispatchEvent(new CustomEvent("mega:scan-created",{detail:{path:d.workspace_path}}));
      if(curMode==="sandbox")show("envRow",false);
      if(curMode==="sandbox"){sbxStartTime=Date.now();sbxSetPhase("running");}
      // Android: drive the live device stream
      if(curMode==="sandbox"&&curEnv==="android"){liveStart();}
      streamEvt(d.id);
      if(m.longRunning){
        pt.textContent="Proxy running…";pb.classList.add("indet");
        if(curOut)ll("Capturing traffic to "+curOut+"/capture.jsonl","lo");
        var sb=document.getElementById("sbtn");sb.disabled=false;sb.classList.add("stop");document.getElementById("sbtn-t").textContent="Stop";
      }else{
        pt.textContent=d.status==="queued"?"Queued — waiting for a scan slot…":"Working…";pb.style.width="12%";
        var p=12;ptmr=setInterval(function(){if(p<84){p+=0.7;pb.style.width=p+"%";}},900);
      }
      var cancelButton=document.getElementById("sbtn");cancelButton.disabled=false;cancelButton.classList.add("stop");document.getElementById("sbtn-t").textContent="Stop";
    })
    .catch(function(err){
      if(!scanIsCurrent(generation,null,requestMode)||(sandboxRequest&&requestSerial!==sbxRunSerial))return;
      var aborted=controller.signal.aborted||(err&&err.name==="AbortError");
      uploadAbort=null;
      running=false;
      var _sb=document.getElementById("sbtn");_sb.classList.remove("stop");document.getElementById("sbtn-t").textContent=MODES[curMode].btn||"Analyze";_sb.disabled=false;ps.style.display="none";
      if(aborted){
        pt.textContent="Stopped";ll("[info] Stopped by you — upload cancelled, nothing was started.");
        if(curMode==="sandbox"){cleanupSbxDashboard();sbxSetPhase("setup");syncEnvRow();prepareSandboxWorkspace();}
        refreshBtn();return;
      }
      var _msg=(err&&err.message)||"upload failed";
      if(err&&err.name==="TypeError")_msg+=" — connection lost mid-upload; check that the web server is still running and that antivirus web protection does not intercept 127.0.0.1";
      ll("[error] "+_msg,"le");
      if(curMode==="sandbox"){cleanupSbxDashboard();sbxSetPhase("setup");syncEnvRow();prepareSandboxWorkspace();showDzErr(1,"Could not start the analysis: "+err.message);refreshBtn();}
    });
}

function streamEvt(id){
  var pb=document.getElementById("pb"),pt=document.getElementById("pt"),ps=document.getElementById("ps");
  var es=null,reconnectTimer=null,retries=0,maxRetries=5,sandboxStream=curMode==="sandbox",scanWasStopped=false;
  var generation=scanGeneration,streamMode=curMode,closed=false;
  function current(){return !closed&&scanIsCurrent(generation,id,streamMode);}
  function close(){closed=true;clearTimeout(reconnectTimer);if(es)es.close();}
  if(closeScanStream)closeScanStream();closeScanStream=close;

  function giveUp(){
    if(!current())return;
    if(sandboxStream){
      sbxOutcome="Connection lost";
      sbxStopReason="Link to the engine lost (the host may be down — this is also how a crashed host looks).";
      appendConsole("status","[sandbox] "+sbxStopReason);sbxEngineLog(sbxStopReason,"err");
    }
    // Retries exhausted (or the tab genuinely lost the connection for good).
    // Only now do we fall back to treating the job as finished — a transient
    // SSE hiccup alone must not show a "Finished" card while the job is
    // still running server-side.
    clearInterval(ptmr);running=false;ps.style.display="none";pb.classList.remove("indet");
    if(curMode==="sandbox"){show("envRow",false);}else{syncEnvRow();}
    cleanupSbxDashboard();
    var sb=document.getElementById("sbtn");sb.classList.remove("stop");document.getElementById("sbtn-t").textContent=MODES[curMode].btn||"Analyze";
    refreshBtn();if(jid&&!MODES[curMode].longRunning)loadFinal(jid);
  }

  function connect(){
    if(!current())return;
    es=new EventSource("/api/events/"+id);
    function evLine(ev,prog){
      if(!current()){close();return;}
      retries=0; // connection is healthy again; reset the backoff counter
      var raw=ev.data;
      try{raw=JSON.parse('"'+ev.data+'"');}catch(x){}
      if(!raw.trim())return;
      // Progress redraws collapse into a single live row. Sandbox is excluded:
      // its stream is telemetry JSON that has to reach the parser intact.
      if(prog&&curMode!=="sandbox"){lp(raw);return;}
      ll(raw,lc(raw));

      if(curMode==="sandbox"){
        var parsed=false;
        try{
          var data=JSON.parse(raw);
          handleSbxTelemetry(data);
          parsed=true;
        }catch(err){}
        // Non-JSON line = a human-readable engine log (install/launch progress,
        // adb errors). Surface it in the visible Engine activity feed.
        if(!parsed&&!captureSandboxFailure({type:"log",details:raw})){ sbxEngineLog(raw, sbxEngineCls(raw)); }
      }
    }
    es.onmessage=function(ev){evLine(ev,false);};
    es.addEventListener("state",function(ev){
      if(!current())return;
      if(ev.data==="stopped")scanWasStopped=true;
      if(ev.data==="queued"){clearInterval(ptmr);pt.textContent="Queued — waiting for a scan slot…";pb.classList.add("indet");}
      else if(ev.data==="running"){pb.classList.remove("indet");pt.textContent=MODES[curMode].longRunning?"Proxy running…":"Working…";}
    });
    es.addEventListener("gap",function(ev){
      if(!current())return;
      try{var gap=JSON.parse(ev.data);ll("[warn] Live log omitted "+(gap.to-gap.from)+" earlier lines. See scan.log in the workspace.","lw");}catch(_){}
    });
    es.addEventListener("progress",function(ev){evLine(ev,true);});
    es.addEventListener("done",function(ev){
      if(!current()){close();return;}
      if(sandboxStream){
        var sandboxCode=parseInt(ev.data,10);
        var sandboxStopped=scanWasStopped||sbxOutcome==="Stop requested";
        if(!sbxFailure && sandboxCode!==0 && !sandboxStopped)captureSandboxFailure({type:"error",code:"engine_failed",stage:"execution",details:"The sandbox engine exited with code "+sandboxCode+". Review the diagnostics; this is not a sample verdict."});
        sbxOutcome=sbxFailure?"Failed":sandboxStopped?"Stopped":"Completed";
        // Plain-language stop reason, mirrored into the console and the feed
        // so the end of the run is never a bare timestamp.
        if(sbxOutcome==="Stopped"){sbxStopReason="Stopped by you. Captured events remain available.";}
        else if(sbxOutcome==="Failed"){sbxStopReason=((sbxFailure&&sbxFailure.title)||"Engine error")+".";}
        else if(sbxOutcome==="Completed"){sbxStopReason=sandboxCompletionMessage(sbxCompletionReason);}
        if(sbxStopReason){appendConsole("status","[sandbox] "+sbxStopReason);sbxEngineLog(sbxStopReason,sbxOutcome==="Failed"?"err":"ok");}
      }
      // The only true completion signal from the server.
      close();clearInterval(ptmr);running=false;
      cleanupSbxDashboard();
      var m=MODES[curMode],code=parseInt(ev.data,10);
      pb.classList.remove("indet");pb.style.width="100%";ps.style.display="none";
      var sb=document.getElementById("sbtn");sb.classList.remove("stop");document.getElementById("sbtn-t").textContent=m.btn||"Analyze";
      pt.textContent=sandboxStream?sbxOutcome:scanWasStopped?"Stopped":m.longRunning?"Proxy stopped":(code===0?"Completed":"Finished (exit "+code+")");
      if(code===0&&!m.longRunning&&(!sandboxStream||!sbxFailure))ll("Done.","lo");
      // Sandbox cleanup persists a report even when Stop ended observation.
      var showResult=sandboxStream||(!scanWasStopped&&!_sbxStopped);
      _sbxStopped=false;
      if(!m.longRunning&&showResult)loadFinal(id);
      // envRow belongs to the sandbox tool, so for every other mode this call
      // only has to confirm that it stays hidden.
      if(curMode!=="sandbox")syncEnvRow();
      refreshBtn();
    });
    es.onerror=function(){
      es.close();
      if(!current())return;
      if(retries<maxRetries){
        retries++;
        var delay=Math.min(1000*Math.pow(2,retries-1),15000); // 1s,2s,4s,8s,15s
        pt.textContent="Connection interrupted — reconnecting ("+retries+"/"+maxRetries+")…";
        reconnectTimer=setTimeout(connect,delay);
        return;
      }
      giveUp();
    };
  }
  connect();
}

// ── Sandbox Live Detonation Dashboard State & Handlers ──
var sbxActivityRows=[],sbxActivityTotal=0,sbxActivityPaused=false,sbxActivityRender=null;
function recordSandboxActivity(data){
  sbxActivityTotal++;
  sbxActivityRows.push(data);
  if(sbxActivityRows.length>1000)sbxActivityRows.shift();
  uiText("sbxActivityCount",String(sbxActivityTotal));
  if(!sbxActivityPaused&&!sbxActivityRender)sbxActivityRender=setTimeout(renderSandboxActivity,150);
}
function renderSandboxActivity(){
  clearTimeout(sbxActivityRender);sbxActivityRender=null;
  if(sbxActivityPaused)return;
  var el=document.getElementById("sbxtbl-activity");
  if(!sbxActivityRows.length){el.innerHTML="<div class='tempty'>"+e(pageT("activityEmpty"))+"</div>";return;}
  var ru=uiLang==="ru";
  var h="<table class='dtbl sbx-activity-table'><thead><tr><th>"+(ru?"Обнаружено":"Observed")+"</th><th>"+(ru?"Кто":"Actor")+"</th><th>"+(ru?"Действие / объект":"Action / object")+"</th><th>"+(ru?"Источник / доказательства":"Source / evidence")+"</th></tr></thead><tbody>";
  sbxActivityRows.forEach(function(row){
    var actor=row.pid?(row.process||"PID")+" · "+row.pid:(ru?"Не установлен":"Unknown");
    var stamp=String(row.timestamp||"");
    if(stamp.indexOf("T")>=0)stamp=stamp.replace("T"," ").replace(/Z$/," UTC");
    var category=row.category||"";
    var categories={file:"activityFiles",directory:"activityFolders",process:"activityProcesses",network:"activityNetwork",session:"activitySession",coverage:"activityCoverage"};
    var actions={appeared:ru?"Обнаружено создание":"Appearance detected",changed:ru?"Обнаружено изменение":"Change detected",disappeared:ru?"Обнаружено удаление":"Disappearance detected",observed:ru?"Замечен":"Observed",prepared:ru?"Подготовлена":"Prepared",ended:ru?"Завершена":"Ended",snapshot_failed:ru?"Сбор недоступен":"Collection unavailable"};
    h+="<tr data-category='"+e(category)+"'><td>"+e(stamp)+"</td><td>"+e(actor)+"</td><td><span class='sbx-activity-kind'>"+e(pageT(categories[category]||category))+" · "+e(actions[row.action]||row.action||"")+"</span><code>"+e(row.object||"")+"</code></td><td><details><summary>"+e(row.source||"unknown")+"</summary><p>"+e(row.details||"")+"</p><p>"+e(ru?"Привязка: ":"Attribution: ")+e(row.attribution||"unknown")+"</p><code>"+e(row.event_id||"")+"</code></details></td></tr>";
  });
  el.innerHTML=h+"</tbody></table>";
  filterSandboxRows();
}
function toggleActivityPause(){
  sbxActivityPaused=!sbxActivityPaused;
  var button=document.getElementById("sbxActivityPause");button.dataset.i18n=sbxActivityPaused?"activityResume":"activityPause";button.textContent=pageT(button.dataset.i18n);button.setAttribute("aria-pressed",String(sbxActivityPaused));
  if(!sbxActivityPaused)renderSandboxActivity();
}
var sbxTimerVal = 0;
var sbxCompletionReason = "";
function sandboxCompletionMessage(reason){
  var ru=uiLang==="ru";
  if(reason==="duration_elapsed")return ru?"Заданный таймер истёк. Наблюдение завершено.":"Duration elapsed — the configured observation window is over.";
  if(reason==="stopped")return ru?"Наблюдение остановлено. Собранные события сохранены.":"Observation stopped. Captured events remain available.";
  if(reason==="interrupted")return ru?"Сбор прерван. Полученные события сохранены; отчёт неполный.":"Collection interrupted. Received events are saved; the report is incomplete.";
  return ru?"Сбор завершён. Собранные события сохранены.":"Collection finished. Captured events remain available.";
}
var sbxTimerInterval = null;
var sbxStartTime = null;
var sbxObservationStartTime=null;
var sbxProcessMap = {}; // PID -> { pid, ppid, name, args, domId, files: 0, reg: 0, net: 0, mut: 0 }
var sbxSelectedPid = null; // pid with the detail panel open; null = nothing selected
var sbxHttpRequests = [];
var sbxConnections = [];
var sbxThreats = [];
var sbxDnsRows = [];
var sbxPerfInterval = null;
var sbxViewMode = "output"; // viewport view: "output" (engine log console) or "screen" (Android live device)

// The VMware console is read from the exact running job, independently of ADB.
function switchSbxView(m){
  if(m==="screen"&&curEnv!=="android"&&!isVMwareTarget())return;
  sbxViewMode=m;syncSbxView();
}
function syncSbxView(){
  var con=document.getElementById("sbxConsole"),andD=document.getElementById("sbxAndroidStream");
  var vmD=document.getElementById("sbxVMwareScreen"),vmware=isVMwareTarget();
  var outB=document.getElementById("sbxViewOutputBtn"),scrB=document.getElementById("sbxViewScreenBtn");
  var showScreen=((curEnv==="android"||vmware)&&sbxViewMode==="screen");
  if(sbxViewPhase!=="setup"){
    if(con)con.style.display=showScreen?"none":"flex";
    if(andD)andD.style.display=showScreen&&!vmware?"flex":"none";
  }else{
    if(con)con.style.display="none";
    if(andD)andD.style.display=showScreen&&!vmware?"flex":"none";
    var idle=document.getElementById("sbxVmIdle");if(idle)idle.style.display=showScreen&&!vmware?"none":"flex";
  }
  if(vmD)vmD.style.display=showScreen&&vmware&&sbxViewPhase!=="setup"?"flex":"none";
  if(showScreen&&vmware&&sbxViewPhase==="running"&&curMode==="sandbox")startVMwareScreen();
  else stopVMwareScreen(true);
  if(curMode==="sandbox"&&curEnv==="android"&&showScreen&&(sbxViewPhase==="running"||sbxViewPhase==="setup"&&curTarget&&curTarget.serial))liveStart();
  else if(sbxViewPhase==="setup")liveStop(false);
  if(showScreen&&vmware&&sbxViewPhase==="complete")uiText("vmwareScreenStatus",uiLang==="ru"?(vmwareScreenState.url?"Последний полученный кадр · сессия завершена":"Сессия завершена · кадр не получен"):(vmwareScreenState.url?"Last captured frame · session ended":"Session ended · no frame captured"));
  if(outB)outB.classList.toggle("on",!showScreen);
  if(scrB){
    scrB.classList.toggle("on",showScreen);
    var hostOnly=curEnv!=="android"&&!vmware;
    scrB.disabled=hostOnly;
    scrB.title=vmware?(uiLang==="ru"?"Живая консоль VMware · мышь и клавиатура":"Live VMware console · mouse and keyboard"):hostOnly?"Screen capture is unavailable for this target":"Live Android device screen";
  }
}

var vmwareScreenState={running:false,generation:0,job:null,timer:null,controller:null,url:null,rfb:null,connected:false};
var vmwareRFBModule=null;
function loadVMwareRFB(){if(!vmwareRFBModule)vmwareRFBModule=import("/static/novnc.js").catch(function(e){vmwareRFBModule=null;throw e;});return vmwareRFBModule;}
function rememberVMwareFrame(rfb){
  try{var data=rfb.getImageData();if(data.width>0&&data.height>0){vmwareScreenState.url=rfb.toDataURL();var img=document.getElementById("vmwareScreenImage");img.src=vmwareScreenState.url;img.hidden=false;document.getElementById("vmwareScreenPlaceholder").hidden=true;}}catch(e){}
}
function stopVMwareScreen(preserve){
  var state=vmwareScreenState;
  state.running=false;state.generation++;
  clearTimeout(state.timer);state.timer=null;
  if(state.controller){state.controller.abort();state.controller=null;}
  var rfb=state.rfb;state.rfb=null;
  if(rfb){if(preserve&&state.connected)rememberVMwareFrame(rfb);rfb.blur();rfb.disconnect();}
  state.connected=false;
  document.getElementById("vmwareConsole").hidden=true;
  document.getElementById("vmwareCtrlAltDel").disabled=true;
  if(!preserve){
    state.url=null;state.job=null;
    var img=document.getElementById("vmwareScreenImage");
    if(img){img.onload=null;img.onerror=null;img.removeAttribute("src");img.hidden=true;}
    var placeholder=document.getElementById("vmwareScreenPlaceholder");if(placeholder)placeholder.hidden=false;
    uiText("vmwareScreenStatus","");
  }
}
function startVMwareScreen(){
  var state=vmwareScreenState;
  if(!jid||state.running&&state.job===jid)return;
  stopVMwareScreen(state.job===jid);
  state.running=true;state.job=jid;
  var generation=state.generation,job=jid,serial=sbxRunSerial;
  function current(){return state.running&&generation===state.generation&&job===jid&&serial===sbxRunSerial&&curMode==="sandbox"&&isVMwareTarget()&&sbxViewMode==="screen"&&sbxViewPhase==="running";}
  function retry(){if(current())state.timer=setTimeout(tick,2000);}
  function tick(){
    if(!current())return;
    if(document.hidden){state.timer=setTimeout(tick,2000);return;}
    var controller=new AbortController();state.controller=controller;
    var timeout=setTimeout(function(){controller.abort();},18000);
    uiText("vmwareScreenStatus",uiLang==="ru"?"Подключаю живую консоль VMware…":"Connecting to the live VMware console…");
    Promise.all([loadVMwareRFB(),fetch("/api/vmware/console-info?job="+encodeURIComponent(job),{cache:"no-store",signal:controller.signal}).then(function(r){if(!r.ok)throw new Error("console unavailable");return r.json();})])
      .then(function(result){
        if(!current())return;
        var root=document.getElementById("vmwareConsole");root.hidden=false;root.replaceChildren();
        var rfb=new result[0].default(root,(location.protocol==="https:"?"wss:":"ws:")+"//"+location.host+"/api/vmware/console?job="+encodeURIComponent(job),{credentials:{password:result[1].password},shared:true});
        state.rfb=rfb;rfb.scaleViewport=true;rfb.resizeSession=false;rfb.showDotCursor=true;rfb.focusOnClick=true;
        rfb.qualityLevel=9;rfb.compressionLevel=2;
        rfb.addEventListener("connect",function(){if(!current()){rfb.disconnect();return;}state.connected=true;document.getElementById("vmwareScreenImage").hidden=true;document.getElementById("vmwareScreenPlaceholder").hidden=true;document.getElementById("vmwareCtrlAltDel").disabled=false;uiText("vmwareScreenStatus",uiLang==="ru"?"В эфире · нажмите на экран для управления":"Live · click the screen to control the guest");});
        rfb.addEventListener("disconnect",function(){if(!current()||state.rfb!==rfb)return;if(state.connected)rememberVMwareFrame(rfb);state.rfb=null;state.connected=false;root.hidden=true;document.getElementById("vmwareCtrlAltDel").disabled=true;uiText("vmwareScreenStatus",uiLang==="ru"?"Консоль отключена · подключаю заново…":"Console disconnected · reconnecting…");retry();});
      })
      .catch(function(){if(current()){uiText("vmwareScreenStatus",uiLang==="ru"?"Ожидаю готовности консоли VMware…":"Waiting for the VMware console…");retry();}})
      .finally(function(){clearTimeout(timeout);if(state.controller===controller)state.controller=null;});
  }
  tick();
}
function vmwareSendCtrlAltDel(){var state=vmwareScreenState;if(state.running&&state.connected&&state.rfb&&sbxViewPhase==="running"&&sbxViewMode==="screen")state.rfb.sendCtrlAltDel();}

function updateSbxTimerDisplay() {
  var clock=document.getElementById("sbxTimer");
  if(!sbxObservationStartTime){if(clock)clock.textContent="Preparing…";return;}
  var elapsed = Math.floor((Date.now() - sbxObservationStartTime) / 1000);
  var unlimited=sbxTimerVal===0;
  var remaining = unlimited?elapsed:Math.max(0, sbxTimerVal - elapsed);
  var el = document.getElementById("sbxTimer");
  if (el) el.textContent = formatSandboxElapsed(remaining);
  if (!unlimited && remaining <= 0) {
    // Time's up. Don't kill the backend — it finishes on its own Duration and
    // emits "done" with the full report. We just stop the countdown and wait,
    // with a safety net in case the engine hangs.
    if (sbxTimerInterval) { clearInterval(sbxTimerInterval); sbxTimerInterval = null; }
    if (el) el.innerHTML = "<span style='font-size:15px'>Finalizing…</span>";
    // Keep capture connected. Only the server's done event confirms completion;
    // the user can still request Stop if the engine takes longer than expected.
  }
}

// sbxStop halts the detonation: kills the backend job, stops the live stream.
var _sbxStopped = false;
function sbxStop() {
  if(curMode==="sandbox"){if(sbxViewPhase!=="running")return;sbxOutcome="Stop requested";sbxStopReason="Stopped by you.";sbxSetPhase("stopping");}
  if (sbxTimerInterval) { clearInterval(sbxTimerInterval); sbxTimerInterval = null; }
  liveStop(true);
  if (typeof stopAudio === "function") stopAudio();
  if (jid) { stopJob(); }
  var el = document.getElementById("sbxTimer");
  if (el) el.innerHTML = "<span style='font-size:16px'>Stopping...</span>";
  var st=document.querySelector(".sbx-stop-btn");if(st){st.disabled=true;st.textContent="Wait";}
  // Remain in Stopping until the server confirms cleanup and emits done.
  // Do not unlock New analysis or invent a report after an arbitrary timeout.

}

// sbxReturnToMenu hides the live dashboard and restores the configuration view.
function sbxReturnToMenu() {
  if(curMode!=="sandbox"||sbxBusy())return;
  _sbxResultLoading=false;jid=null;sbxRunSerial++;document.body.classList.remove("sbx-running");setLockOverlay(false);
  document.getElementById("res").classList.remove("show");
  document.getElementById("prog").classList.remove("show");
  document.getElementById("ps").style.display="none";
  document.getElementById("sbtn-t").textContent=MODES[curMode].btn||"Analyze";
  sbxSetPhase("setup");syncEnvRow();prepareSandboxWorkspace();refreshBtn();
}

function initSbxDashboard() {
  stopVMwareScreen(false);
  sbxCompletionReason="";
  sbxOutcome="";sbxStopReason="";sbxHasFrame=false;sbxEndTime=null;sbxFailure=null;sbxSessionId="";sbxDiagnostics=[];document.getElementById("sbxStreamPlaceholder").hidden=false;
  sbxTimerVal = sandboxDurationSeconds();
  sbxStartTime = null;
  sbxObservationStartTime=null;
  updateSbxTimerDisplay();
  sbxProcessMap = {};
  clearTimeout(sbxActivityRender);sbxActivityRender=null;sbxActivityRows=[];sbxActivityTotal=0;sbxActivityPaused=false;
  document.getElementById("sbxActivityCategory").value="";
  var pause=document.getElementById("sbxActivityPause");pause.dataset.i18n="activityPause";pause.textContent=pageT("activityPause");pause.setAttribute("aria-pressed","false");
  uiText("sbxActivityCount","0");renderSandboxActivity();
  sbxHttpRequests = [];
  sbxConnections = [];
  sbxThreats = [];
  sbxDnsRows = [];

  document.getElementById("liveProcessTree").innerHTML = "";
  document.getElementById("sbxProcCount").textContent = "0";
  document.getElementById("sbxHttpCount").textContent = "—";
  document.getElementById("sbxConnCount").textContent = "0";
  document.getElementById("sbxDnsCount").textContent = "—";
  document.getElementById("sbxThreatCount").textContent = "0";

  document.getElementById("sbxtbl-http").innerHTML = "<div class='tempty'>Waiting for requests from the configured network capture.</div>";
  document.getElementById("sbxtbl-conn").innerHTML = "<div class='tempty'>Waiting for connections reported by the engine.</div>";
  document.getElementById("sbxtbl-dns").innerHTML = "<div class='tempty'>Waiting for DNS queries…</div>";
  document.getElementById("sbxtbl-threats").innerHTML = "<div class='tempty'>No alerts received yet. This is not a clean verdict.</div>";

  document.getElementById("sbxAlertBanner").style.display = "none";
  var feed = document.getElementById("sbxEngineFeedBody");
  if (feed) feed.innerHTML = "";
  sbxEngineLog("Preparing session…", "info");

  var fn = sf ? sf.name : "sample";
  document.getElementById("sbxFileName").textContent = fn;
  document.getElementById("sbxMD5").textContent = "MD5: awaiting engine metadata";

  // Reset perf bars (hidden until a real sample arrives).
  document.getElementById("sbxPerfPanel").style.visibility = "hidden";
  document.getElementById("sbxCpuVal").textContent = "—";
  document.getElementById("sbxRamVal").textContent = "—";
  document.getElementById("sbxCpuFill").style.width = "0%";
  document.getElementById("sbxRamFill").style.width = "0%";

  var osIco = document.getElementById("sbxOsIco");
  var osName = document.getElementById("sbxOsName");
  var con = document.getElementById("sbxConsole");
  var conBody = document.getElementById("sbxConsoleBody");
  var andD = document.getElementById("sbxAndroidStream");
  var idle = document.getElementById("sbxVmIdle");
  var icoKey = (curTarget && curTarget.ico) || (curEnv === "android" ? "android" : "win");
  osIco.innerHTML = OS_ICONS[icoKey] || OS_ICONS.other;
  osName.textContent = (curTarget && curTarget.label) || "Dynamic analysis";
  if (idle) idle.style.display = "none";

  sbxViewMode=(curEnv==="android"||isVMwareTarget())?"screen":"output";
  if (curEnv === "android") {
    con.style.display = "none";
    andD.style.display = "flex";
    var canvas = document.getElementById("liveCanvas");
    var screenImg = document.getElementById("liveScreen");
    var bezel = document.getElementById("liveBezel");
    // Keep the screen + canvas inside the device bezel.
    if (canvas && bezel) bezel.appendChild(canvas);
    if (screenImg && bezel) bezel.appendChild(screenImg);
    // Apply chosen orientation to the device frame.
    andD.classList.toggle("landscape", curOri === "landscape");
  } else {
    andD.style.display = "none";
    con.style.display = "flex";
    document.getElementById("sbxConsoleIco").innerHTML = OS_ICONS[icoKey] || OS_ICONS.other;
    document.getElementById("sbxConsoleTitle").textContent = fn + " — captured output";
    conBody.innerHTML = "";
    appendConsole("status", "[sandbox] preparing " + fn + " on " + ((curTarget && curTarget.label) || "guest") + "…");
  }
  syncSbxView();

  document.getElementById("tagEvasion").style.display = "none";
  document.getElementById("tagInjection").style.display = "none";
  document.getElementById("tagNetwork").style.display = "none";

  if (sbxTimerInterval) clearInterval(sbxTimerInterval);
  // The engine owns execution time; preparation has a separate clock.
  sbxTimerInterval = setInterval(updateSbxTimerDisplay, 1000);
}

// sbxEngineLog appends one line to the always-visible Engine activity feed.
function sbxEngineLog(text, cls) {
  text = String(text || "").trim();
  if (!text) return;
  var body = document.getElementById("sbxEngineFeedBody");
  if (!body) return;
  var line = document.createElement("span");
  line.className = "sbx-efl" + (cls ? " " + cls : "");
  line.textContent = text;
  body.appendChild(line);
  body.scrollTop = body.scrollHeight;
  while (body.childNodes.length > 300) body.removeChild(body.firstChild);
}

// sbxEngineCls picks a colour class for an engine log line from its content.
function sbxEngineCls(s) {
  s = (s || "").toLowerCase();
  if (/error|fail|failed|could not|not found|unable|no host|skipping/.test(s)) return "err";
  if (/warn|⚠/.test(s)) return "warn";
  if (/✓|success|installed|launched|capturing|complete|started|running/.test(s)) return "ok";
  return "info";
}

// appendConsole prints one line to the VM console view.
function appendConsole(kind, text) {
  var body = document.getElementById("sbxConsoleBody");
  if (!body) return;
  var line = document.createElement("div");
  line.className = "sbx-cline c-" + (kind || "out");
  line.textContent = text;
  body.appendChild(line);
  body.scrollTop = body.scrollHeight;
  // Bound the console so a chatty sample can't grow it unbounded.
  while (body.childNodes.length > 600) body.removeChild(body.firstChild);
}

function cleanupSbxDashboard() {
  if (sbxTimerInterval) { clearInterval(sbxTimerInterval); sbxTimerInterval = null; }
  if (sbxPerfInterval) { clearInterval(sbxPerfInterval); sbxPerfInterval = null; }
  document.body.classList.remove("sbx-running");
  setLockOverlay(false);
  if (typeof stopAudio === "function") stopAudio();
  liveStop(curMode==="sandbox");
  var dash = document.getElementById("liveSbxDash");
  if(curMode==="sandbox"){sbxSetPhase("complete");}else if(dash){dash.style.display="none";}
}

// handleSbxTelemetry consumes one real telemetry event from the sandbox engine.
function handleSbxTelemetry(data) {
  if (!data || !data.type) return;
  recordSandboxMetadata(data);
  if(captureSandboxFailure(data))return;
  if(data.type==="status"&&data.stage==="observing"){sbxObservationStartTime=Date.now();updateSbxTimerDisplay();return;}
  if(data.type==="metadata"||data.type==="device")return;
  if(data.type==="activity"){recordSandboxActivity(data);return;}
  var nowStr = data.timestamp || new Date().toLocaleTimeString();
  var elapsedSec = Math.round((Date.now() - sbxStartTime) / 100) / 10;
  var timeshift = elapsedSec + "s";

  // Live host CPU/RAM samples.
  if (data.type === "perf") {
    var panel = document.getElementById("sbxPerfPanel");
    if (panel) panel.style.visibility = "visible";
    var cpu = Math.max(0, Math.min(100, data.cpu || 0));
    var ram = Math.max(0, Math.min(100, data.ram || 0));
    document.getElementById("sbxCpuVal").textContent = cpu + "%";
    document.getElementById("sbxCpuFill").style.width = cpu + "%";
    document.getElementById("sbxRamVal").textContent = ram + "%";
    document.getElementById("sbxRamFill").style.width = ram + "%";
    return;
  }

  // Real captured stdout / status lines into the console view.
  if (data.type === "stdout") { appendConsole("out", data.details || ""); return; }
  if (data.type === "status") { appendConsole("status", data.details || ""); sbxEngineLog(data.details || "", sbxEngineCls(data.details||"")); return; }
  // Engine log line (device detection, APK install/launch, adb errors). These
  // are the real fmt.Printf logs from the sandbox engine, streamed live.
  if (data.type === "log") { appendConsole("out", data.details || ""); sbxEngineLog(data.details || "", sbxEngineCls(data.details||"")); return; }
  if (data.type === "alert") { sbxEngineLog(data.details || "", "err"); }
  if (data.type === "report") { sbxSessionId=String(data.details||"");sbxCompletionReason=data.completion_reason||"";return; } // report-ready signal; final report loads on "done"

  // HTTP request / TLS SNI sighting (from the live PCAPdroid feed or mitmproxy).
  if (data.type === "http") {
    sbxHttpRequests.push({
      timeshift: timeshift,
      method: data.method || "—",
      status: data.status || "—",
      pid: data.pid || "",
      procName: data.process || "",
      url: data.url || data.host || ""
    });
    updateSbxTabTable("http");
    document.getElementById("tagNetwork").style.display = "inline-block";
    return;
  }

  if (data.details && data.details.indexOf("MD5:") >= 0) {
    var mm = data.details.match(/MD5:\s*([a-fA-F0-9]{32})/);
    if (mm) document.getElementById("sbxMD5").textContent = "MD5: " + mm[1].toLowerCase();
  }

  var pid = data.pid || 0;
  var procName = data.process || (sbxProcessMap[pid]&&sbxProcessMap[pid].name) || (pid>0 ? ("pid " + pid) : "Unattributed");

  if (data.type === "process") {
    addSbxProcess(pid, data.ppid || 0, procName, data.details || "");
  }
  var pObj = pid>0?ensureSbxProcessExists(pid, procName):null;

  // Mirror the event to the console (capped at 600 lines, safe when hidden).
  if (data.details) {
    appendConsole(data.type, "[" + nowStr + "] " + procName + (pid ? (" (PID " + pid + ")") : "") + ": " + data.details);
  }

  switch (data.type) {
    case "fs":
      if(pObj)pObj.files++;
      updateSbxProcessDOMCounters(pid);
      break;

    case "network": {
      if(pObj)pObj.net++;
      updateSbxProcessDOMCounters(pid);
      document.getElementById("tagNetwork").style.display = "inline-block";
      var details = data.details || "";
      var proto = (details.match(/\b(TCP|UDP|ICMP)\b/) || ["TCP"])[0];
      var rm = details.match(/->\s*([^\s()]+)/) || details.match(/([0-9a-fA-F:.\[\]]+:[0-9]+)/);
      var remote = rm ? rm[1] : "";
      var st = (details.match(/\(([^)]+)\)/) || ["", ""])[1] || "";
      sbxConnections.push({ timeshift: timeshift, protocol: proto, pid: pid, procName: procName, source: "guest", destination: remote, status: st });
      updateSbxTabTable("conn");
      break;
    }

    case "dns":
      sbxDnsRows.push({ timeshift: timeshift, pid: pid, process: procName, query: data.details || "" });
      updateSbxTabTable("dns");
      break;

    case "api_call": {
      var apiName = data.details || "";
      if (pObj && apiName.indexOf("Reg") >= 0) pObj.reg++;
      else if (pObj && (apiName.indexOf("Mutex") >= 0 || apiName.indexOf("Section") >= 0 || apiName.indexOf("Event") >= 0)) pObj.mut++;
      updateSbxProcessDOMCounters(pid);
      break;
    }

    case "alert": {
      var det = data.details || "Suspicious behaviour detected";
      var low = det.toLowerCase();
      if (low.indexOf("inject") >= 0) document.getElementById("tagInjection").style.display = "inline-block";
      if (low.indexOf("anti-sandbox") >= 0 || low.indexOf("evasion") >= 0) document.getElementById("tagEvasion").style.display = "inline-block";
      sbxThreats.push({ timeshift: timeshift, pid: pid, procName: procName, type: det.split(":")[0].slice(0, 40), description: det, severity: (typeof data.severity==="number"?data.severity:null) });
      if(pObj)pObj.flagged=true;
      var flaggedNode=pObj?document.getElementById(pObj.domId):null;if(flaggedNode)flaggedNode.classList.add("flagged");
      updateSbxTabTable("threats");
      filterSbxProcs();
      var banner = document.getElementById("sbxAlertBanner");
      var bannerText = document.getElementById("sbxAlertText");
      if (banner && bannerText) {
        bannerText.textContent = procName + (pid ? (" (PID " + pid + ")") : "") + ": " + det;
        banner.style.display = "flex";
      }
      syncSandboxWorkbench();
      break;
    }
  }
}

function ensureSbxProcessExists(pid, name) {
  if(!Number.isInteger(Number(pid))||Number(pid)<=0)return null;
  if (!sbxProcessMap[pid]) {
    addSbxProcess(pid, 0, name, "");
  }
  return sbxProcessMap[pid];
}

function addSbxProcess(pid, parentPid, name, details) {
  if(!Number.isInteger(Number(pid))||Number(pid)<=0)return;
  if (sbxProcessMap[pid]) return;
  
  var domId = "sbx-node-" + pid;
  sbxProcessMap[pid] = {
    pid: pid,
    ppid: parentPid,
    name: name,
    args: details || "",
    domId: domId,
    files: 0,
    reg: 0,
    net: 0,
    mut: 0
  };
  
  var parentContainer = document.getElementById("liveProcessTree");
  if (parentPid && sbxProcessMap[parentPid]) {
    var pNode = document.getElementById(sbxProcessMap[parentPid].domId);
    if (pNode) {
      var childList = pNode.querySelector(".sbx-pt-children");
      if (childList) parentContainer = childList;
    }
  }
  
  var node = document.createElement("div");
  node.className = "sbx-pt-node";
  node.id = domId;
  
  var row = document.createElement("div");
  row.className = "sbx-pt-row";row.tabIndex=0;row.setAttribute("role","button");row.setAttribute("aria-label",name+", PID "+pid);
  row.onclick = function() {
    if(sbxSelectedPid===pid){deselectSandboxProcess();return;}
    document.querySelectorAll(".sbx-pt-row").forEach(function(x) { x.classList.remove("active"); });
    row.classList.add("active");
    selectSandboxProcess(pid);
  };
  row.onkeydown=function(ev){
    if(ev.key==="Escape"){deselectSandboxProcess();return;}
    if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();row.click();}
  };
  
  if (parentPid && sbxProcessMap[parentPid]) {
    var branch = document.createElement("span");
    branch.className = "sbx-pt-branch";
    row.appendChild(branch);
  }
  
  var ico = document.createElement("span");
  ico.className = "sbx-pt-ico";
  if (name.indexOf("powershell") >= 0 || name.indexOf("cmd") >= 0) {
    ico.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M4 17l6-6-6-6M12 19h8"/></svg>';
  } else if (name.indexOf("svchost") >= 0 || name.indexOf("services") >= 0) {
    ico.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 17V7M15 17V7"/></svg>';
  } else {
    ico.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
  }
  row.appendChild(ico);
  
  var pName = document.createElement("span");
  pName.className = "sbx-pt-name";
  pName.textContent = name;
  pName.title = name;
  row.appendChild(pName);
  
  var pPid = document.createElement("span");
  pPid.className = "sbx-pt-pid";
  pPid.textContent = pid;
  row.appendChild(pPid);
  
  var pArgs = document.createElement("span");
  pArgs.className = "sbx-pt-args";
  var cleanedArgs = (details || "").replace(/ParentPID=\d+/i, "").trim();
  pArgs.textContent = cleanedArgs || "";
  pArgs.title = details;
  row.appendChild(pArgs);
  
  var counts = document.createElement("div");
  counts.className = "sbx-pt-counts";
  
  var fCount = document.createElement("span");
  fCount.className = "sbx-pt-cnt f-cnt";
  fCount.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg> 0';
  counts.appendChild(fCount);
  
  var rCount = document.createElement("span");
  rCount.className = "sbx-pt-cnt r-cnt";
  rCount.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18M15 3v18M3 9h18M3 15h18"/></svg> 0';
  counts.appendChild(rCount);
  
  var nCount = document.createElement("span");
  nCount.className = "sbx-pt-cnt n-cnt";
  nCount.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg> 0';
  counts.appendChild(nCount);
  
  var mCount = document.createElement("span");
  mCount.className = "sbx-pt-cnt m-cnt";
  mCount.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> 0';
  counts.appendChild(mCount);
  
  counts.appendChild(fCount);
  counts.appendChild(rCount);
  counts.appendChild(nCount);
  counts.appendChild(mCount);
  
  row.appendChild(counts);
  node.appendChild(row);
  
  var childDiv = document.createElement("div");
  childDiv.className = "sbx-pt-children";
  node.appendChild(childDiv);
  
  parentContainer.appendChild(node);
  
  var keys = Object.keys(sbxProcessMap);
  document.getElementById("sbxProcCount").textContent = keys.length;
  filterSbxProcs();
}

function updateSbxProcessDOMCounters(pid) {
  var p = sbxProcessMap[pid];
  if (!p) return;
  var node = document.getElementById(p.domId);
  if (!node) return;
  
  var fNode = node.querySelector(".f-cnt");
  if (fNode) { fNode.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg> ' + p.files; fNode.classList.toggle("active", p.files > 0); }
  
  var rNode = node.querySelector(".r-cnt");
  if (rNode) { rNode.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18M15 3v18M3 9h18M3 15h18"/></svg> ' + p.reg; rNode.classList.toggle("active", p.reg > 0); }
  
  var nNode = node.querySelector(".n-cnt");
  if (nNode) { nNode.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg> ' + p.net; nNode.classList.toggle("active", p.net > 0); }
  
  var mNode = node.querySelector(".m-cnt");
  if (mNode) { mNode.innerHTML = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> ' + p.mut; mNode.classList.toggle("active", p.mut > 0); }
}

function switchSbxTab(tab) {
  if(tab==="frida"&&curTarget&&curTarget.kind==="vm")return;
  document.querySelectorAll(".sbx-tab-btn").forEach(function(x) {
    var active=x.getAttribute("data-sbxtab")===tab;
    x.classList.toggle("active",active);x.setAttribute("aria-selected",String(active));x.tabIndex=active?0:-1;
  });
  document.querySelectorAll(".sbx-tab-pane").forEach(function(x) {
    x.classList.toggle("active", x.id === "sbxtp-" + tab);
  });
  var toolbar=document.querySelector(".sbx-event-toolbar");if(toolbar)toolbar.hidden=(tab==="frida"||tab==="report");
  filterSandboxRows();
}

function updateSbxTabTable(tab) {
  var el = document.getElementById("sbxtbl-" + tab);
  if (!el) return;
  
  if (tab === "http") {
    document.getElementById("sbxHttpCount").textContent = sbxHttpRequests.length;
    if (!sbxHttpRequests.length) { el.innerHTML = "<div class='tempty'>Waiting for traffic...</div>"; return; }
    
    var h = "<table class='dtbl'><thead><tr><th>Time</th><th>Method / status</th><th>PID</th><th>Process</th><th>URL</th></tr></thead><tbody>";
    sbxHttpRequests.forEach(function(r) {
      h += "<tr><td>" + e(r.timeshift) + "</td><td><span class='chip c-low'>" + e(r.method) + " : " + e(r.status) + "</span></td><td>" + e(r.pid) + "</td><td>" + e(r.procName) + "</td><td>" + e(r.url) + "</td></tr>";
    });
    el.innerHTML = h + "</tbody></table>";
  }
  else if (tab === "conn") {
    document.getElementById("sbxConnCount").textContent = sbxConnections.length;
    if (!sbxConnections.length) { el.innerHTML = "<div class='tempty'>Waiting for connections...</div>"; return; }
    
    var h = "<table class='dtbl'><thead><tr><th>Timeshift</th><th>Proto</th><th>PID</th><th>Process</th><th>Source</th><th>Destination</th><th>Status</th></tr></thead><tbody>";
    sbxConnections.forEach(function(c) {
      h += "<tr><td>" + e(c.timeshift) + "</td><td>" + e(c.protocol) + "</td><td>" + e(c.pid) + "</td><td>" + e(c.procName) + "</td><td>" + e(c.source) + "</td><td>" + e(c.destination) + "</td><td><span class='chip c-info'>" + e(c.status) + "</span></td></tr>";
    });
    el.innerHTML = h + "</tbody></table>";
  }
  else if (tab === "dns") {
    document.getElementById("sbxDnsCount").textContent = sbxDnsRows.length;
    if (!sbxDnsRows.length) { el.innerHTML = "<div class='tempty'>Waiting for DNS queries...</div>"; return; }
    var h = "<table class='dtbl'><thead><tr><th>Timeshift</th><th>PID</th><th>Process</th><th>Query / Response</th></tr></thead><tbody>";
    sbxDnsRows.forEach(function(q) {
      h += "<tr><td>" + e(q.timeshift) + "</td><td>" + e(q.pid) + "</td><td>" + e(q.process) + "</td><td>" + e(q.query) + "</td></tr>";
    });
    el.innerHTML = h + "</tbody></table>";
  }
  else if (tab === "threats") {
    document.getElementById("sbxThreatCount").textContent = sbxThreats.length;
    if (!sbxThreats.length) { el.innerHTML = "<div class='tempty'>No alerts in collected data. This is not a clean verdict.</div>"; return; }
    
    var h = "<table class='dtbl'><thead><tr><th>Timeshift</th><th>PID</th><th>Process</th><th>Severity</th><th>Type</th><th>Description</th></tr></thead><tbody>";
    sbxThreats.forEach(function(t) {
      h += "<tr><td>" + e(t.timeshift) + "</td><td>" + e(t.pid) + "</td><td>" + e(t.procName) + "</td><td>" + (t.severity==null?"<span class='chip c-crit'>Alert</span>":sevChip(t.severity)) + "</td><td><span class='chip c-crit'>" + e(t.type) + "</span></td><td>" + e(t.description) + "</td></tr>";
    });
    el.innerHTML = h + "</tbody></table>";
  }
  filterSandboxRows();
}

function filterSbxProcs() {
  var input=document.getElementById("sbxProcInput"),only=document.getElementById("sbxFlaggedOnly");
  var query=(input.value||"").trim().toLowerCase(),keep=new Set(),matches=new Set();
  Object.keys(sbxProcessMap).forEach(function(key){var p=sbxProcessMap[key];
    if((String(p.name)+" "+p.pid+" "+p.args).toLowerCase().indexOf(query)<0||(only.checked&&!p.flagged))return;
    matches.add(String(p.pid));var current=p,seen=new Set();
    while(current&&!seen.has(String(current.pid))){seen.add(String(current.pid));keep.add(String(current.pid));current=sbxProcessMap[current.ppid];}
  });
  Object.keys(sbxProcessMap).forEach(function(key){var p=sbxProcessMap[key],node=document.getElementById(p.domId);if(!node)return;
    node.style.display=keep.has(String(p.pid))?"":"none";
    node.classList.toggle("filter-context",keep.has(String(p.pid))&&!matches.has(String(p.pid)));
  });
  var tree=document.getElementById("liveProcessTree");tree.dataset.emptyMessage=Object.keys(sbxProcessMap).length?"No matching processes":"Processes appear here when the engine observes them.";
  tree.classList.toggle("is-empty",matches.size===0);
}

function toggleSbxNetOpts() {
  var chk = document.getElementById("netChk");
  var sub = document.getElementById("sbxNetSubOpts");
  if(chk && sub) sub.style.display = chk.checked ? "flex" : "none";
  if(curMode==="sandbox"){buildOsMenu();refreshBtn();}
}

// The run-bar Internet switch mirrors the "Allow network access" setting.
// netChk stays the single source of truth; this only keeps the two in sync
// and remembers the choice across page reloads.
function syncNetToggle(src){
  var main=document.getElementById("netChk"),mirror=document.getElementById("sbxNetToggle");
  if(!main||!mirror)return;
  var on=(src===mirror)?mirror.checked:main.checked;
  main.checked=on;mirror.checked=on;
  try{localStorage.setItem("sbxAllowNet",on?"1":"0");}catch(e){}
  uiText("sbxNetToggleState",pageT(on?"on":"off"));
  toggleSbxNetOpts();
}
(function initNetToggle(){
  var on=false;
  try{on=localStorage.getItem("sbxAllowNet")==="1";}catch(e){}
  var main=document.getElementById("netChk"),mirror=document.getElementById("sbxNetToggle");
  if(main)main.checked=on;
  if(mirror)mirror.checked=on;
  uiText("sbxNetToggleState",pageT(on?"on":"off"));
})();

function toggleSbxFridaOpts(){
  var c=document.getElementById("sbxFrida");
  var o=document.getElementById("sbxFridaOpts");
  if(o) o.style.display=(c&&c.checked)?"flex":"none";
}

// ── target environment picker ──────────────────────────────────────────────
// Execution is routed to an explicitly selected VMware guest or Android target.
// The analyzer's own host remains unavailable for uploaded sample execution.
function hostRunnableWindows(){return ENV&&ENV.host&&ENV.host.os==="windows";}
function androidAvailable(){var a=ENV&&ENV.android;return !!a&&((a.deviceDetails||[]).some(function(d){return d.state==="device";})||((a.avds||[]).length&&a.emulatorAvailable&&a.adbAvailable));}
function targetKey(r){return r?r.key||r.env+":"+(r.serial||r.avd||r.label):"";}
function environmentRows(env,fileName,allowNetwork){
  var rows=[],fam=familyForFile(fileName),ext=(String(fileName||"").toLowerCase().match(/\.[a-z0-9]+$/)||[""])[0];
  if(env&&env.host){
    var H=env.host,hos=H.os;
    var hFam=H.family||(hos==="windows"?"windows":hos==="darwin"?"macos":hos==="linux"?"linux":"any");
    var hIco=H.icon||(hos==="windows"?"win":hos==="darwin"?"macos":hos==="linux"?"linux":"other");
    var label=H.label||(hos+" analyzer host");
    if(H.hostname)label=H.hostname+" · "+(hos==="windows"?"Windows":hos==="darwin"?"macOS":H.android?"Android":H.distro||hos);
    var hRun=false;
    var why="Execution on this PC is blocked. Use the remote VM collector (-sandbox-remote-config); reports stay on this PC.";
    if(fileName&&fam!==hFam&&fam!=="any")why="This file needs a "+fam+" target. Your PC remains listed, but cannot execute this format.";
    if(H.android)why="This Android device runs the analyzer itself. Use a separate disposable device or AVD.";
    rows.push({key:"host",kind:"host",group:"Analyzer host",env:hFam,label:label,sub:(H.sub||H.arch||"")+(H.cpuCount?" · "+H.cpuCount+" logical CPUs":""),ico:hIco,family:hFam,
      compatible:(fam==="any"||fam===hFam),runnable:hRun,detected:true,
      reason:hRun?"":why});
  }
  ["vbox","vmware"].forEach(function(provider){(env&&env[provider]||[]).forEach(function(vm){
    var f=osTypeFamily(vm.osType);
    var stale=provider==="vmware"&&!vm.running&&!vm.registered;
    var compatible=!fileName||[".exe",".com",".bat",".cmd",".ps1"].indexOf(ext)>=0;
    var canRun=provider==="vmware"&&!!env.vmwareExecution&&!stale&&f==="windows"&&compatible;
    var reason=stale?"Файл конфигурации найден на диске, но ВМ нет в библиотеке VMware.":provider!=="vmware"?"ВМ обнаружена, но адаптер исполнения VirtualBox не реализован.":!env.vmwareExecution?"Для запуска нужен vmrun и Windows-сборка анализатора.":f!=="windows"?"Исполнение поддерживается в гостевой Windows.":!compatible?"Выберите EXE, COM, BAT, CMD или PowerShell-файл.":"";
    rows.push({key:vm.id||provider+":"+vm.name,kind:"vm",group:provider==="vbox"?"VirtualBox":"VMware",env:provider+":"+vm.name,label:vm.name,sub:(vm.osType||"Virtual machine")+(stale?" · config on disk, not in library":""),ico:provider,family:f,compatible:provider==="vmware"?compatible&&(f==="windows"):fam==="any"||f==="any"||f===fam,runnable:canRun,detected:true,running:vm.running,registered:vm.registered,reason:reason});
  });});
  var ad=env&&env.android||{},compatible=!fileName||[".apk",".xapk",".apks"].indexOf(ext)>=0;
  (ad.deviceDetails||[]).forEach(function(d){
    var ready=d.state==="device",why=ready?"":"Device is "+d.state+". Check USB debugging authorization and cable.";
    if(ready&&!allowNetwork)why="Offline execution is unavailable. Use live network only on a disposable, externally isolated device.";
    if(!compatible)why="Android execution supports APK, XAPK and APKS only.";
    rows.push({key:"device:"+d.serial,kind:"device",group:"Android devices",env:"android",serial:d.serial,avd:"",label:d.model||d.serial,sub:d.serial+" · "+d.state,ico:"android",family:"android",compatible:compatible,runnable:ready&&compatible&&allowNetwork,detected:true,running:ready,reason:why});
  });
  (ad.avds||[]).forEach(function(name){
    var tools=ad.adbAvailable&&ad.emulatorAvailable;
    rows.push({key:"avd:"+name,kind:"avd",group:"Android emulators",env:"android",serial:"",avd:name,label:name,sub:"Configured AVD · persistent disk",ico:"android",family:"android",compatible:compatible,runnable:!!tools&&compatible&&allowNetwork,detected:true,reason:!tools?"ADB and Android emulator are required to start this AVD.":!compatible?"Select an APK, XAPK or APKS.":!allowNetwork?"Android network isolation is not implemented. Use an externally isolated disposable AVD.":""});
  });
  return rows;
}
function buildOsMenu(){
  var menu=document.getElementById("osMenu");if(!menu)return;
  if(sbxBusy())return; // never change the target identity during a run
  curFamily=sf?familyForFile(sf.name):"any";
  var rows=environmentRows(ENV,sf?sf.name:"",document.getElementById("netChk").checked);
  if(!envFresh)rows.forEach(function(r){if(r.kind!=="host"){r.runnable=false;r.reason="Device discovery is incomplete or stale. Refresh before execution.";}});
  var html="",group="";
  rows.forEach(function(r,idx){
    if(r.group!==group){group=r.group;html+="<div class='os-grp'>"+e(group)+"</div>";}
    var tag=r.runnable?(r.ico==="vmware"?"Гостевой запуск":"Ready"):r.kind==="host"?"Detected":r.kind==="vm"?(r.ico==="vmware"?"Проверка / снимки":"Только обнаружение"):"Unavailable";
    html+="<button type='button' class='os-row"+(r.runnable?" runnable":"")+"' onclick='pickOs("+idx+")'>"+
      "<span class='os-row-ico'>"+(OS_ICONS[r.ico]||OS_ICONS.other)+"</span><span class='os-row-main'><span class='os-row-name'>"+e(r.label)+"</span>"+
      "<span class='os-row-sub'>"+e(r.sub||"")+"</span>"+(r.reason?"<span class='os-row-why'>"+e(r.reason)+"</span>":"")+"</span><span class='os-tag "+(r.runnable?"run":"off")+"'>"+tag+"</span></button>";
  });
  if(!rows.length)html="<div class='os-empty'>"+e(hostError?"Host discovery failed. Retry below.":"Detecting the analyzer host…")+"</div>";
  var st=menu.scrollTop;
  menu.innerHTML=html;menu._rows=rows;
  menu.scrollTop=st;
  var preferred=rows.filter(function(r){return targetKey(r)===selectedTargetKey;})[0];
  if(!preferred&&selectionExplicit){applyTarget(null);uiText("osNote","The selected target disconnected. Choose a target again; another device will not be used automatically.");show("osNote",true);}
  else{if(!preferred||(!selectionExplicit&&!preferred.compatible))preferred=rows.filter(function(r){return r.compatible&&r.runnable;})[0]||rows.filter(function(r){return r.compatible;})[0]||rows[0];applyTarget(preferred||null);}
  uiText("envDiscoveryStatus",envError?"Optional discovery failed: "+envError:envState==="loading"?"Checking attached devices and virtual machines…":"Only detected targets are listed. Host = the machine running the analyzer.");
}

function osTypeFamily(t){
  t=(t||"").toLowerCase();
  if(t.indexOf("windows")>=0||t.indexOf("win")>=0)return "windows";
  if(t.indexOf("linux")>=0||t.indexOf("ubuntu")>=0||t.indexOf("debian")>=0||t.indexOf("fedora")>=0)return "linux";
  if(t.indexOf("mac")>=0||t.indexOf("osx")>=0||t.indexOf("darwin")>=0)return "macos";
  if(t.indexOf("android")>=0)return "android";
  return "any";
}

function pickOs(idx){
  var menu=document.getElementById("osMenu"),r=menu&&menu._rows&&menu._rows[idx];if(!r||sbxBusy())return;
  selectionExplicit=true;selectedTargetKey=targetKey(r);applyTarget(r);closeOsMenu();
}

function applyTarget(r){
  uiText("sbxIntakeTargetHint",r?r.label+" · "+(r.kind==="host"?"native host, not a VM":"selected "+r.kind):"No target detected. Devices appear only after detection.");
  var changed=targetKey(curTarget)!==targetKey(r);
  if(changed)document.getElementById("sbxConsent").checked=false;
  curTarget=r;curEnv=r?(r.kind==="vm"?(r.ico==="vmware"&&r.family==="windows"?"windows":r.env.split(":")[0]):r.env):"";
  if(r)selectedTargetKey=targetKey(r);
  document.getElementById("osPickIco").innerHTML=r?(OS_ICONS[r.ico]||OS_ICONS.other):OS_ICONS.other;
  uiText("osPickName",r?r.label:hostError?"Host discovery unavailable":"Detecting environments…");
  var badge=document.getElementById("osPickBadge");badge.style.display=r?"":"none";badge.className="os-pick-badge "+(r&&r.runnable?"run":"off");badge.textContent=r&&r.runnable?(r.ico==="vmware"?"Гостевая Windows":"Ready"):"Not runnable";
  document.getElementById("sbxWinConfigOpts").style.display=curEnv==="windows"?"flex":"none";
  document.getElementById("sbxAndConfigOpts").style.display=curEnv==="android"?"flex":"none";
  uiText("androidTargetDetail",r&&r.kind==="device"?"Device serial: "+r.serial:r&&r.kind==="avd"?"AVD: "+r.avd+". Cold boot does not wipe its disk.":"");
  var note=document.getElementById("osNote");note.style.display=r&&!r.runnable?"":"none";note.textContent=r?r.reason||"This target cannot run the selected file.":"";
  updateVMwarePanel(r);
  syncSandboxCapabilities();refreshBtn();syncSandboxWorkbench();
}
var vmwarePanelID="",vmwarePanelGeneration=0,vmwarePanelBusy=false,vmwareReport=null;
var vmwarePanelPower=null,vmwareInspectQueued=false,vmwareInspectTimer=null,vmwareCredentialGeneration=0;
function invalidateVMwareReport(){
  vmwarePanelGeneration++;vmwareReport=null;
  document.getElementById("vmwareChecks").replaceChildren();document.getElementById("vmwareSnapshot").replaceChildren();
  document.getElementById("vmwareStatus").textContent="Проверяю настройки выбранной ВМ…";
  document.getElementById("vmwareSnapshots").style.display="none";
}
function flushVMwareInspection(){
  if(!vmwareInspectQueued||!vmwarePanelID||vmwarePanelBusy||sbxBusy()||vmwareInspectTimer!==null)return;
  vmwareInspectTimer=setTimeout(function(){
    vmwareInspectTimer=null;
    if(vmwareInspectQueued&&vmwarePanelID&&!vmwarePanelBusy&&!sbxBusy())vmwareAction("inspect");
  },0);
}
function updateVMwarePanel(r){
  var panel=document.getElementById("vmwarePanel");if(!panel)return;
  var id=r&&r.kind==="vm"&&r.ico==="vmware"&&!(!r.running&&!r.registered)?r.key:"";
  panel.style.display=id?"flex":"none";
  var changed=id!==vmwarePanelID,power=id?!!r.running:null;
  if(changed||power!==vmwarePanelPower){
    vmwarePanelID=id;vmwarePanelPower=power;invalidateVMwareReport();
    if(changed){
      document.getElementById("vmwareUser").value="";document.getElementById("vmwarePassword").value="";
      document.getElementById("vmwareCredentialFile").value="";vmwareCredentialsChanged();
    }
    vmwareInspectQueued=!!id;
  }
  flushVMwareInspection();syncVMwareButtons();
}
function vmwareCredentialsChanged(message){
  vmwareCredentialGeneration++;
  document.getElementById("vmwareCredentialStatus").textContent=message||"";
  refreshBtn();
}
async function importVMwareCredentials(file){
  if(!file||!vmwarePanelID||sbxBusy())return;
  var id=vmwarePanelID,generation=++vmwareCredentialGeneration;
  var status=document.getElementById("vmwareCredentialStatus");
  status.textContent="Читаю файл учётной записи…";
  try{
    if(file.size>8192)throw new Error("invalid credentials file");
    var data=JSON.parse((await file.text()).replace(/^\uFEFF/,""));
    if(!data||typeof data!=="object"||typeof data.username!=="string"||!data.username.trim()||data.username.length>256||typeof data.password!=="string"||!data.password||data.password.length>1024||/[\x00\r\n]/.test(data.username+data.password))throw new Error("invalid credentials file");
    if(id!==vmwarePanelID||generation!==vmwareCredentialGeneration||sbxBusy())return;
    if(data.vm&&data.vm!==curTarget.label&&data.vm!==id){status.textContent="Файл учётных данных относится к другой ВМ. Выберите файл для текущей гостевой Windows.";return;}
    document.getElementById("vmwareUser").value=data.username.trim();
    document.getElementById("vmwarePassword").value=data.password;
    status.textContent="Загружены имя и пароль пользователя "+data.username.trim()+". Данные готовы для одного запуска.";
  }catch(err){
    // JSON parser errors can contain input text, including the password.
    if(id===vmwarePanelID&&generation===vmwareCredentialGeneration&&!sbxBusy())status.textContent="Не удалось загрузить учётные данные. Выберите JSON-файл с полями username и password и непустым паролем.";
  }finally{
    if(id===vmwarePanelID&&generation===vmwareCredentialGeneration)document.getElementById("vmwareCredentialFile").value="";
    refreshBtn();
  }
}
function syncVMwareButtons(){
  var off=vmwareReport&&!vmwareReport.running&&!vmwareReport.suspended,busy=vmwarePanelBusy||sbxBusy();
  document.getElementById("vmwareInspect").disabled=busy;
  document.getElementById("vmwarePrepare").disabled=busy||!!(vmwareReport&&(vmwareReport.running||vmwareReport.suspended));
  document.getElementById("vmwareCreate").disabled=busy||!off;
  var select=document.getElementById("vmwareSnapshot");select.disabled=busy;
  document.getElementById("vmwareRestore").disabled=busy||!off||!select.value;
  ["vmwareUser","vmwarePassword","vmwareLoadCredentials","vmwareCredentialFile"].forEach(function(id){document.getElementById(id).disabled=sbxBusy();});
  document.getElementById("vmwareSnapshotName").textContent=select.value||"";
}
function renderVMwareReport(report){
  vmwareReport=report;
  var power=report.running?"ВМ включена":report.suspended?"ВМ приостановлена":"ВМ выключена";
  var tools=report.tools&&report.tools!==power?" "+report.tools+".":"";
  document.getElementById("vmwareStatus").textContent=power+"."+tools+" "+report.notice;
  var checks=document.getElementById("vmwareChecks");checks.replaceChildren();
  (report.checks||[]).forEach(function(check){var item=document.createElement("li");item.textContent=(check.ok?"Настройка проверена: ":"Внимание: ")+check.message;checks.appendChild(item);});
  document.getElementById("vmwareAudit").open=!report.configurationPass;
  uiText("vmwareAuditSummary","Проверка конфигурации: "+(report.checks||[]).filter(function(check){return check.ok;}).length+" / "+(report.checks||[]).length);
  var select=document.getElementById("vmwareSnapshot");select.replaceChildren();var restorable=0;
  (report.snapshots||[]).forEach(function(snapshot){if(!snapshot.restorable)return;restorable++;var option=document.createElement("option");option.value=snapshot.name;option.textContent=snapshot.name;select.appendChild(option);});
  if(!restorable){var empty=document.createElement("option");empty.value="";empty.textContent="Нет подтверждённых исходных снимков";select.appendChild(empty);}
  if(report.lastSnapshot)select.value=report.lastSnapshot;
  document.getElementById("vmwareSnapshots").style.display="flex";syncVMwareButtons();refreshBtn();
}
async function vmwareAction(action){
  if(vmwarePanelBusy||!vmwarePanelID||sbxBusy())return;
  var id=vmwarePanelID,generation=vmwarePanelGeneration,body={id:id,action:action};
  if(action==="create-baseline"){
    if(!vmwareReport||vmwareReport.running||vmwareReport.suspended)return;
    if(!window.confirm("Создать снимок выключенной ВМ? Это сохранит текущее состояние, но не подтвердит, что система чистая. Не управляйте этой ВМ одновременно из другого окна."))return;
    body.confirmation="СОЗДАТЬ СНИМОК";
  }
  if(action==="restore-baseline"){
    if(!vmwareReport||vmwareReport.running||vmwareReport.suspended)return;
    body.snapshot=document.getElementById("vmwareSnapshot").value;if(!body.snapshot)return;
    var typed=window.prompt("Все изменения ВМ после снимка будут потеряны. Для подтверждения введите полное имя снимка:\n"+body.snapshot);
    if(typed!==body.snapshot)return;body.confirmation=typed;
  }
  vmwareInspectQueued=false;vmwarePanelBusy=true;syncVMwareButtons();refreshBtn();document.getElementById("vmwareStatus").textContent="Выполняется операция VMware… Не закрывайте анализатор.";
  try{
    var response=await fetch("/api/vmware",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    var report=await response.json();if(!response.ok)throw new Error(report.error||"Ошибка VMware: "+response.status);
    if(id!==vmwarePanelID||generation!==vmwarePanelGeneration)return;
    if(typeof report.running!=="boolean"||typeof report.suspended!=="boolean"||typeof report.guestExecution!=="boolean"||typeof report.configurationPass!=="boolean"||!Array.isArray(report.checks)||!Array.isArray(report.snapshots))throw new Error("Неполный ответ сервера VMware");
    renderVMwareReport(report);
  }catch(err){if(id===vmwarePanelID&&generation===vmwarePanelGeneration){vmwareReport=null;document.getElementById("vmwareChecks").replaceChildren();document.getElementById("vmwareSnapshot").replaceChildren();document.getElementById("vmwareSnapshots").style.display="none";document.getElementById("vmwareStatus").textContent="Операция не подтверждена: "+err.message+". Повторите проверку состояния; не повторяйте создание снимка вслепую.";}}
  finally{vmwarePanelBusy=false;syncVMwareButtons();refreshBtn();flushVMwareInspection();}
}
document.getElementById("vmwareSnapshot").addEventListener("change",syncVMwareButtons);

function syncSandboxCapabilities(){
  var vmOnly=!!(curTarget&&curTarget.kind==="vm");
  var vmware=isVMwareTarget();
  var android=curEnv==="android",limits=curEnv==="windows"||(curTarget&&curTarget.kind==="avd");
  ["netChk","sbxNetToggle"].forEach(function(id){document.getElementById(id).disabled=vmOnly;if(vmware)document.getElementById(id).checked=false;});
  if(vmware)uiText("sbxNetToggleState",pageT("off"));
  document.getElementById("sbxConsent").disabled=vmOnly&&!vmware;
  document.getElementById("sbxConsent").closest("label").style.display=vmOnly&&!vmware?"none":"";
  var consent=document.getElementById("sbxConsentText");consent.dataset.i18n=vmware?"vmwareConsent":"consent";consent.textContent=pageT(consent.dataset.i18n);
  document.getElementById("sbxNativeNotice").style.display=vmware?"none":"";
  ["sbxcpu-r","sbxram-r"].forEach(function(id){document.getElementById(id).disabled=!limits;});
  uiText("sbxLimitsNote",vmware?"Лимит RAM и привязка к выбранному числу ядер применяются к процессу внутри гостевой Windows. Память и ядра основной Windows не меняются.":vmOnly?"Для этой ВМ исполнение пока не поддерживается.":curTarget&&curTarget.kind==="device"?"CPU / RAM limits cannot be applied to an attached Android device.":curTarget&&curTarget.kind==="avd"?"CPU / RAM apply only when starting an AVD, not to an already-running emulator.":"Windows: per-process RAM cap; best-effort CPU affinity. Neither is VM isolation.");
  document.getElementById("sbxCmdArgs").disabled=!(!android&&curEnv==="windows");
  ["sbxUninstall","sbxCapture","sbxFrida","sbxFridaScript"].forEach(function(id){document.getElementById(id).disabled=!android;});
  show("sbxAndroidOnlyNote",!android);
  // Features without a trustworthy end-to-end implementation remain unavailable.
  ["netFake","netTor","netRes","netMitm","sbxFridaSpawn","sbxMITM"].forEach(function(id){var el=document.getElementById(id);if(el){el.checked=false;el.disabled=true;}});
  uiText("sbxNetworkHelp",vmware?"VMware-анализ работает с отключёнными виртуальными сетевыми адаптерами. Файлы и события передаются через VMware Tools.":vmOnly?"Этот переключатель не меняет сеть ВМ.":android?"Blocking is unavailable on Android: the run will not start with blocking requested. Radio settings are never changed. Network access must be deliberately allowed on an externally isolated lab device.":"Unchecked: Windows Firewall rules for the launched executable only. Descendant processes are not covered. Use an externally isolated analysis host.");
  show("sbxFridaOpts",android&&document.getElementById("sbxFrida").checked);
  syncFridaToolbar();
}
// The Frida tab doubles as a terminal REPL on the Windows host: server push
// and APK repack are Android-only, so they hide and the status guides.
function syncFridaToolbar(){
  var host=(curEnv==="windows"&&curTarget&&curTarget.kind==="host");
  var vm=!!(curTarget&&curTarget.kind==="vm");
  var start=document.getElementById("fridaStartBtn"),repack=document.getElementById("fridaRepackBtn");
  if(start)start.style.display=host||vm?"none":"";
  if(repack)repack.style.display=host||vm?"none":"";
  document.querySelectorAll("#sbxtp-frida button,#sbxtp-frida select,#sbxtp-frida input").forEach(function(control){control.disabled=vm;});
  var tab=document.getElementById("fridaTabBtn");
  if(tab){tab.disabled=vm;tab.title=vm?"Frida для гостевой ВМ пока недоступна":"";if(vm&&tab.classList.contains("active"))switchSbxTab("activity");}
  if(vm&&_fridaWS)fridaDetach();
  var st=document.getElementById("fridaStatus");
  if(vm){if(st)st.textContent="Frida для гостевой ВМ пока недоступна";return;}
  if(st&&(st.textContent==="frida-server not started"||st.textContent.indexOf("Local frida")===0||st.textContent.indexOf("Frida для гостевой ВМ")===0))
    st.textContent=host?"Local frida · press Refresh to list PC processes (attach to inspect, system processes can crash Windows)":"frida-server not started";
}

function toggleOsMenu(ev){
  if(ev)ev.stopPropagation();
  osMenuOpen?closeOsMenu():openOsMenu();
}
function openOsMenu(){
  var menu=document.getElementById("osMenu");if(!menu)return;
  if(!menu.innerHTML)buildOsMenu();
  var btn=document.getElementById("osPickBtn");
  var r=btn.getBoundingClientRect();
  menu.style.display="block";
  menu.style.left=r.left+"px";
  menu.style.width=r.width+"px";
  var spaceBelow=window.innerHeight-r.bottom-8;
  if(spaceBelow>=menu.scrollHeight||spaceBelow>=200){
    menu.style.top=(r.bottom+6)+"px";
    menu.style.bottom="";
  } else {
    menu.style.bottom=(window.innerHeight-r.top+6)+"px";
    menu.style.top="";
  }
  btn.classList.add("open");osMenuOpen=true;
}
function closeOsMenu(){
  var menu=document.getElementById("osMenu");if(menu)menu.style.display="none";
  var b=document.getElementById("osPickBtn");if(b)b.classList.remove("open");osMenuOpen=false;
}
document.addEventListener("click",function(ev){
  if(!osMenuOpen)return;
  if(!ev.target.closest("#osMenu")&&!ev.target.closest("#osPickBtn"))closeOsMenu();
});
window.addEventListener("scroll",function(ev){if(osMenuOpen&&!document.getElementById("osMenu").contains(ev.target))closeOsMenu();},true);

var curFamily="any";

// route finished jobs: sandbox → ANY.RUN-style dashboard, everything else → findings table
function loadFinal(id){if(jid!==id)return;liveStop(curMode==="sandbox");if(curMode==="sandbox")loadSandbox(id);else loadRes(id);}

var SO=["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
var SC={CRITICAL:"c-crit",HIGH:"c-high",MEDIUM:"c-med",LOW:"c-low",INFO:"c-info"};

function findingLocation(f){
  var loc=(f.locations||[]).find(function(v){return v&&typeof v.file==="string"&&v.file;})||f.location||{};
  var file=typeof f.File==="string"?f.File:typeof f.file==="string"?f.file:typeof loc.file==="string"?loc.file:"";
  if(!file&&Array.isArray(f.evidence)){
    var ev=f.evidence.find(function(v){return v&&v.location&&typeof v.location.file==="string"&&v.location.file;});
    if(ev){loc=ev.location;file=loc.file;}
  }
  return file?file.replace(/\\/g,"/")+(loc.line>0?":"+loc.line:""):loc.method||"—";
}

// Typed findings and artifact_findings are projections of the same evidence.
function collectResultFindings(data){
  var base=(Array.isArray(data)?data:(data.findings||data.results||[])).slice();
  // The typed projection includes artifact evidence with its final severity.
  if(Array.isArray(data)||Array.isArray(data.findings))return base;
  var key=function(f){
    var loc=(f.locations||[])[0]||{};
    var ev=(f.evidence||[])[0]||{};
    return JSON.stringify([(f.severity||f.Severity||"INFO").toUpperCase(),f.title||f.Title||f.pattern||f.Pattern||f.reason||"",(loc.file||f.path||f.file||"").replace(/\\/g,"/"),ev.snippet||f.payload||""]);
  };
  var seen=new Set(base.map(key));
  (data.artifact_findings||[]).forEach(function(a){
    if(seen.has(key(a)))return;
    seen.add(key(a));
    var j=a.jvm_evidence;
    base.push({severity:a.severity||"INFO",category:j?j.category:"ARTIFACT",pattern:j?(j.pattern+" · "+(j.evidence_type||"reference")):a.reason,file:j?j.file:a.path,context:j?j.context:a.reason,payload:a.payload});
  });
  return base;
}

function bundleResultSummary(s){
  if(!s||!s.standalone)return "";
  var ru=uiLang==="ru";
  return "<div class='done-card'><div class='dt'>"+e(s.status)+" · "+e(s.observations)+(ru?" наблюдений, ":" observations, ")+e(s.risk_signals)+(ru?" сигналов риска":" risk signals")+"</div><div class='dp'>"+(ru?"Строки: ":"Strings: ")+e(s.strings_scanned)+" / "+e(s.strings_total)+" · "+e(Number(s.elapsed_seconds).toFixed(3))+" s</div><p>"+(ru?"Бандл, не весь APK. Итоговая безопасность НЕ ОЦЕНЕНА. URL и названия API — справочные наблюдения, не подтверждённые уязвимости.":"Bundle scope, not the full APK. Security NOT ASSESSED. URL/API names are inventory, not confirmed vulnerabilities.")+"</p></div>";
}

function staticResultSummary(data){
  if(!data||Array.isArray(data)||(!data.run&&!data.risk_profile))return "";
  var ru=uiLang==="ru",run=data.run||{},risk=data.risk_profile||{};
  var counts={malware:0,vulnerability:0,hardening:0,inventory:0};
  (Array.isArray(data.findings)?data.findings:[]).forEach(function(f){if(f&&Object.prototype.hasOwnProperty.call(counts,f.kind))counts[f.kind]++;});
  var incomplete=run.status==="incomplete";
  var title=incomplete?(ru?"Анализ неполный":"Incomplete analysis"):(ru?"Сводка статического анализа":"Static analysis summary");
  var h="<div class='done-card'><div class='dt'>"+title+"</div>";
  if(Number.isFinite(risk.overall_score))h+="<div class='dp'>"+(ru?"Общий риск: ":"Overall risk: ")+e(risk.overall_level||"")+" · "+e(risk.overall_score)+"/100</div>";
  h+="<div class='dp'>"+(ru?"Признаки вредоносного поведения: ":"Malware indicators: ")+counts.malware+" · "+(ru?"Уязвимости: ":"Vulnerabilities: ")+counts.vulnerability+" · "+(ru?"Усиление защиты: ":"Hardening: ")+counts.hardening+" · "+(ru?"Справочные наблюдения: ":"Inventory: ")+counts.inventory+"</div>";
  if(incomplete){
    h+="<p>"+(run.stop_reason==="timeout"?(ru?"Достигнут лимит времени. Проверьте охват анализа в отчёте.":"Time limit reached. Review analysis coverage in the report."):(ru?"Охват анализа неполный. Причина: ":"Analysis coverage is incomplete. Reason: ")+e(run.stop_reason||"unknown"))+"</p>";
    var df=data.data_flow_stats||{};
    if(df.slices_truncated>0)h+="<p>"+(ru?"Пути data flow ограничены бюджетом: ":"Data-flow slices limited by analysis budget: ")+e(df.slices_truncated)+". "+(ru?"Это ограничение охвата, а не обнаруженная угроза.":"This is a coverage limit, not a detected threat.")+"</p>";
    (Array.isArray(run.limitations)?run.limitations:[]).slice(0,6).forEach(function(value){h+="<p>"+e(value)+"</p>";});
  }
  return h+"</div>";
}

function loadRes(id){
  if(jid!==id)return;
  var generation=scanGeneration,serial=++resultRequest,resultMode=curMode,output=curOut;
  if(resultAbort)resultAbort.abort();resultAbort=new AbortController();
  function current(){return serial===resultRequest&&scanIsCurrent(generation,id,resultMode);}
  var res=document.getElementById("res"),fw=document.getElementById("fw"),dl=document.getElementById("dlbtn"),ob=document.getElementById("openbtn"),chips=document.getElementById("chips");
  res.classList.add("show");
  loadArtifacts(id);
  var hasReport=!!MODES[curMode].report;
  dl.style.display=hasReport?"":"none";
  ob.style.display=hasReport?"":"none";
  dl.href="/api/report/"+id+"?dl=1";
  ob.href="/api/report/"+id;
  if(curMode==="build"||curMode==="decode"){
    chips.innerHTML="";
    var heading=curMode==="build"?(uiLang==="ru"?"Файлы сборки APK":"APK build files"):(uiLang==="ru"?"Декодированный проект":"Decoded project");
    fw.innerHTML="<div class='done-card'><div class='dt'>"+heading+"</div><div class='dp'>"+(uiLang==="ru"?"Папка результата: ":"Result folder: ")+e(output)+"</div></div>";
    return;
  }
  fetch("/api/result/"+id,{signal:resultAbort.signal,cache:"no-store"})
    .then(function(r){return r.ok?r.json():null;})
    .then(function(data){
      if(!current())return;
      if(!data){
        chips.innerHTML="";
        fw.innerHTML="<div class='done-card'><div class='dt'>Summary unavailable — check logs and files below</div><div class='dp'>Result folder: "+e(output)+"</div></div>";
        return;
      }
      var minecraftResult=Array.isArray(data.packs)&&typeof data.complete==="boolean";
      var minecraftSummary=staticResultSummary(data)+bundleResultSummary(data.bundle_analysis);
      if(minecraftResult){
        minecraftSummary="<div class='done-card'><div class='dt'>"+e(data.format)+" · "+(data.complete?"Inspection completed":"Incomplete inspection")+"</div><div class='dp'>"+e(String((data.packs||[]).length))+" packs · "+e(String((data.files||[]).length))+" files · indicator score "+e(String(data.risk_score||0))+"/100. Static indicators are not a malware verdict. Open the report for dependencies and contents.</div></div>";
      }
      var fnd=collectResultFindings(data);
      var cnt={};fnd.forEach(function(f){var s=(f.Severity||f.severity||"INFO").toUpperCase();cnt[s]=(cnt[s]||0)+1;});
      chips.innerHTML="";SO.forEach(function(sv){if(cnt[sv]){var s=document.createElement("span");s.className="chip "+(SC[sv]||"c-info");s.textContent=cnt[sv]+" "+sv;chips.appendChild(s);}});
      if(!fnd.length&&(minecraftResult||data.bundle_analysis)){fw.innerHTML=minecraftSummary;return;}
      if(!fnd.length){fw.innerHTML=minecraftSummary+"<div class='done-card'><div class='dt'>No findings in this result</div><div class='dp'>Output written to "+e(curOut)+"</div></div>";return;}
      var top=fnd.slice().sort(function(a,b){return SO.indexOf((a.Severity||a.severity||"INFO").toUpperCase())-SO.indexOf((b.Severity||b.severity||"INFO").toUpperCase());}).slice(0,5).map(function(f){
        var sv=(f.Severity||f.severity||"INFO").toUpperCase();
        var rule=f.Pattern||f.pattern||f.Rule||f.rule||f.Title||f.title||"";
        return "<div class='done-top'><span class='chip "+(SC[sv]||"c-info")+"'>"+e(sv)+"</span><span>"+e(rule)+"</span></div>";
      }).join("");
      fw.innerHTML=minecraftSummary+"<div class='done-card'><div class='dt'>"+fnd.length+(uiLang==="ru"?" записей — подробности в отчёте":" records — open the report for details")+"</div><div class='dp'>Output written to "+e(curOut)+"</div>"+top+"</div>";
    })
    .catch(function(){if(current())fw.innerHTML="<div class='done-card'><div class='dt'>Summary unavailable — check logs and files below</div><div class='dp'>Result folder: "+e(output)+"</div></div>";});
}

// ── live android view (ANY.RUN-style) ──
var liveTimer=null,liveStreaming=false,liveWS=null,liveDecoder=null,liveCtx=null,liveMode="";
var liveGeneration=0,liveFrameTimer=null,liveRetryTimer=null,liveStatusAbort=null,liveRequestScope="";
var liveRetainTimer=null,liveCanvasHasFrame=false;
var hasWebCodecs=(typeof window.VideoDecoder!=="undefined");

function liveURL(path){
  var query=jid?"job="+encodeURIComponent(jid):curTarget&&curTarget.serial?"serial="+encodeURIComponent(curTarget.serial):"";
  return path+(query?(path.indexOf("?")>=0?"&":"?")+query:"");
}
// fridaURL adds the host flag so the backend lists/attaches local PC
// processes instead of the USB Android device.
function fridaURL(path){
  var u=liveURL(path);
  if(curEnv==="windows"&&curTarget&&curTarget.kind==="host")u+=(u.indexOf("?")>=0?"&":"?")+"host=1";
  return u;
}

function liveStart(){
  var scope=liveURL("/api/live/status");
  if(liveTimer&&liveRequestScope===scope)return;
  if(liveTimer)liveStop(false);
  liveCanvasHasFrame=false;sbxHasFrame=false;document.getElementById("sbxStreamPlaceholder").hidden=false;
  liveRequestScope=scope;
  liveGeneration++;
  liveTick();
  liveTimer=setInterval(liveTick,1500);
}
function stopLiveVideo(){
  clearTimeout(liveFrameTimer);liveFrameTimer=null;
  var ws=liveWS;liveWS=null;
  if(ws){ws.onmessage=ws.onerror=ws.onclose=null;try{ws.close();}catch(e){}}
  var decoder=liveDecoder;liveDecoder=null;
  if(decoder){try{decoder.close();}catch(e){}}
}
function stopLiveImageRetention(){
  if(liveRetainTimer){clearInterval(liveRetainTimer);liveRetainTimer=null;}
}
function retainLiveImageFrame(){
  var img=document.getElementById("liveScreen"),cv=document.getElementById("liveCanvas");
  if(!img||!cv||!img.naturalWidth||!img.naturalHeight)return false;
  try{
    // Preserve pixels while the image is decodable. Closing a multipart stream
    // or starting the next PNG request can invalidate it before the done event.
    var context=cv.getContext("2d");if(!context)return false;
    if(cv.width!==img.naturalWidth||cv.height!==img.naturalHeight){cv.width=img.naturalWidth;cv.height=img.naturalHeight;}
    context.drawImage(img,0,0);liveCanvasHasFrame=true;return true;
  }catch(e){return false;}
}
function liveStop(preserveFrame){
  liveGeneration++;
  if(liveTimer){clearInterval(liveTimer);liveTimer=null;}
  if(liveStatusAbort){liveStatusAbort.abort();liveStatusAbort=null;}
  clearTimeout(liveRetryTimer);liveRetryTimer=null;
  var img=document.getElementById("liveScreen"),cv=document.getElementById("liveCanvas");
  if(preserveFrame&&sbxHasFrame&&liveMode!=="video")retainLiveImageFrame();
  stopLiveImageRetention();
  stopLiveVideo();
  liveStreaming=false;liveMode="";
  liveRequestScope="";
  if(img){img.onload=img.onerror=img.onabort=null;img.removeAttribute("src");img.style.display="none";}
  var retained=!!(preserveFrame&&cv&&liveCanvasHasFrame);
  if(cv)cv.style.display=retained?"":"none";
  sbxHasFrame=retained;document.getElementById("sbxStreamPlaceholder").hidden=retained;
  if(!preserveFrame)liveCanvasHasFrame=false;
}

// poll status to drive the badge; once booted, attach the best stream available
function liveTick(){
  if(liveStatusAbort)return;
  var generation=liveGeneration,controller=new AbortController();liveStatusAbort=controller;
  var timeout=setTimeout(function(){controller.abort();},5000);
  fetch(liveURL("/api/live/status"),{signal:controller.signal}).then(function(r){if(!r.ok)throw new Error("Device status unavailable");return r.json();}).then(function(s){
    if(generation!==liveGeneration)return;
    var badge=document.getElementById("liveBadge"),bt=document.getElementById("liveBadgeT");
    // Locked / sleeping screen → show an English overlay instead of a black frame.
    setLockOverlay(s.serial&&s.booted&&s.screen===false);
    if(s.serial&&s.booted){
      if(badge) badge.classList.remove("off");
      if(!liveStreaming){
        liveStreaming=true;
        // scrcpy-server present → smooth H.264 (WebCodecs); otherwise screenshot mode.
        if(s.scrcpy&&hasWebCodecs)startVideo();else startMjpeg();
      }
      if(bt) bt.textContent=s.serial+(liveMode?(" · "+liveMode):" · live");
    }else if(s.serial){
      if(badge) badge.classList.add("off");
      if(bt) bt.textContent=s.serial+" · booting…";
    }else{
      if(liveStreaming){
        liveStreaming=false;liveMode="";stopLiveVideo();stopLiveImageRetention();clearTimeout(liveRetryTimer);liveRetryTimer=null;
        var img=document.getElementById("liveScreen");img.onload=img.onerror=img.onabort=null;img.removeAttribute("src");
      }
      if(badge) badge.classList.add("off");
      if(bt) bt.textContent="Waiting for device…";
    }
  }).catch(function(){
    if(generation!==liveGeneration)return;
    var bt=document.getElementById("liveBadgeT");if(bt)bt.textContent=uiLang==="ru"?"Не удалось проверить устройство · повторяю…":"Device status unavailable · reconnecting…";
  }).finally(function(){clearTimeout(timeout);if(liveStatusAbort===controller)liveStatusAbort=null;});
}
// setLockOverlay shows/hides the "device is locked" message over the stream.
function setLockOverlay(locked){
  var ov=document.getElementById("sbxLockOverlay");
  if(ov)ov.style.display=locked?"flex":"none";
}

// ── real H.264 video via WebCodecs (ANY.RUN-grade smoothness) ──
// parseAvcCodecString reads SPS NAL bytes (Annex-B) and returns an "avc1.PPCCLL" codec string.
function parseAvcCodecString(au){
  for(var i=0;i+4<au.length;i++){
    if(au[i]===0&&au[i+1]===0&&au[i+2]===1&&(au[i+3]&0x1f)===7&&i+6<au.length){
      var hex=function(b){return("0"+b.toString(16)).slice(-2);};
      return"avc1."+hex(au[i+4])+hex(au[i+5])+hex(au[i+6]);
    }
  }
  return"avc1.42e01e"; // baseline fallback
}
function _setStreamMode(txt,color){
  var m=document.getElementById("sbxStreamMode");
  if(m){m.textContent=txt;m.style.color=color||"#7ba05b";}
}
function startVideo(){
  if(!liveStreaming)return;
  var generation=liveGeneration,decoder=null,ws=null;
  function current(){return liveStreaming&&generation===liveGeneration&&liveMode==="video"&&liveDecoder===decoder;}
  liveMode="video";
  var canvas=document.getElementById("liveCanvas"),img=document.getElementById("liveScreen");
  canvas.style.display="";img.style.display="none";
  _setStreamMode("⚡ HD video","#7ba05b");
  liveCtx=canvas.getContext("2d");
  var configured=false;
  var ts=0;
  var frameCount=0,blackCount=0,blackChecked=false;
  liveFrameTimer=setTimeout(function(){if(current())fallbackMjpeg();},12000);
  try{
    decoder=new VideoDecoder({
      output:function(frame){
        if(!current()){frame.close();return;}
        clearTimeout(liveFrameTimer);liveFrameTimer=null;
        if(canvas.width!==frame.displayWidth||canvas.height!==frame.displayHeight){canvas.width=frame.displayWidth;canvas.height=frame.displayHeight;}
        liveCtx.drawImage(frame,0,0,canvas.width,canvas.height);
        liveCanvasHasFrame=true;
        frame.close();
        sbxHasFrame=true;document.getElementById("sbxStreamPlaceholder").hidden=true;
        // Auto-detect black screen (MediaTek/DRM: real H264 frames but all black pixels).
        // Sample a 5×5 patch at the centre after frame 3 and 8.
        frameCount++;
        if(!blackChecked&&(frameCount===3||frameCount===8)&&canvas.width>10&&canvas.height>10){
          try{
            var cx=Math.floor(canvas.width/2),cy=Math.floor(canvas.height/2);
            var d=liveCtx.getImageData(cx-2,cy-2,5,5).data;
            var bright=0;for(var i=0;i<d.length;i+=4)bright+=d[i]+d[i+1]+d[i+2];
            if(bright<150){blackCount++;if(blackCount>=2){blackChecked=true;fallbackMjpeg();return;}}
            else{blackChecked=true;}
          }catch(e){blackChecked=true;}
        }
      },
      error:function(){if(current())fallbackMjpeg();}
    });
    liveDecoder=decoder;
  }catch(e){fallbackMjpeg();return;}

  var proto=location.protocol==="https:"?"wss:":"ws:";
  try{ws=new WebSocket(proto+"//"+location.host+liveURL("/api/live/video"));}catch(e){fallbackMjpeg();return;}
  liveWS=ws;ws.binaryType="arraybuffer";
  ws.onmessage=function(ev){
    if(!current()||liveWS!==ws)return;
    var au=new Uint8Array(ev.data);
    if(!configured){
      // Wait for an access unit containing SPS (type 7) — that's our codec config.
      if(!nalContains(au,7))return;
      var codecStr=parseAvcCodecString(au);
      // The server sends Annex-B access units. Supplying description switches
      // WebCodecs to AVC format, which expects an avcC record and length prefixes.
      var cfg={codec:codecStr,optimizeForLatency:true};
      try{decoder.configure(cfg);configured=true;}
      catch(e){fallbackMjpeg();return;}
    }
    var key=nalContains(au,5)||nalContains(au,7);
    try{decoder.decode(new EncodedVideoChunk({type:key?"key":"delta",timestamp:ts,duration:33333,data:au}));ts+=33333;}
    catch(e){fallbackMjpeg();}
  };
  ws.onerror=ws.onclose=function(){if(current()&&liveWS===ws)fallbackMjpeg();};
}
function fallbackMjpeg(){
  if(!liveStreaming||liveMode==="mjpeg"||liveMode==="png")return;
  stopLiveVideo();
  startMjpeg();
}
function startMjpeg(){
  if(!liveStreaming)return;
  var generation=liveGeneration;
  function current(){return liveStreaming&&generation===liveGeneration&&liveMode==="mjpeg";}
  liveMode="mjpeg";
  var canvas=document.getElementById("liveCanvas"),img=document.getElementById("liveScreen");
  canvas.style.display="none";img.style.display="";
  _setStreamMode("📷 Screenshot","#fc9");
  _attachLiveEvents(img);
  // Some Android targets cannot keep a persistent capture pipe open.
  // Individual PNG requests still provide a live screen on those targets.
  img.onerror=function(){if(current())startScreenshotPolling();};
  img.onabort=img.onerror;
  img.onload=function(){if(!current())return;clearTimeout(liveFrameTimer);liveFrameTimer=null;retainLiveImageFrame();sbxHasFrame=true;document.getElementById("sbxStreamPlaceholder").hidden=true;};
  stopLiveImageRetention();
  liveRetainTimer=setInterval(function(){if(current())retainLiveImageFrame();},500);
  clearTimeout(liveFrameTimer);
  liveFrameTimer=setTimeout(function(){if(current())startScreenshotPolling();},12000);
  img.src=liveURL("/api/live/stream?t="+Date.now());
}
function startScreenshotPolling(){
  if(!liveStreaming)return;
  stopLiveImageRetention();
  clearTimeout(liveFrameTimer);clearTimeout(liveRetryTimer);
  liveFrameTimer=liveRetryTimer=null;
  var generation=liveGeneration,img=document.getElementById("liveScreen"),url=liveURL("/api/live/screen");
  function current(){return liveStreaming&&generation===liveGeneration&&liveMode==="png";}
  liveMode="png";
  document.getElementById("liveCanvas").style.display="none";img.style.display="";
  img.onload=img.onerror=img.onabort=null;img.removeAttribute("src");
  _setStreamMode("📷 Screenshot","#fc9");_attachLiveEvents(img);
  function next(delay){
    clearTimeout(liveFrameTimer);liveFrameTimer=null;clearTimeout(liveRetryTimer);
    if(current())liveRetryTimer=setTimeout(request,delay);
  }
  function failed(){
    if(!current())return;
    if(!sbxHasFrame){
      uiText("sbxStreamPlaceholderTitle",uiLang==="ru"?"Ожидаю кадры устройства":"Waiting for device frames");
      uiText("sbxStreamPlaceholderNote",uiLang==="ru"?"Не удалось получить кадр. Подключаюсь повторно…":"Could not receive a frame. Reconnecting…");
    }
    next(1000);
  }
  img.onload=function(){if(!current())return;retainLiveImageFrame();sbxHasFrame=true;document.getElementById("sbxStreamPlaceholder").hidden=true;next(500);};
  img.onerror=img.onabort=failed;
  function request(){
    if(!current())return;
    liveRetryTimer=null;
    liveFrameTimer=setTimeout(function(){if(current()){img.removeAttribute("src");failed();}},12000);
    img.src=url+(url.indexOf("?")>=0?"&":"?")+"t="+Date.now();
  }
  request();
}
// Attach pointer events once on first page load (H264 path uses canvas which is always in DOM).
(function(){
  var cv=document.getElementById("liveCanvas");
  if(cv)_attachLiveEvents(cv);
})();
// scan an Annex-B access unit for a NAL of the given type (7=SPS, 5=IDR)
function nalContains(b,want){
  for(var i=0;i+4<b.length;i++){
    if(b[i]===0&&b[i+1]===0&&b[i+2]===1){if((b[i+3]&0x1f)===want)return true;}
  }
  return false;
}
var _lpTimer=null,_lpStartX=0,_lpStartY=0,_lpEl=null,_swipeStartX=0,_swipeStartY=0,_swipeT=0;
function _liveNorm(ev,el){
  var rect=el.getBoundingClientRect();
  var cx=ev.touches?ev.touches[0].clientX:ev.clientX;
  var cy=ev.touches?ev.touches[0].clientY:ev.clientY;
  return{nx:(cx-rect.left)/rect.width,ny:(cy-rect.top)/rect.height};
}
function _liveInput(obj){
  fetch(liveURL("/api/live/input"),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(obj)}).catch(function(){});
}
function liveTap(ev){
  // liveTap is kept for click fallback; pointer/touch events handle tap + long-press + swipe.
  ev.preventDefault();ev.stopPropagation();
}
function livePointerDown(ev){
  ev.preventDefault();ev.stopPropagation();
  var el=ev.currentTarget||ev.target;
  var p=_liveNorm(ev,el);
  if(p.nx<0||p.nx>1||p.ny<0||p.ny>1)return;
  _lpEl=el;_lpStartX=p.nx;_lpStartY=p.ny;_swipeStartX=p.nx;_swipeStartY=p.ny;_swipeT=Date.now();
  if(_lpTimer)clearTimeout(_lpTimer);
  _lpTimer=setTimeout(function(){
    _lpTimer=null;
    _liveInput({type:"longpress",nx:_lpStartX,ny:_lpStartY,dur:700});
  },550);
  if(ev.pointerId!=null)el.setPointerCapture&&el.setPointerCapture(ev.pointerId);
}
function livePointerUp(ev){
  ev.preventDefault();ev.stopPropagation();
  if(!_lpEl)return;
  var el=_lpEl;_lpEl=null;
  var p=_liveNorm(ev,el);
  var dx=p.nx-_swipeStartX,dy=p.ny-_swipeStartY;
  var dt=Date.now()-_swipeT;
  var dist=Math.sqrt(dx*dx+dy*dy);
  if(_lpTimer){
    clearTimeout(_lpTimer);_lpTimer=null;
    if(dist<0.03){
      // Short tap
      _liveInput({type:"tap",nx:_swipeStartX,ny:_swipeStartY});
    } else {
      // Swipe gesture
      _liveInput({type:"swipe",nx:_swipeStartX,ny:_swipeStartY,nx2:p.nx,ny2:p.ny,dur:Math.max(100,dt)});
    }
  }
  // If _lpTimer was null, long-press was already fired — do nothing on release.
}
function livePointerCancel(ev){
  if(_lpTimer){clearTimeout(_lpTimer);_lpTimer=null;}
  _lpEl=null;
}
function liveKey(k){
  _liveInput({type:"key",key:k});
}

// ── Audio streaming (AAC-ADTS via scrcpy-server audio channel) ──
var _audioWS=null,_audioCtx=null,_audioSrc=null;
var _audioMSE=null,_audioBuf=null,_audioEl=null;
// The audio control is duplicated (live side-panel + sandbox viewport). These
// helpers keep both button labels and both status lines in sync.
function _audioBtnSet(text){
  ["liveAudioBtn","liveAudioBtn2"].forEach(function(id){
    var b=document.getElementById(id);if(b)b.textContent=text;
  });
}
function toggleAudio(){
  if(_audioWS){
    stopAudio();
    _audioBtnSet("🔊 Audio");
    _audioStatus("");
    return;
  }
  startAudio();
  _audioBtnSet("🔇 Stop");
}
function _audioStatus(msg){
  ["liveAudioStatus","liveAudioStatus2"].forEach(function(id){
    var st=document.getElementById(id);
    if(st){st.style.display=msg?"block":"none";st.textContent=msg||"";}
  });
}
function stopAudio(){
  if(_audioWS){try{_audioWS.close();}catch(e){}  _audioWS=null;}
  if(_audioCtx){try{_audioCtx.close();}catch(e){} _audioCtx=null;}
  if(_audioEl){_audioEl.pause();_audioEl.src="";_audioEl=null;}
  _audioMSE=null;_audioBuf=null;
}
function startAudio(){
  stopAudio();
  _audioStatus("Connecting…");
  var proto=location.protocol==="https:"?"wss:":"ws:";
  var ws2=new WebSocket(proto+"//"+location.host+liveURL("/api/live/audio"));
  ws2.binaryType="arraybuffer";
  _audioWS=ws2;
  // Use MediaSource + AAC-ADTS SourceBuffer (supported in Chrome)
  if(typeof MediaSource!=="undefined"&&MediaSource.isTypeSupported('audio/aac')){
    var ms=new MediaSource();
    _audioMSE=ms;
    var ael=new Audio();
    ael.src=URL.createObjectURL(ms);
    ael.play().catch(function(){});
    _audioEl=ael;
    ms.addEventListener("sourceopen",function(){
      try{
        _audioBuf=ms.addSourceBuffer('audio/aac');
        _audioBuf.mode='sequence';
        _audioStatus("Buffering…");
      }catch(e){_audioStatus("MSE error: "+e.message);stopAudio();}
    });
    ws2.onmessage=function(ev){
      if(!_audioBuf||_audioBuf.updating)return;
      try{_audioBuf.appendBuffer(ev.data);}catch(e){}
    };
  } else {
    // Fallback: try to play through AudioContext + manual AAC decode (no-op for unsupported)
    _audioStatus("AAC-MSE not supported in this browser");
  }
  ws2.onmessage=ws2.onmessage||(function(ev){});
  ws2.onerror=function(){ _audioStatus("Audio unavailable (requires scrcpy-server)"); stopAudio(); _audioBtnSet("🔊 Audio"); };
  ws2.onclose=function(){
    if(_audioWS===ws2){_audioWS=null;}
    _audioBtnSet("🔊 Audio");
  };
  // Text message = status/error string from the server
  var origMsg=ws2.onmessage;
  ws2.onmessage=function(ev){
    if(typeof ev.data==="string"){_audioStatus(ev.data);return;}
    if(origMsg)origMsg(ev);
  };
}

function _attachLiveEvents(el){
  el.addEventListener("pointerdown",livePointerDown,{passive:false});
  el.addEventListener("pointerup",livePointerUp,{passive:false});
  el.addEventListener("pointercancel",livePointerCancel,{passive:false});
  el.style.touchAction="none"; // prevent browser scroll interfering
}

// ── sandbox dashboard (ANY.RUN-style) ──
function baseName(p){return String(p||"").replace(/\\/g,"/").split("/").pop();}

// renderSandboxLive builds a results view from the data the dashboard collected
// live. Used when the backend report is missing — e.g. the user pressed Stop
// early, so the engine was killed before it could write sandbox_report.json.
// Everything here is real captured telemetry, just sourced from the live feed.
function renderSandboxLive(){
  var procs=Object.keys(sbxProcessMap).map(function(k){return sbxProcessMap[k];});
  var conns=sbxConnections, dns=sbxDnsRows, http=sbxHttpRequests, threats=sbxThreats;
  var elapsed=sbxStartTime?Math.round(((sbxEndTime||Date.now())-sbxStartTime)/100)/10:0;

  var fn=(sf&&sf.name)?sf.name:"sample";
  // Live observations are not an engine verdict. Never manufacture a risk score
  // or declare a sample clean when the final report is missing.
  var h="<div class='sbx-capture-summary'><div class='sbx-capture-title'>Captured activity</div><div class='sbx-capture-note'>"+e(fn)+" · The final engine report is unavailable. These are the events captured during this session, not a verdict.</div></div>";
  h+="<div class='tiles'>"+tile(procs.length,"Processes")+tile(conns.length,"Connections")+tile(dns.length,"DNS")+tile(elapsed+"s","Duration")+"</div>";

  var tabs=[];
  tabs.push({k:"proc",n:"Processes",c:procs.length,html:dtable(["PID","PPID","Name","Args"],procs.map(function(p){return [e(p.pid),e(p.ppid),e(p.name||""),e(String(p.args||"").slice(0,120))];}))});
  tabs.push({k:"conn",n:"Connections",c:conns.length,html:dtable(["Time","Proto","PID","Process","Destination","Status"],conns.map(function(c){return [e(c.timeshift),e(c.protocol),e(c.pid),e(c.procName),e(c.destination),e(c.status)];}))});
  tabs.push({k:"http",n:"HTTP",c:http.length,html:dtable(["Time","Method","Status","URL"],http.map(function(r){return [e(r.timeshift),e(r.method),e(r.status),e(r.url)];}))});
  tabs.push({k:"dns",n:"DNS",c:dns.length,html:dtable(["Time","PID","Process","Query"],dns.map(function(d){return [e(d.timeshift),e(d.pid),e(d.process),e(d.query)];}))});
  if(threats.length)tabs.push({k:"thr",n:"Threats",c:threats.length,html:dtable(["Time","Severity","Type","Description"],threats.map(function(t){return [e(t.timeshift),(t.severity==null?"<span class='chip c-crit'>Alert</span>":sevChip(t.severity)),e(t.type),e(t.description)];}))});

  var tb="<div class='tabs'>",tp="<div class='tabpanes'>";
  tabs.forEach(function(t,i){
    tb+="<button class='tabb"+(i===0?" on":"")+"' data-tab='"+t.k+"'>"+e(t.n)+" <span>"+t.c+"</span></button>";
    tp+="<div class='tabpane"+(i===0?" on":"")+"' id='tp-"+t.k+"'>"+t.html+"</div>";
  });
  return h+tb+"</div>"+tp+"</div>";
}
function dtable(headers,rows){
  if(!rows.length)return "<div class='tempty'>Nothing captured in this run</div>";
  var h="<table class='dtbl'><thead><tr>";
  headers.forEach(function(x){h+="<th>"+e(x)+"</th>";});
  h+="</tr></thead><tbody>";
  rows.forEach(function(r){h+="<tr>";r.forEach(function(c){h+="<td>"+c+"</td>";});h+="</tr>";});
  return h+"</tbody></table>";
}
function sevChip(sev){var n=typeof sev==="number"?sev:0;var c=n>=8?"c-crit":n>=6?"c-high":n>=4?"c-med":n>=1?"c-low":"c-info";return "<span class='chip "+c+"'>"+e(n)+"</span>";}
function tile(n,l){return "<div class='tile'><div class='tile-n'>"+e(n)+"</div><div class='tile-l'>"+e(l)+"</div></div>";}

function renderSandboxCrypto(crypto){
  var materials=crypto.materials||[];
  var status=crypto.status==="captured"?"Key material captured":crypto.status==="not_instrumented"?"Crypto instrumentation was not active":"No key material captured";
  var h="<div class='sbx-report-limitations'><strong>"+e(status)+"</strong><p>Keys and IVs observed in supported crypto calls. File decryption has not been verified.</p>";
  if(crypto.status==="not_instrumented")h+="<p>Enable API tracing with the Crypto category on Windows, or Frida instrumentation on Android.</p>";
  if(crypto.status==="no_material")h+="<p>The sample may use custom crypto, a non-exportable key, or code outside the captured calls.</p>";
  if(crypto.truncated)h+="<p>Capture is partial: a collection or input limit was reached.</p>";
  if(crypto.rejected)h+="<p>Rejected material records: "+e(crypto.rejected)+".</p>";
  h+="</div>";
  return h+dtable(["Algorithm / operation","PID / source","Key (hex)","IV (hex)","Observations"],materials.map(function(m){return [e(m.algorithm||"unknown")+"<br>"+e(m.operation||""),e(m.pid)+"<br>"+e(m.source||"")+"<br>"+e(m.function||""),"<code class='sbx-crypto-value'>"+e(m.key_hex||"")+"</code><br>"+e(m.key_bytes||0)+" bytes",m.iv_hex?"<code class='sbx-crypto-value'>"+e(m.iv_hex)+"</code>":"—",e(m.observations||1)];}));
}
function renderSandbox(rep){
  var incomplete=!!rep.execution_error||!!(rep.vmware&&rep.vmware.incomplete);

  var ba=rep.behavior_analysis||{},nc=rep.network_capture||{},b=rep.behavior||{};
  var procs=rep.processes||[];
  var conns=(nc.connections&&nc.connections.length)?nc.connections:(rep.connections||[]);
  var dns=nc.dns_queries||[],tls=nc.tls_metadata||[],inds=ba.indicators||[],anti=rep.anti_sandbox_detected||[],techs=ba.techniques||[];
  var score=(ba.risk_score!=null)?ba.risk_score:0,cls=(ba.classification||"").toLowerCase();
  var verdict,vcls;
  if(incomplete){verdict="INCOMPLETE REPORT — NO VERDICT";vcls="";score="—";}
  else if(cls.indexOf("malic")>=0||(!cls&&score>=70)){verdict="MALICIOUS";vcls="v-mal";}
  else if(cls.indexOf("susp")>=0||(!cls&&score>=35)){verdict="SUSPICIOUS";vcls="v-sus";}
  else if(rep.executed===false||!cls){verdict=rep.executed===false?"NOT EXECUTED":"NO VERDICT";vcls="";score="—";}
  else{verdict="NO THREATS REPORTED";vcls="v-clean";}
  var conf=ba.confidence?(Math.round(ba.confidence*100)+"% confidence"):"static heuristics";
  var tset={};
  techs.forEach(function(t){if(t.tactic)tset[t.tactic.toLowerCase()]=1;});
  if((conns&&conns.length)||b.connection_count)tset["network"]=1;
  if(b.persistence_count)tset["persistence"]=1;
  if(b.dropped_executable_count)tset["dropper"]=1;
  if(anti.length)tset["anti-sandbox"]=1;
  if(rep.android_profile)tset["android"]=1;
  var tags=Object.keys(tset);
  var dur=rep.duration_ms?((Math.round(rep.duration_ms/100)/10)+"s"):"—";

  var h="<div class='verdict "+vcls+"'><div class='vinfo'><div class='vlabel'>"+e(verdict)+"</div><div class='vsub'>"+e(baseName(rep.target_original)||"sample")+" · "+e(conf)+"</div></div><div class='vscore'><span class='vscore-n'>"+e(score)+"</span><span class='vscore-l'>/100</span></div></div>";
  if(incomplete)h+="<div class='sbx-report-limitations'><strong>"+(uiLang==="ru"?"Сбор прерван — данные сохранены":"Collection interrupted — captured data retained")+"</strong><p>"+e(rep.execution_error?rep.execution_error.message:(uiLang==="ru"?"Итоговый отчёт гостя недоступен. Ниже — полученные наблюдения.":"The final guest report is unavailable. Received observations are shown below."))+"</p></div>";
  if(tags.length){h+="<div class='tagrow'>";tags.forEach(function(t){h+="<span class='dtag'>#"+e(t)+"</span>";});h+="</div>";}
  h+="<div class='tiles'>"+tile(procs.length,"Processes")+tile(conns.length,"Connections")+tile(dns.length,"DNS")+tile(dur,"Duration")+"</div>";

  if(rep.activity_path)h+="<div class='sbx-report-limitations'><strong>Activity journal</strong><p><code>"+e(rep.activity_path)+"</code></p><p>"+e(rep.activity_count||0)+" observations · "+(rep.activity_truncated?"journal truncated at the 64 MiB resource budget":"journal saved")+". The browser shows only the latest 1,000 observations.</p></div>";
  var warnings=(rep.warnings||[]).slice();
  (rep.degraded_components||[]).forEach(function(c){warnings.push(c.name+" — "+c.phase+": "+c.reason);});
  if(rep.execution_skip_reason)warnings.unshift(rep.execution_skip_reason);
  if(warnings.length)h+="<div class='sbx-report-limitations'><strong>Coverage &amp; limitations</strong><ul>"+warnings.map(function(w){return "<li>"+e(w)+"</li>";}).join("")+"</ul></div>";

  var tabs=[];
  tabs.push({k:"proc",n:"Processes",c:procs.length,html:dtable(["PID","PPID","Name","Command line"],procs.map(function(p){return [e(p.pid),e(p.parent_pid),e(p.name||""),e(String(p.command_line||p.executable_path||"").slice(0,120))];}))});
  if(rep.crypto_analysis)tabs.push({k:"crypto",n:"Crypto keys",c:(rep.crypto_analysis.materials||[]).length,html:renderSandboxCrypto(rep.crypto_analysis)});
  tabs.push({k:"conn",n:"Connections",c:conns.length,html:dtable(["Proto","Process","Remote","State / bytes"],conns.map(function(c){
    var remote=c.remote_addr||"";if(c.remote_port)remote+=":"+c.remote_port;
    var proc=c.process_name||(c.pid?("pid "+c.pid):"");
    var sb=c.state||"";if(c.bytes_sent||c.bytes_received)sb=(c.bytes_sent||0)+"↑ "+(c.bytes_received||0)+"↓";
    return [e(c.protocol||""),e(proc),e(remote),e(sb)];
  }))});
  if(dns.length)tabs.push({k:"dns",n:"DNS",c:dns.length,html:dtable(["Domain","Type","Response","Code"],dns.map(function(d){return [e(d.query_name||""),e(d.query_type||""),e((d.response||[]).join(", ")),e(d.response_code||"")];}))});
  if(tls.length)tabs.push({k:"tls",n:"TLS",c:tls.length,html:dtable(["SNI","Remote","Version","Cipher"],tls.map(function(t){var r=t.remote_addr||"";if(t.remote_port)r+=":"+t.remote_port;return [e(t.sni||""),e(r),e(t.tls_version||""),e(t.cipher_suite||"")];}))});
  if(inds.length||anti.length){
    var trows=[];
    inds.forEach(function(i){trows.push([sevChip(i.severity),e(i.type||""),e(i.description||"")]);});
    anti.forEach(function(a){trows.push(["<span class='chip c-high'>evasion</span>",e(a.type||""),e(a.description||"")]);});
    tabs.push({k:"thr",n:"Threats",c:trows.length,html:dtable(["Severity","Type","Description"],trows)});
  }
  if(techs.length)tabs.push({k:"att",n:"ATT&CK",c:techs.length,html:dtable(["ID","Technique","Tactic","Sev"],techs.map(function(t){return [e(t.id||""),e(t.name||""),e(t.tactic||""),sevChip(t.severity)];}))});
  // Files tab — lazy-loaded on click
  tabs.push({k:"files",n:"Files",c:"…",html:"<div id='sbxFilesWrap'><button class='files-load-btn' onclick='loadSbxFiles()'>Load captured files</button></div>"});

  var tb="<div class='tabs'>",tp="<div class='tabpanes'>";
  tabs.forEach(function(t,i){
    tb+="<button class='tabb"+(i===0?" on":"")+"' data-tab='"+t.k+"'>"+e(t.n)+" <span>"+t.c+"</span></button>";
    tp+="<div class='tabpane"+(i===0?" on":"")+"' id='tp-"+t.k+"'>"+t.html+"</div>";
  });
  return h+tb+"</div>"+tp+"</div>";
}
function wireTabs(){
  document.querySelectorAll(".tabb").forEach(function(btn){
    btn.onclick=function(){
      var k=btn.dataset.tab;
      document.querySelectorAll(".tabb").forEach(function(x){x.classList.toggle("on",x===btn);});
      document.querySelectorAll(".tabpane").forEach(function(p){p.classList.toggle("on",p.id==="tp-"+k);});
    };
  });
}
var _curSbxId=null;
var _sbxResultLoading=false;
function loadSandbox(id){
  if(_sbxResultLoading)return;
  _sbxResultLoading=true;
  _curSbxId=id;
  var resultSerial=sbxRunSerial;
  var res=document.getElementById("res"),fw=document.getElementById("fw"),dl=document.getElementById("dlbtn"),ob=document.getElementById("openbtn"),chips=document.getElementById("chips");
  sbxSetPhase("complete");
  document.getElementById("sbxReportTab").disabled=false;
  switchSbxTab("report");
  show("envRow",false);
  res.classList.add("show");chips.innerHTML="";
  dl.href="/api/sandbox/"+id+"?dl=1";dl.style.display="none";
  ob.style.display="none";
    fw.innerHTML="<div class='done-card' style='display:flex;align-items:center;gap:10px'><div class='spin'></div><span style='color:var(--dim);font-size:13px'>Loading analysis report…</span></div>";
  document.getElementById("sbxtp-report").scrollTop=0;
  if(window.innerWidth<=880)res.scrollIntoView({behavior:preferredScrollBehavior(),block:"start"});
  var backBtn="<button type='button' class='return-btn' onclick='sbxReturnToMenu()'><svg viewBox='0 0 24 24' aria-hidden='true'><path d='M19 12H5M12 5l-7 7 7 7'/></svg> New analysis</button>";
  var resultSerial=sbxRunSerial;
  fetch("/api/sandbox/"+id)
    .then(function(r){return r.ok?r.json():null;})
    .then(function(rep){
      if(resultSerial!==sbxRunSerial||_curSbxId!==id||sbxViewPhase!=="complete")return;
      if(curMode!=="sandbox"||resultSerial!==sbxRunSerial||_curSbxId!==id)return;
      if(!rep){
        // No backend report (e.g. stopped early). Show the live-captured data.
        fw.innerHTML=(sbxFailure?sandboxDiagnosticSummary():renderSandboxLive())+backBtn;
        wireTabs();
        return;
      }
      dl.style.display="";
      sbxCompletionReason=rep.completion_reason||(rep.timed_out?"duration_elapsed":"");
      if(sbxOutcome==="Completed"){
        sbxStopReason=sandboxCompletionMessage(sbxCompletionReason);
        syncSandboxWorkbench();
      }
      if(rep.execution_error){captureSandboxFailure({type:"error",code:rep.execution_error.code,stage:rep.execution_error.stage,details:rep.execution_error.message});}
      fw.innerHTML=(sbxFailure?sandboxDiagnosticSummary():"")+renderSandbox(rep)+backBtn;
      wireTabs();
    })
    .catch(function(){
      if(resultSerial!==sbxRunSerial||_curSbxId!==id||sbxViewPhase!=="complete")return;
      if(curMode!=="sandbox"||resultSerial!==sbxRunSerial||_curSbxId!==id)return;
      fw.innerHTML=(sbxFailure?sandboxDiagnosticSummary():renderSandboxLive())+backBtn;
      wireTabs();
    });
}

// ── Files tab ─────────────────────────────────────────────────────────────────
function fmtSize(n){
  if(n<1024)return n+"B";
  if(n<1048576)return (n/1024).toFixed(1)+"KB";
  return (n/1048576).toFixed(1)+"MB";
}
function loadSbxFiles(){
  if(!_curSbxId)return;
  var wrap=document.getElementById("sbxFilesWrap");
  if(!wrap)return;
  wrap.innerHTML="<span style='color:var(--dim);font-size:12px'>Loading files…</span>";
  fetch("/api/sandbox/"+_curSbxId+"/files")
    .then(function(r){return r.ok?r.json():null;})
    .then(function(files){
      if(!files||!files.length){wrap.innerHTML="<span style='color:var(--dim);font-size:12px'>No files found in session directory.</span>";return;}
      var base="/api/sandbox/"+_curSbxId+"/files/";
      var h="<div class='file-list'>";
      files.forEach(function(f){
        if(f.is_dir)return;
        h+="<div class='file-entry'><a href='"+base+encodeURI(f.path)+"' download='"+e(f.name)+"'>";
        h+="<svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'><path d='M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z'/><polyline points='14 2 14 8 20 8'/></svg>";
        h+=e(f.path)+"<span class='fsize'> "+fmtSize(f.size)+"</span></a></div>";
      });
      h+="</div>";
      wrap.innerHTML=h;
    })
    .catch(function(){wrap.innerHTML="<span style='color:var(--dim)'>Error loading files.</span>";});
}

// ── Frida REPL ────────────────────────────────────────────────────────────────
var _fridaWS=null,_fridaHist=[],_fridaHistIdx=-1;
function fridaLog(text,cls){
  var out=document.getElementById("fridaOutput");
  if(!out)return;
  var d=document.createElement("div");
  d.className="frida-line"+(cls?" "+cls:"");
  d.textContent=text;
  out.appendChild(d);
  out.scrollTop=out.scrollHeight;
}
function fridaSetStatus(txt){var el=document.getElementById("fridaStatus");if(el)el.textContent=txt;}

function fridaStartServer(){
  if(curTarget&&curTarget.kind==="vm")return;
  fridaSetStatus("Starting frida-server…");
  fetch(fridaURL("/api/live/frida/start"),{method:"POST"})
    .then(function(r){return r.json();})
    .then(function(d){
      if(d.ok){fridaSetStatus("Server started — refresh processes");fridaLog("[frida-server started on device]","out");fridaRefreshProcs();}
      else{fridaSetStatus("Error");fridaLog("[error: "+(d.error||"unknown")+"]","err");}
    })
    .catch(function(e){fridaSetStatus("Error");fridaLog("["+e+"]","err");});
}
function fridaRefreshProcs(){
  if(curTarget&&curTarget.kind==="vm")return;
  fridaSetStatus("Fetching processes…");
  fetch(fridaURL("/api/live/frida/processes"))
    .then(function(r){return r.ok?r.json():null;})
    .then(function(procs){
      if(!procs){fridaSetStatus("Failed to list processes");return;}
      var sel=document.getElementById("fridaProc");
      if(!sel)return;
      sel.innerHTML="<option value=''>— select process —</option>";
      procs.forEach(function(p){
        var o=document.createElement("option");
        o.value=p.pid;
        o.textContent=p.pid+" — "+p.name;
        sel.appendChild(o);
      });
      fridaSetStatus("Found "+procs.length+" processes");
      fridaLog("["+procs.length+" processes listed]","out");
      if(curEnv==="windows"&&sf){
        var base=String(sf.name||"").toLowerCase();
        for(var i=0;i<sel.options.length;i++){
          if(base&&sel.options[i].textContent.toLowerCase().indexOf(base)>=0){
            sel.selectedIndex=i;
            fridaLog("[sample process auto-selected: "+sel.options[i].textContent+"]","out");
            break;
          }
        }
      }
    })
    .catch(function(e){fridaSetStatus("Error");fridaLog("["+e+"]","err");});
}
function fridaAttach(){
  if(curTarget&&curTarget.kind==="vm")return;
  var sel=document.getElementById("fridaProc");
  var pid=sel?sel.value:"";
  if(!pid){fridaLog("[select a process first]","err");return;}
  fridaConnect(pid);
}
function fridaConnect(pid){
  if(curTarget&&curTarget.kind==="vm")return;
  if(_fridaWS){_fridaWS.close();_fridaWS=null;}
  var proto=location.protocol==="https:"?"wss:":"ws:";
  _fridaWS=new WebSocket(proto+"//"+location.host+fridaURL("/api/live/frida/repl?pid="+pid));
  _fridaWS.onopen=function(){
    fridaSetStatus("Attached to PID "+pid);
    fridaLog("[attached → pid "+pid+"]","out");
    var db=document.getElementById("fridaDetachBtn");if(db)db.style.display="";
    var inp=document.getElementById("fridaInput");if(inp)inp.focus();
  };
  _fridaWS.onmessage=function(ev){fridaLog(ev.data,"out");};
  _fridaWS.onclose=function(){
    fridaSetStatus("Detached");fridaLog("[session closed]");
    _fridaWS=null;
    var db=document.getElementById("fridaDetachBtn");if(db)db.style.display="none";
  };
  _fridaWS.onerror=function(){fridaLog("[WebSocket error]","err");};
}
function fridaDetach(){
  if(_fridaWS){_fridaWS.close();_fridaWS=null;}
}
function fridaSend(){
  if(curTarget&&curTarget.kind==="vm")return;
  var inp=document.getElementById("fridaInput");
  if(!inp)return;
  var val=inp.value;
  if(!val.trim())return;
  _fridaHist.unshift(val);_fridaHistIdx=-1;
  inp.value="";
  fridaLog(">> "+val,"cmd");
  if(!_fridaWS||_fridaWS.readyState!==1){fridaLog("[not attached — click Attach first]","err");return;}
  _fridaWS.send(val);
}
function fridaKey(ev){
  if(ev.key==="Enter"){fridaSend();return;}
  if(ev.key==="ArrowUp"){
    if(_fridaHistIdx<_fridaHist.length-1){_fridaHistIdx++;ev.currentTarget.value=_fridaHist[_fridaHistIdx]||"";}
    ev.preventDefault();
  }
  if(ev.key==="ArrowDown"){
    if(_fridaHistIdx>0){_fridaHistIdx--;ev.currentTarget.value=_fridaHist[_fridaHistIdx];}
    else{_fridaHistIdx=-1;ev.currentTarget.value="";}
    ev.preventDefault();
  }
}
function fridaRepackDialog(){
  if(curTarget&&curTarget.kind==="vm")return;
  var apk=curFile?curFile.name:"";
  var abi=prompt("ABI (arm64 / arm / x86 / x86_64)","arm64");
  if(!abi)return;
  fridaLog("[repacking APK for Frida Gadget injection ("+abi+")…]");
  fetch("/api/live/frida/repack",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({apk_path:curFile?curFile._serverPath:"",abi:abi})
  }).then(function(r){return r.json();})
    .then(function(d){
      if(d.output_apk)fridaLog("[output APK: "+d.output_apk+"]","out");
      else fridaLog("[error: "+(d.error||"unknown")+"]","err");
    })
    .catch(function(e){fridaLog("["+e+"]","err");});
}

// discover which environments / Android devices are actually available
// discover real environments (host, VirtualBox, VMware, Android) for the picker
var _envPollTimer=null,_envPending=false,_hostPending=false;
function fetchDiscovery(path,ms){
  var controller=new AbortController(),timer=setTimeout(function(){controller.abort();},ms);
  return fetch(path,{cache:"no-store",signal:controller.signal}).then(function(r){if(!r.ok)throw new Error("HTTP "+r.status);return r.json();}).finally(function(){clearTimeout(timer);});
}
function refreshHost(){
  if(_hostPending||sbxBusy())return;_hostPending=true;
  fetchDiscovery("/api/host",10000).then(function(host){
    if(!host||!host.os)throw new Error("Invalid host response");
    if(sbxBusy())return;
    var changed=!ENV||JSON.stringify(ENV.host)!==JSON.stringify(host)||!!hostError;
    ENV=ENV||{};ENV.host=host;hostError="";
    var cr=document.getElementById("sbxcpu-r");if(host.cpuCount>0){cr.max=host.cpuCount;if(+cr.value>host.cpuCount)cr.value=host.cpuCount;syncR("sbxcpu");}
    if(changed)buildOsMenu();
  }).catch(function(err){if(sbxBusy())return;hostError=err.name==="AbortError"?"Host request timed out":err.message;buildOsMenu();}).finally(function(){_hostPending=false;});
}
function refreshEnv(){
  if(_envPending||sbxBusy())return;_envPending=true;if(!envFresh)envState="loading";
  fetchDiscovery("/api/env",15000).then(function(env){
    if(!env||!env.host||!env.host.os)throw new Error("Invalid environment response");
    if(sbxBusy())return;
    var changed=!envFresh||envState!=="ready"||JSON.stringify(ENV)!==JSON.stringify(env);
    ENV=env;envState="ready";envFresh=true;envError="";
    if(env.warnings&&env.warnings.length)envError=env.warnings.join("; ");
    if(changed)buildOsMenu(); // unchanged responses do not replace controls or steal focus
  }).catch(function(err){if(sbxBusy())return;envState="error";envFresh=false;envError=err.name==="AbortError"?"Timed out; the host is shown independently.":err.message;buildOsMenu();}).finally(function(){_envPending=false;});
}
function refreshEnvironments(reinspect){
  if(window.MegaWasm)return;
  if(reinspect&&vmwarePanelID&&!sbxBusy()){invalidateVMwareReport();vmwareInspectQueued=true;flushVMwareInspection();syncVMwareButtons();refreshBtn();}
  refreshHost();refreshEnv();
}
function startEnvPoll(){/* Discovery runs on initial load and explicit Refresh only. No background VM polling. */}
function stopEnvPoll(){if(_envPollTimer){clearInterval(_envPollTimer);_envPollTimer=null;}}
refreshEnvironments();startEnvPoll();

// pull real bundle counts (SAST rules, trackers) from the backend
fetch("/api/meta").then(function(r){return r.json();}).then(function(m){
	var version=document.getElementById("appVersion");
	if(version&&m.version){version.textContent="v"+String(m.version).replace(/^v/,"");version.title=[m.commit,m.buildDate].filter(Boolean).join(" · ");}
  var a=document.getElementById("sastCount");if(a&&m.sastRules)a.textContent=m.sastRules;
  var b=document.getElementById("trackerCount");if(b&&m.trackers)b.textContent=m.trackers;
  // Keep the pre-flight limit and the dropzone label in sync with the server.
  if(m.uploadMaxBytes&&m.uploadMaxBytes!==MAX_UPLOAD_BYTES){
    MAX_UPLOAD_BYTES=m.uploadMaxBytes;
    var mb=Math.round(MAX_UPLOAD_BYTES/1048576);
    PAGE_I18N.dzMax={en:"Maximum "+mb+" MB",ru:"Максимум "+mb+" МБ"};
    applyPageLang();
  }
}).catch(function(){});

// ── URL routing — each tool gets its own path ──
var TOOL_SLUG={
  "minecraft":"minecraft",
  "full":"","decode":"decode","build":"build","machine-code":"machine-code","firmware":"firmware",
  "version-diff":"diff",
  "sandbox":"sandbox","web-scan":"scan","intercept":"mitm"
};
var SLUG_TOOL={};Object.keys(TOOL_SLUG).forEach(function(k){SLUG_TOOL[TOOL_SLUG[k]]=k;});
SLUG_TOOL["js"]="full";SLUG_TOOL["js-patch"]="full";
SLUG_TOOL["full"]="full"; // legacy /full permalinks still resolve

function toolFromPath(){
  var p=location.pathname.replace(/^\/+/,"").replace(/\/+$/,"").toLowerCase();
  return SLUG_TOOL[p]||"full";
}
window.addEventListener("popstate",function(e){
  selTool((e.state&&e.state.tool)||toolFromPath());
});

// ── Presentation only: appearance, disclosure summaries, accessible navigation ──
// Keep network calls, command flags and analysis state in their original handlers.
var appearancePreference="system";
try{var storedAppearance=localStorage.getItem("ma-appearance");if(storedAppearance==="light"||storedAppearance==="dark")appearancePreference=storedAppearance;}catch(err){}
var APPEARANCE_ICONS={
  system:'<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>',
  light:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M5 19l1.5-1.5M17.5 6.5 19 5"/>',
  dark:'<path d="M20.5 13.2A8.8 8.8 0 0 1 10.8 3.5a8.8 8.8 0 1 0 9.7 9.7Z"/>'
};
function syncAppearance(){
  var root=document.documentElement;
  if(appearancePreference==="system")delete root.dataset.theme;
  else root.dataset.theme=appearancePreference;
  var name=appearancePreference.charAt(0).toUpperCase()+appearancePreference.slice(1);
  var next=appearancePreference==="system"?"light":appearancePreference==="light"?"dark":"system";
  document.getElementById("appearanceIcon").innerHTML=APPEARANCE_ICONS[appearancePreference];
  document.getElementById("appearanceLabel").textContent=name;
  document.getElementById("appearanceBtn").setAttribute("aria-label","Appearance: "+appearancePreference+". Switch to "+next+".");
  document.getElementById("appearanceBtn").title="Appearance: "+name+". Click for "+next+".";
}
function cycleAppearance(){
  appearancePreference=appearancePreference==="system"?"light":appearancePreference==="light"?"dark":"system";
  try{if(appearancePreference==="system")localStorage.removeItem("ma-appearance");else localStorage.setItem("ma-appearance",appearancePreference);}catch(err){}
  syncAppearance();
}
function preferredScrollBehavior(){return window.matchMedia("(prefers-reduced-motion: reduce)").matches?"instant":"smooth";}
function uiText(id,text){var el=document.getElementById(id);if(el&&el.textContent!==text)el.textContent=text;}
function syncWorkspaceUI(){
  var mode=MODES[curMode];if(!mode)return;
  var buildMode=curMode==="build",decodeMode=curMode==="decode";
  var dropTitle=document.querySelector("#dz .dz-t"),dropHint=document.querySelector("#dz .dz-s"),dropLabel=document.getElementById("dz1lbl");
  if(dropTitle)dropTitle.textContent=pageT(buildMode?"buildChoose":decodeMode?"decodeChoose":"dzChoose");
  if(dropHint)dropHint.textContent=pageT(buildMode?"buildHint":"dzDrag");
  if(dropLabel&&dropLabel.firstChild)dropLabel.firstChild.textContent=pageT(buildMode?"buildProject":curMode==="version-diff"?"dzOriginal":"dzTarget")+" ";
  var dropAria=pageT(buildMode?"buildChoose":decodeMode?"decodeChoose":"dzChoose");
  document.getElementById("dz").setAttribute("aria-label",dropAria);
  document.getElementById("fi").setAttribute("aria-label",pageT(buildMode?"buildProject":"dzTarget"));
  uiText("toolCrumb",toolLabel(curMode)||mode.t);
  var group=TOOL_GROUPS.filter(function(g){return g.items.indexOf(curMode)!==-1;})[0];
  uiText("toolCategory",group?groupLabel(group.name):groupLabel("Analyze"));
  var modules=document.querySelectorAll("input.fg:checked").length;
  uiText("moduleSummary",modules?modules+" "+pageT("selected"):pageT("defaults"));
  var seg=document.querySelector(".sbtn.on"),format=seg?(seg.dataset.v||"auto"):"default";
  uiText("tuningSummary",format.charAt(0).toUpperCase()+format.slice(1)+" "+pageT("reportWord"));
  var output=document.getElementById("outdir").value.trim()||document.getElementById("outname").value.trim();
  uiText("outputSummary",output||pageT("wsScans"));
  document.getElementById("outputSummary").title=output||pageT("wsScans");
  var button=document.getElementById("sbtn"),bar=document.getElementById("runBar");
  var title=sf?sf.name:pageT("noFile"),note=pageT("chooseTarget");
  var state=button.disabled?"idle":"ready";
  if(sf){
    var profile=document.querySelector(".pcard.on .p-name");
    note=fb(sf.size)+(curMode==="full"&&profile?" · "+profile.textContent+" profile":" · "+pageT("readyAnalyze"));
  }
  if(buildMode)note=sf?fb(sf.size)+" · "+pageT("buildReady"):pageT("buildHint");
  if(decodeMode)note=sf?fb(sf.size)+" · "+pageT("decodeReady"):pageT("decodeChoose");
  if(curMode==="version-diff")note=sf&&sf2?pageT("bothBuilds"):pageT("selectBoth");
  if(curMode==="sandbox"){
    if(!sf)note="Choose a sample, then select a compatible environment.";
    else if(!curTarget||!curTarget.runnable)note="Select a compatible, available environment to continue.";
    else if(isVMwareTarget()&&!vmwareExecutionReady())note=vmwareReadinessMessage();
    else note=fb(sf.size)+" · "+curTarget.label;
  }
  if(mode.fileless){
    title=curMode==="web-scan"?"Target authorization":"Proxy configuration";
    note=curMode==="web-scan"?"Enter a target URL and confirm permission to scan.":"Set the upstream server before starting the proxy.";
    if(!button.disabled)note=curMode==="web-scan"?"Target and authorization set · Ready to scan":"Upstream set · Ready to start";
  }
  var progress=document.getElementById("prog"),spinner=document.getElementById("ps");
  if(running||(button.disabled&&progress.classList.contains("show")&&spinner.style.display!=="none")){
    state="busy";note=document.getElementById("pt").textContent||"Analysis in progress…";
    if(mode.longRunning)title="Proxy session";
  }
  bar.dataset.state=state;
  if(curMode==="sandbox"&&sf&&curTarget&&curTarget.runnable&&!sandboxConsentReady()&&(!isVMwareTarget()||vmwareExecutionReady()))note=isVMwareTarget()?"Подтвердите запуск выбранного файла в гостевой Windows.":"Confirm use of a disposable host/device below to enable real execution.";
  uiText("runTitle",title);uiText("runNote",note);
  document.getElementById("runTitle").title=title;
  document.getElementById("dz").classList.toggle("has-file",!!sf);
  document.getElementById("dz2").classList.toggle("has-file",!!sf2);
  syncSandboxWorkbench();
}

(function initPresentation(){
  syncAppearance();applyLang();setMenuOpen(false);
  document.querySelectorAll("details.advanced-settings").forEach(function(panel){
    panel.addEventListener("toggle",function(){if(panel.open)requestAnimationFrame(moveSeg);});
  });
  document.addEventListener("input",syncWorkspaceUI);
  document.addEventListener("change",syncWorkspaceUI);
  ["dz","dz2"].forEach(function(id){
    document.getElementById(id).addEventListener("keydown",function(ev){
      if(ev.target===this&&(ev.key==="Enter"||ev.key===" ")){ev.preventDefault();this.click();}
    });
  });
  document.querySelector(".prof-row").addEventListener("keydown",function(ev){
    var buttons=Array.from(this.querySelectorAll(".pcard")),index=buttons.indexOf(document.activeElement);
    if(index<0)return;
    var next=index;
    if(ev.key==="ArrowRight"||ev.key==="ArrowDown")next=(index+1)%buttons.length;
    else if(ev.key==="ArrowLeft"||ev.key==="ArrowUp")next=(index+buttons.length-1)%buttons.length;
    else if(ev.key==="Home")next=0;else if(ev.key==="End")next=buttons.length-1;else return;
    ev.preventDefault();buttons[next].focus();selProfile(buttons[next]);
  });
  document.addEventListener("keydown",function(ev){
    var side=document.getElementById("sidebar");
    if(ev.key==="Escape"){
      if(osMenuOpen){closeOsMenu();document.getElementById("osPickBtn").focus();ev.preventDefault();}
      else if(side.classList.contains("open")){closeMenu();ev.preventDefault();}
    }
    if(ev.key!=="Tab"||!side.classList.contains("open"))return;
    var focusable=Array.from(side.querySelectorAll("button,a[href],input,select,[tabindex='0']")).filter(function(el){return !el.disabled&&el.getClientRects().length;});
    var first=focusable[0],last=focusable[focusable.length-1];
    if(ev.shiftKey&&document.activeElement===first){ev.preventDefault();last.focus();}
    else if(!ev.shiftKey&&document.activeElement===last){ev.preventDefault();first.focus();}
  });
  window.addEventListener("resize",function(){
    if(window.innerWidth>880)closeMenu();
    else document.getElementById("sidebar").inert=!document.getElementById("sidebar").classList.contains("open");
  });
  if(window.MutationObserver){
    var statusObserver=new MutationObserver(syncWorkspaceUI);
    statusObserver.observe(document.getElementById("sbtn"),{attributes:true,attributeFilter:["disabled","class"],childList:true,subtree:true,characterData:true});
    statusObserver.observe(document.getElementById("pt"),{childList:true,subtree:true,characterData:true});
    var picker=document.getElementById("osPickBtn");
    new MutationObserver(function(){picker.setAttribute("aria-expanded",String(picker.classList.contains("open")));}).observe(picker,{attributes:true,attributeFilter:["class"]});
  }
  document.getElementById("osPickBtn").addEventListener("keydown",function(ev){
    if(ev.key!=="ArrowDown")return;
    ev.preventDefault();if(!osMenuOpen)toggleOsMenu(ev);
    var first=document.querySelector("#osMenu .os-row:not(.dis)");if(first)first.focus();
  });
  document.getElementById("osMenu").addEventListener("keydown",function(ev){
    if(ev.key!=="ArrowDown"&&ev.key!=="ArrowUp")return;
    var rows=Array.from(this.querySelectorAll(".os-row:not(.dis)"));if(!rows.length)return;
    var index=rows.indexOf(document.activeElement),next=(index+(ev.key==="ArrowDown"?1:rows.length-1))%rows.length;
    ev.preventDefault();rows[next].focus();
  });
})();


// ── Docked sandbox workbench ────────────────────────────────────────────────
// The dock moves existing controls, not copies. IDs, flags and backend endpoints
// stay the same; leaving Sandbox restores each shared control to its origin.
var sbxViewPhase="setup",sbxDocked=false,sbxDockOrigins={},sbxRunSerial=0,sbxOutcome="",sbxStopReason="",sbxHasFrame=false,sbxEndTime=null,sbxFailure=null,sbxSessionId="",sbxDiagnostics=[];
function sbxBusy(){return sbxViewPhase==="starting"||sbxViewPhase==="running"||sbxViewPhase==="stopping";}
function mountSandboxWorkbench(enabled){
  if(!enabled)stopVMwareScreen(true);
  document.body.classList.toggle("sandbox-mode",enabled);
  if(sbxDocked===enabled)return;
  var slots={dz1wrap:"sbxIntakeSlot",envRow:"sbxConfigSlot",outRow:"sbxConfigSlot",runBar:"sbxRunSlot",res:"sbxtp-report"};
  Object.keys(slots).forEach(function(id){
    var el=document.getElementById(id);
    if(enabled){
      if(!sbxDockOrigins[id]){var mark=document.createComment("original position: "+id);el.parentNode.insertBefore(mark,el);sbxDockOrigins[id]=mark;}
      document.getElementById(slots[id]).appendChild(el);
    }else{var mark=sbxDockOrigins[id];if(mark&&mark.parentNode)mark.parentNode.insertBefore(el,mark);}
  });
  sbxDocked=enabled;
  if(!enabled){document.getElementById("liveSbxDash").style.display="none";document.querySelector(".new-btn").disabled=false;}
}
function sbxSetPhase(phase){
  var wasBusy=sbxBusy();
  if(phase==="complete"&&sbxViewPhase!=="complete")sbxEndTime=Date.now();
  sbxViewPhase=phase;
  var dash=document.getElementById("liveSbxDash");
  dash.dataset.phase=phase;
  if(curMode==="sandbox")dash.style.display="grid";
  if(wasBusy&&!sbxBusy()&&vmwarePanelID){invalidateVMwareReport();vmwareInspectQueued=true;}
  syncVMwareButtons();flushVMwareInspection();
  syncSandboxWorkbench();
}
function prepareSandboxWorkspace(){
  if(curMode!=="sandbox")return;
  stopVMwareScreen(false);
  sbxFailure=null;sbxSessionId="";sbxDiagnostics=[];
  document.getElementById("liveSbxDash").style.display="grid";
  document.getElementById("sbxVmIdle").style.display="flex";
  document.getElementById("sbxConsole").style.display="none";
  document.getElementById("sbxAndroidStream").style.display="none";
  document.getElementById("sbxVMwareScreen").style.display="none";
  document.getElementById("sbxReportTab").disabled=true;
  document.getElementById("sbxProcessDetail").hidden=true;
  sbxSelectedPid=null;
  document.getElementById("sbxProcInput").value="";
  document.getElementById("sbxFlaggedOnly").checked=false;
  document.getElementById("sbxEventFilter").value="";
  sbxProcessMap={};sbxHttpRequests=[];sbxConnections=[];sbxDnsRows=[];sbxThreats=[];sbxStartTime=null;
  document.getElementById("liveProcessTree").innerHTML="";
  document.getElementById("sbxEngineFeedBody").innerHTML="";
  document.getElementById("sbxAlertBanner").style.display="none";
  ["sbxProcCount","sbxHttpCount","sbxConnCount","sbxDnsCount","sbxThreatCount"].forEach(function(id){uiText(id,"0");});
  var messages={http:"HTTP requests appear when network capture provides them.",conn:"Connections observed by the engine appear here.",dns:"Captured DNS queries and responses appear here.",threats:"Engine alerts will appear here. No analysis has run yet."};
  Object.keys(messages).forEach(function(key){var el=document.getElementById("sbxtbl-"+key);el.innerHTML="";var empty=document.createElement("div");empty.className="tempty";empty.textContent=messages[key];el.appendChild(empty);});
  switchSbxTab("activity");filterSbxProcs();sbxApplySavedRows();syncSandboxWorkbench();
}
function syncSandboxWorkbench(){
  var fridaTab=document.getElementById("fridaTabBtn");if(fridaTab)fridaTab.disabled=!((curEnv==="android"&&sbxViewPhase==="running")||(curEnv==="windows"&&curTarget&&curTarget.kind==="host"));
  syncFridaToolbar();
  if(curMode!=="sandbox"||!sbxDocked)return;
  document.getElementById("sbxReportTab").textContent=sbxFailure?"Diagnostics":"Report";
  var phase=sbxViewPhase,busy=sbxBusy(),setup=phase==="setup";
  uiText("sbxStreamPlaceholderTitle",phase==="complete"?"No screen was captured":"Waiting for the device screen");
  uiText("sbxStreamPlaceholderNote",phase==="complete"?"Review the engine activity and captured events.":"The connected Android device will appear here when frames arrive.");
  document.querySelectorAll(".stream-controls button").forEach(function(b){b.disabled=phase!=="running";});
  var labels={setup:"Not started",starting:"Uploading",running:"Running",stopping:"Stopping",complete:sbxOutcome||"Captured session"};
  uiText("sbxSessionState",labels[phase]||phase);
  document.getElementById("sbxNewSession").disabled=busy;
  document.querySelector(".new-btn").disabled=busy;
  document.getElementById("sbxStopBtn").disabled=phase!=="running";
  uiText("sbxStopBtn",phase==="stopping"?"Stopping…":"Stop");
  var captured=sbxStartTime?Math.max(0,Math.floor(((sbxEndTime||Date.now())-sbxStartTime)/1000)):0;
  var capturedMMSS=sbxStartTime?formatSandboxElapsed(captured):"—";
  var outcomeWord={Stopped:"STOPPED",Completed:"COMPLETED",Failed:"FAILED"}[sbxOutcome];
  uiText("sbxTimeLabel",phase==="complete"?(outcomeWord?outcomeWord.toLowerCase()+" · captured "+capturedMMSS:"captured"):(sbxTimerVal===0?(uiLang==="ru"?"прошло · без таймера":"elapsed · no timer"):(uiLang==="ru"?"осталось":"time left")));
  if(phase==="complete"){
    if(outcomeWord){uiText("sbxTimer",outcomeWord);}
    else{uiText("sbxTimer",capturedMMSS);}
  }
  var target=(curTarget&&curTarget.label)||"No target selected";
  uiText("sbxOsName",target);
  uiText("sbxViewerKind",setup?"Environment":(curEnv==="android"||isVMwareTarget())?(sbxViewMode==="screen"?(phase==="complete"?(isVMwareTarget()?"Guest screen":"Recorded device"):(isVMwareTarget()?"VMware screen":"Live device")):(isVMwareTarget()?"Console log":"Engine log")):"Captured output");
  syncSbxView();
  uiText("sbxConsoleState",phase==="running"?"live":phase==="starting"?"starting":phase==="stopping"?"stopping":"recorded");
  if(setup){
    uiText("sbtn-t","Start analysis");
    uiText("sbxIntakeTitle",sf?"Sample ready for analysis.":"Prepare an analysis.");
    uiText("sbxIntakeHint",sf?"Review the environment and limits, then start the session.":"Upload a sample and configure its execution environment.");
  }
  var status=setup?(sf?"Sample selected · Review settings before execution.":"Select a sample to prepare an analysis."):phase==="starting"?"Uploading sample · Execution has not started yet.":phase==="stopping"?"Stop requested · Waiting for the engine.":phase==="complete"?(sbxOutcome||"Capture disconnected")+" · Captured events remain available.":"Live capture · "+target;
  var progressText=document.getElementById("pt").textContent;
  if(phase==="running"&&progressText.indexOf("Connection interrupted")===0)status=progressText;
  uiText("sbxStatusMessage",status);
  var netAllowed=document.getElementById("netChk").checked;
  var elevated=ENV&&ENV.host&&ENV.host.sandbox&&ENV.host.sandbox.elevated;
  var vmOnly=!!(curTarget&&curTarget.kind==="vm");
  uiText("sbxNetworkState",isVMwareTarget()?(vmwareReport&&vmwareReport.configurationPass?"VMware · сеть отключена в настройках":"VMware · требуется подготовка сети"):vmOnly?"Сеть ВМ не управляется анализатором":netAllowed?"Network allowed · not isolated":curEnv==="android"?"Android isolation unavailable":elevated?"Network blocked · firewall rule will be applied":"Network blocked · start needs admin rights");
  document.getElementById("sbxNetworkState").classList.toggle("allowed",!vmOnly&&document.getElementById("netChk").checked);
  var banner=document.getElementById("sbxAlertBanner");
  document.querySelector(".sbx-statusbar").classList.toggle("has-alert",banner.style.display!=="none"&&!!document.getElementById("sbxAlertText").textContent);
  document.querySelectorAll("#sbxWinConfigOpts .pbtn").forEach(function(b){b.setAttribute("aria-pressed",String(b.classList.contains("on")));});
  document.querySelectorAll("#sbxOriSeg .pbtn").forEach(function(b){b.setAttribute("aria-pressed",String(b.classList.contains("on")));});
  syncSandboxFailureUI();
}
function sbxNewAnalysis(){
  if(sbxBusy())return;
  sbxReturnToMenu();clearFile(1);clearFile(2);jid=null;
  document.getElementById("sbxConfigSlot").scrollTop=0;
  document.getElementById("dz").focus({preventScroll:true});
  document.querySelector(".main").scrollTop=0;window.scrollTo({top:0,behavior:preferredScrollBehavior()});
}
function recordSandboxMetadata(data){
  var md5=data.md5||data.MD5||"";
  if(!md5&&data.details){var match=String(data.details).match(/MD5:\s*([a-fA-F0-9]{32})/);if(match)md5=match[1];}
  if(/^[a-fA-F0-9]{32}$/.test(md5))uiText("sbxMD5","MD5: "+md5.toLowerCase());
  if(/^[a-fA-F0-9]{64}$/.test(data.sha256||""))document.getElementById("sbxMD5").title="SHA-256: "+data.sha256;
  syncSandboxWorkbench();
}
function selectSandboxProcess(pid){
  var p=sbxProcessMap[pid];if(!p)return;
  sbxSelectedPid=p.pid;
  var detail=document.getElementById("sbxProcessDetail");detail.hidden=false;
  uiText("sbxSelectedProcess",p.name+" · PID "+p.pid+(p.ppid?" · parent "+p.ppid:""));
  uiText("sbxSelectedCommand",p.args||"No command line reported by the engine.");
}
function deselectSandboxProcess(){
  sbxSelectedPid=null;
  document.querySelectorAll(".sbx-pt-row").forEach(function(x){x.classList.remove("active");});
  document.getElementById("sbxProcessDetail").hidden=true;
}
function filterSandboxRows(){
  var pane=document.querySelector(".sbx-tab-pane.active");if(!pane)return;
  var input=document.getElementById("sbxEventFilter");if(!input)return;
  var query=input.value.trim().toLowerCase(),rows=pane.querySelectorAll(".dtbl tbody tr"),visible=0;
  var category=pane.id==="sbxtp-activity"?document.getElementById("sbxActivityCategory").value:"";
  rows.forEach(function(row){var match=row.textContent.toLowerCase().indexOf(query)!==-1&&(!category||row.dataset.category===category);row.hidden=!match;if(match)visible++;});
  uiText("sbxEventCaption",rows.length?(query?visible+" / "+rows.length+" events":rows.length+" captured events"):sbxViewPhase==="setup"?"Waiting for a session":"No events in this view");
  syncSandboxWorkbench();
}
function toggleSandboxFullscreen(){
  var view=document.querySelector(".sbx-vm-panel");
  if(document.fullscreenElement){if(document.exitFullscreen)document.exitFullscreen();return;}
  if(view.requestFullscreen)view.requestFullscreen().catch(function(){uiText("sbxStatusMessage","Fullscreen is unavailable in this browser.");});
}
// Drag-resize between the viewport panel and the event tabs below it.
// Desktop grid only; the fraction persists across runs, double-click resets.
var sbxDragState=null;
function sbxResizeStart(ev){
  if(ev.button!==undefined&&ev.button!==0)return;
  var dash=document.getElementById("liveSbxDash");
  if(!dash||!window.matchMedia||!window.matchMedia("(min-width:881px)").matches)return;
  var panel=document.querySelector(".sbx-vm-panel"),tabs=document.querySelector(".sbx-net-tabs");
  if(!panel||!tabs||!panel.offsetHeight||!tabs.offsetHeight)return;
  ev.preventDefault();
  sbxDragState={y:ev.clientY,vp:panel.offsetHeight,tabs:tabs.offsetHeight,dash:dash};
  document.addEventListener("mousemove",sbxResizeMove);
  document.addEventListener("mouseup",sbxResizeEnd);
}
function sbxResizeMove(ev){
  if(!sbxDragState)return;
  var total=sbxDragState.vp+sbxDragState.tabs;
  var vp=Math.max(220,Math.min(total-180,sbxDragState.vp+(ev.clientY-sbxDragState.y)));
  var cs=getComputedStyle(sbxDragState.dash).gridTemplateRows.split(" ");
  if(cs.length<4)return;
  sbxDragState.dash.style.gridTemplateRows=cs[0]+" "+vp+"px "+(total-vp)+"px "+cs[cs.length-1];
}
function sbxResizeEnd(){
  if(!sbxDragState)return;
  try{
    var cs=getComputedStyle(sbxDragState.dash).gridTemplateRows.split(" ");
    var total=sbxDragState.vp+sbxDragState.tabs;
    if(cs.length>=4)localStorage.setItem("sbxViewRows",parseFloat(cs[1])/total);
  }catch(e){}
  sbxDragState=null;
  document.removeEventListener("mousemove",sbxResizeMove);
  document.removeEventListener("mouseup",sbxResizeEnd);
}
function sbxApplySavedRows(){
  var dash=document.getElementById("liveSbxDash");
  if(!dash||!window.matchMedia||!window.matchMedia("(min-width:881px)").matches)return;
  var frac=NaN;
  try{frac=parseFloat(localStorage.getItem("sbxViewRows"));}catch(e){}
  if(!(frac>0&&frac<1))return;
  var panel=document.querySelector(".sbx-vm-panel"),tabs=document.querySelector(".sbx-net-tabs");
  if(!panel||!tabs||!panel.offsetHeight||!tabs.offsetHeight)return;
  var total=panel.offsetHeight+tabs.offsetHeight;
  var vp=Math.max(220,Math.min(total-180,Math.round(total*frac)));
  var cs=getComputedStyle(dash).gridTemplateRows.split(" ");
  if(cs.length<4)return;
  dash.style.gridTemplateRows=cs[0]+" "+vp+"px "+(total-vp)+"px "+cs[cs.length-1];
}
function sbxResetRows(){
  try{localStorage.removeItem("sbxViewRows");}catch(e){}
  var dash=document.getElementById("liveSbxDash");
  if(dash)dash.style.gridTemplateRows="";
}
(function initSandboxWorkbench(){
  document.querySelector(".new-btn").setAttribute("aria-label","New analysis");
  document.querySelector(".new-btn").title="New analysis";
  document.querySelectorAll(".sbx-tab-btn").forEach(function(btn,i){
    var key=btn.dataset.sbxtab;btn.type="button";btn.setAttribute("role","tab");btn.id=btn.id||"sbx-tab-"+key;
    btn.setAttribute("aria-controls","sbxtp-"+key);btn.setAttribute("aria-selected",String(i===0));btn.tabIndex=i===0?0:-1;
    var pane=document.getElementById("sbxtp-"+key);if(pane){pane.setAttribute("role","tabpanel");pane.setAttribute("aria-labelledby",btn.id);pane.tabIndex=0;}
  });
  document.querySelector(".sbx-tab-btn-row").addEventListener("keydown",function(ev){
    if(["ArrowLeft","ArrowRight","Home","End"].indexOf(ev.key)<0)return;
    var tabs=Array.from(this.querySelectorAll(".sbx-tab-btn:not(:disabled)")),i=tabs.indexOf(document.activeElement);if(i<0)return;
    ev.preventDefault();i=ev.key==="Home"?0:ev.key==="End"?tabs.length-1:(i+(ev.key==="ArrowRight"?1:tabs.length-1))%tabs.length;
    tabs[i].click();tabs[i].focus();
  });
  if(!document.fullscreenEnabled){document.getElementById("sbxFullscreenBtn").disabled=true;document.getElementById("sbxFullscreenBtn").title="Fullscreen is unavailable";}
  document.addEventListener("fullscreenchange",function(){var btn=document.getElementById("sbxFullscreenBtn");btn.setAttribute("aria-label",document.fullscreenElement?"Exit fullscreen":"Expand environment view");});
})();



function sandboxFailureInfo(data){
  var raw=String(data.details||data.message||""),plain=raw.replace(/^\s*[✗✘×]\s*/,"").trim();
  var legacy=!data.pid && /^(?:sandbox run failed:|sandbox target not found:|invalid sandbox target:|sandbox run produced no report)/i.test(plain);
  if(data.type!=="error"&&data.type!=="engine_error"&&!legacy)return null;
  var code=data.code||(/(?:network guard|firewall rule)/i.test(plain)?"network_guard_failed":/target.*not found/i.test(plain)?"target_missing":"engine_failed");
  var title="Analysis failed",message=plain,help="Review the engine output and the analysis environment before retrying.";
  if(code==="admin_required"){
    title="Administrator permission required";message="The analyzer cannot prepare Windows network isolation with its current permissions.";
    help="Run the analyzer as administrator only on a disposable analysis host. Keep network isolation enabled. Native analysis is not a virtual machine.";
  }else if(code==="network_guard_failed"){
    title="Network isolation could not be prepared";message="Windows rejected the firewall rule required for this run. The engine stopped instead of bypassing isolation.";
    help="On the isolated analysis host, check the analyzer's elevation, Windows Firewall service and any policy restrictions. Do not disable the guard to work around this error.";
  }else if(code==="target_missing"||code==="target_invalid"){
    title="Sample could not be opened";message="The selected sample is missing or its path is unavailable.";help="Select the sample again and check access to the analysis directory.";
  }else if(code==="report_missing"){
    title="No final report was received";message="The session ended without a final engine report. The captured data does not establish a clean verdict.";
  }else if(code==="guest_powered_off"){
    title=uiLang==="ru"?"Гостевая Windows выключилась":"Guest Windows powered off";
    help=uiLang==="ru"?"Полученные события сохранены на основном ПК. Отчёт неполный; по нему нельзя считать образец безопасным.":"Received events are saved on the host. The report is incomplete and cannot establish that the sample is safe.";
  }
  return {code:code,stage:data.stage||"preparation",title:title,message:message,help:help,raw:raw};
}
function captureSandboxFailure(data){
  if(data.code==="canceled"){sbxOutcome="Stopped";return true;}
  var failure=sandboxFailureInfo(data);if(!failure)return false;
  var repeated=sbxFailure&&sbxFailure.message===failure.message;
  if(!sbxFailure)sbxFailure=failure;
  if(sbxDiagnostics.indexOf(failure.raw)<0){sbxDiagnostics.push(failure.raw);if(sbxDiagnostics.length>100)sbxDiagnostics.shift();if(!repeated)sbxEngineLog(failure.message,"err");}
  sbxOutcome="Failed";syncSandboxWorkbench();return true;
}
function syncSandboxFailureUI(){
  var el=document.getElementById("sbxFailurePanel"),failed=!!sbxFailure;
  el.hidden=!failed;document.getElementById("liveSbxDash").dataset.outcome=failed?"failed":"";
  if(!failed)return;
  uiText("sbxFailureTitle",sbxFailure.title);uiText("sbxFailureMessage",sbxFailure.message);uiText("sbxFailureHelp",sbxFailure.help);
  uiText("sbxFailureRaw",sbxDiagnostics.join("\n\n"));
  document.getElementById("sbxReviewSettings").disabled=sbxBusy();
  uiText("sbxSessionState",sbxBusy()?"Execution error":"Failed");
  uiText("sbxStatusMessage","Engine error · "+sbxFailure.title+" · No successful analysis verdict");
  uiText("sbxConsoleState","error");
  if(sbxFailure.code==="admin_required"||sbxFailure.code==="network_guard_failed")uiText("sbxNetworkState","Isolation not applied");
  if(!Object.keys(sbxProcessMap).length)document.getElementById("liveProcessTree").setAttribute("data-empty-message","No sample process was observed.");
}
function sandboxDiagnosticSummary(){
  return "<div class='sbx-capture-summary'><div class='sbx-capture-title'>Execution diagnostics</div><div class='sbx-capture-note'>"+e(sbxFailure?sbxFailure.message:"The final engine report is unavailable.")+"</div><div class='sbx-capture-note'>Engine failures are not malware detections. No successful verdict is available for this session.</div><button type='button' class='sbx-secondary-button' onclick='downloadSandboxDiagnostics()'>Export diagnostics</button></div>";
}
function downloadSandboxDiagnostics(){
  var data={sample:sf?sf.name:null,target:curTarget?curTarget.label:null,outcome:sbxOutcome,failure:sbxFailure,engineMessages:sbxDiagnostics,processes:Object.keys(sbxProcessMap).map(function(k){return sbxProcessMap[k]}),http:sbxHttpRequests,connections:sbxConnections,dns:sbxDnsRows,threats:sbxThreats};
  var url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:"application/json;charset=utf-8"})),a=document.createElement("a");
  a.href=url;a.download="sandbox-diagnostics.json";document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(url)},15000);
}

// init — read URL path to activate the right tool
var _initTool=toolFromPath();
selTool(_initTool);syncR("w");syncR("t");syncR("fp");syncR("sbx");
setTimeout(moveSeg,40);window.addEventListener("resize",moveSeg);

// Results are files, not just an analysis.json preview. Works for Decode and
// legacy JS jobs as well as full scans, including nonzero/partial jobs.
function loadArtifacts(id){
  if(jid!==id)return;
  var generation=scanGeneration,artifactMode=curMode,page=0,query="",request=0;
  if(artifactAbort)artifactAbort.abort();
  var old=document.getElementById("artifactResults");if(old)old.remove();
  var wrap=document.createElement("div");wrap.id="artifactResults";wrap.className="done-card";
  document.getElementById("res").appendChild(wrap);
  var ru=uiLang==="ru";
  wrap.innerHTML="<div class='dt'>"+(ru?"Файлы результата":"Result files")+"</div>";
  var search=document.createElement("form"),input=document.createElement("input"),searchBtn=document.createElement("button");
  input.type="search";input.maxLength=256;input.placeholder=ru?"Найти файл или папку…":"Search file or folder…";input.setAttribute("aria-label",input.placeholder);
  searchBtn.type="submit";searchBtn.textContent=ru?"Найти":"Search";search.appendChild(input);search.appendChild(searchBtn);wrap.appendChild(search);
  var info=document.createElement("div"),list=document.createElement("div"),nav=document.createElement("div");
  list.className="file-list";list.style.maxHeight="360px";list.style.overflow="auto";wrap.appendChild(info);wrap.appendChild(list);wrap.appendChild(nav);
  function current(serial){return serial===request&&scanIsCurrent(generation,id,artifactMode)&&document.getElementById("artifactResults")===wrap;}
  function loadPage(offset){
    var serial=++request;
    if(artifactAbort)artifactAbort.abort();artifactAbort=new AbortController();
    info.textContent=ru?"Загрузка файлов результата…":"Loading result files…";nav.replaceChildren();list.replaceChildren();
    fetch("/api/artifacts/"+encodeURIComponent(id)+"?offset="+offset+"&q="+encodeURIComponent(query),{signal:artifactAbort.signal,cache:"no-store"}).then(function(r){if(!r.ok)throw Error("files");return r.json();}).then(function(data){
    if(!current(serial))return;
    page=offset;
    var files=data.files||[],ru=uiLang==="ru";
    var h="";
    if(data.done&&data.exit_code!==0)h+="<p>"+(ru?"Задание завершилось с ошибкой. Файлы могут быть частичными; проверь логи. Код: ":"Job failed; files may be partial. Check logs. Exit code: ")+e(data.exit_code)+"</p>";
    var apkFile=files.find(function(f){return f.path.endsWith(".apk")||f.path.endsWith(".xapk");});
    if(artifactMode==="build"&&data.done&&data.exit_code===0&&apkFile){
      h+="<p><a class='ws-button ws-primary' href='/api/artifacts/"+encodeURIComponent(id)+"/files/"+encodeURIComponent(apkFile.path)+"' download='"+e(apkFile.path)+"'>"+(ru?"Скачать ":"Download ")+e(apkFile.path)+"</a></p>";
    }
    var customName=(document.getElementById("outname")&&document.getElementById("outname").value.trim())||
                   (sf?sf.name.replace(/\.[^/.]+$/,""):"archive");
    var safeBase=safeResultBase(customName,"archive");
    var archiveDlName=safeBase+".zip";
    if(data.done)h+="<p><a href='/api/artifacts/"+encodeURIComponent(id)+"/archive.zip' download='"+e(archiveDlName)+"'>"+(ru?"Скачать все файлы ("+e(archiveDlName)+")":"Download all files as ZIP")+"</a></p><p>"+(ru?"ZIP доступен до ":"ZIP supports up to ")+e(data.archive_limit||200000)+(ru?" файлов. Для больших результатов используй рабочую область.":" files. Use the workspace for larger results.")+"</p>";
    if(artifactMode==="decode"&&data.done&&data.exit_code===0){
      var targetExt=(sf&&sf.name&&sf.name.toLowerCase().endsWith(".xapk"))?".xapk":".apk";
      var rebuildName=safeBase+targetExt;
      h+="<p><button type='button' class='ws-button ws-primary' id='rebuildDecodedBtn' onclick='rebuildFromDecoded(\""+encodeURIComponent(id)+"\",\""+e(safeBase)+"\")'>"+(ru?"Собрать в "+e(rebuildName):"Build as "+e(rebuildName))+"</button></p>";
    }
    (data.stages||[]).forEach(function(stage){
      h+="<p><b>"+e(stage.stage)+"</b>: "+e(stage.status)+(stage.diagnostics&&stage.diagnostics.length?" — "+e(stage.diagnostics.join("; ")):"")+"</p>";
      var c=stage.export;
      if(c)h+="<p>"+(ru?"Декодировано функций: ":"Functions decoded: ")+e(c.decoded_functions)+" / "+e(c.total_functions)+" · "+e(c.instructions)+(ru?" инструкций":" instructions")+" · "+fmtSize(c.output_bytes)+(c.limit_reason?" · "+(ru?"Лимит: ":"Limit: ")+e(c.limit_reason):"")+"</p>";
      if(stage.total_functions)h+="<p>"+(ru?"Граф: ":"Graph: ")+e(stage.decoded_functions)+" / "+e(stage.total_functions)+" · "+(ru?"вызовы: ":"call sites: ")+e(stage.recorded_calls)+" / "+e(stage.total_calls)+"</p>";
    });
    if(!files.length)h+="<p>"+(query?(ru?"Совпадений нет.":"No matching files."):(ru?"Файлы не созданы. Проверь ошибки в логах.":"No files were created. Check the logs for errors."))+"</p>";
    info.innerHTML=h;
    files.forEach(function(f){var row=document.createElement("div"),a=document.createElement("a");row.className="file-entry";a.href="/api/artifacts/"+encodeURIComponent(id)+"/files/"+f.path.split("/").map(encodeURIComponent).join("/");a.download="";a.textContent=f.path+" · "+fmtSize(f.size);row.appendChild(a);list.appendChild(row);});
    var caption=document.createElement("span");caption.textContent=(ru?"Файлы ":"Files ")+(files.length?offset+1:0)+"–"+(offset+files.length)+(data.truncated?"+":"");nav.appendChild(caption);
    function pageButton(label,next){var b=document.createElement("button");b.type="button";b.textContent=label;b.addEventListener("click",function(){loadPage(next);});nav.appendChild(b);}
    if(offset>0)pageButton(ru?"Назад":"Previous",Math.max(0,offset-2000));
    if(data.truncated)pageButton(ru?"Далее":"Next",data.next_offset);
    var hasHTML=!!(data.reports&&data.reports["REPORT.html"]);
    document.getElementById("dlbtn").style.display=hasHTML?"":"none";
    document.getElementById("openbtn").style.display=hasHTML?"":"none";
  }).catch(function(){if(current(serial))info.textContent=ru?"Не удалось получить список файлов. Проверь логи и рабочую область.":"Cannot load result files. Check logs and the workspace.";});
  }
  search.addEventListener("submit",function(ev){ev.preventDefault();query=input.value.trim();loadPage(0);});
  loadPage(0);
}

function syncStaticOutputFlags(){
  var save=document.querySelector("input.fg[data-f='-save-decoded']");if(!save)return;
  save.disabled=!!sf&&/\.(bundle|hbc|jsbundle|js|mjs|cjs|ipa)$/i.test(sf.name);
  ["-java-view","-no-resources","-copy-original"].forEach(function(flag){
    var el=document.querySelector("input.fg[data-f='"+flag+"']");
    if(el)el.disabled=save.disabled||!save.checked;
  });
}
document.addEventListener("change",syncStaticOutputFlags);
syncStaticOutputFlags();

window.rebuildFromDecoded = function(id, baseName) {
  fetch("/api/artifacts/" + encodeURIComponent(id) + "/archive.zip")
    .then(function(r){ return r.blob(); })
    .then(function(blob){
      var ext = (sf && sf.name && sf.name.toLowerCase().endsWith(".xapk")) ? ".xapk" : ".apk";
      selTool("build");
      var file = new File([blob], baseName + ".zip", { type: "application/zip" });
      setf(file, 1);
      var on = document.getElementById("outname");
      if (on) on.value = safeResultBase(baseName,"app") + ext;
      var sbtn = document.getElementById("sbtn");
      if (sbtn) {
        sbtn.scrollIntoView({ behavior: "smooth", block: "center" });
        sbtn.focus();
      }
    });
};
