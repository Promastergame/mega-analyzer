"use strict";
(() => {
  const dialog=document.getElementById("browserNotice");if(!dialog)return;
  const preference="ma-browser-notice-hidden",remember=document.getElementById("browserNoticeRemember");
  function setLanguage(language){
    const ru=language==="ru";
    document.getElementById("browserNoticeTitle").textContent=ru?"Перед началом":"Before you start";
    document.getElementById("browserNoticeText").textContent=ru?"Файлы остаются на вашем устройстве. Скачайте результаты перед закрытием или обновлением страницы.":"Files stay on your device. Save your results before closing or refreshing this page.";
    document.getElementById("browserNoticeRememberText").textContent=ru?"Больше не показывать":"Don't show again";
    document.getElementById("browserNoticeAccept").textContent=ru?"Понятно":"Got it";
    document.getElementById("browserNoticeClose").setAttribute("aria-label",ru?"Закрыть":"Close");
  }
  function close(){
    if(remember.checked)try{localStorage.setItem(preference,"1");}catch{}
    dialog.close();document.getElementById("dz")?.focus({preventScroll:true});
  }
  document.getElementById("browserNoticeClose").addEventListener("click",close);
  document.getElementById("browserNoticeAccept").addEventListener("click",close);
  dialog.addEventListener("cancel",event=>{event.preventDefault();close();});
  dialog.addEventListener("click",event=>{
    if(event.target!==dialog)return;const box=dialog.getBoundingClientRect();
    if(event.clientX<box.left||event.clientX>box.right||event.clientY<box.top||event.clientY>box.bottom)close();
  });
  window.MegaBrowserNotice={setLanguage};
  document.addEventListener("DOMContentLoaded",()=>{
    setLanguage(typeof uiLang==="string"?uiLang:"en");
    try{if(localStorage.getItem(preference)==="1")return;}catch{}
    dialog.showModal();
  },{once:true});
})();
