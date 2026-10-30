// Minimal DOM for dependency-free logic tests. Browser QA covers real layout.
const assert = require('node:assert/strict');
class Element {
  constructor(tag='div') {
    this.tagName=tag.toUpperCase();this.nodeType=1;this.children=[];this.listeners={};this.attributes={};this.dataset={};this.style={};this.value='';this.disabled=false;this.hidden=false;this._text='';
    const classes=new Set();
    this.classList={add:(...v)=>v.forEach(x=>classes.add(x)),remove:(...v)=>v.forEach(x=>classes.delete(x)),contains:v=>classes.has(v),toggle:(v,force)=>{const on=force===undefined?!classes.has(v):force;if(on)classes.add(v);else classes.delete(v);return on;}};
  }
  set className(v){this._className=v;v.split(/\s+/).filter(Boolean).forEach(x=>this.classList.add(x));}
  get className(){return this._className||'';}
  get textContent(){return this._text+this.children.map(e=>e.textContent).join('');}
  set textContent(v){this._text=String(v);this.children=[];}
  set innerHTML(v){this._html=v;this.children=[];this._text='';}
  get innerHTML(){return this._html||'';}
  get childNodes(){return this.children;}
  get firstChild(){return this.children[0];}
  get lastElementChild(){return this.children.at(-1);}
  appendChild(e){e.parentElement=this;this.children.push(e);return e;}
  append(...es){es.forEach(e=>this.appendChild(e));}
  prepend(e){e.parentElement=this;this.children.unshift(e);}
  replaceChildren(...es){this.children=[];this._text='';this.append(...es);}
  remove(){if(this.parentElement)this.parentElement.children=this.parentElement.children.filter(e=>e!==this);}
  setAttribute(k,v){this.attributes[k]=String(v);}
  removeAttribute(k){delete this.attributes[k];}
  addEventListener(name,fn){(this.listeners[name]||= []).push(fn);}
  dispatchEvent(e){e.target||=this;e.preventDefault||=()=>{};for(const fn of this.listeners[e.type]||[])fn.call(this,e);}
  showModal(){this.open=true;}
  close(){this.open=false;this.dispatchEvent({type:'close'});}
  focus(){this.focused=true;}
  scrollIntoView(){}
  contains(e){return e===this||this.children.some(c=>c.contains(e));}
  matches(selector){
    if(selector.startsWith('.'))return this.classList.contains(selector.slice(1));
    if(selector.startsWith('#'))return this.id===selector.slice(1);
    const attr=/^\[([^=\]]+)(?:=["']?([^"'\]]+)["']?)?\]$/.exec(selector);
    if(attr){const key=attr[1];const actual=key.startsWith('data-')?this.dataset[key.slice(5).replace(/-([a-z])/g,(_,c)=>c.toUpperCase())]:this.attributes[key]??this[key];return actual!==undefined&&(attr[2]===undefined||String(actual)===attr[2]);}
    return this.tagName===selector.toUpperCase();
  }
  querySelectorAll(selector){const out=[];for(const child of this.children){if(child.matches(selector))out.push(child);out.push(...child.querySelectorAll(selector));}return out;}
  querySelector(selector){return this.querySelectorAll(selector)[0]||null;}
  closest(selector){return this.matches(selector)?this:this.parentElement?.closest(selector)||null;}
}
function createDOM(html){
  const ids={};const body=new Element('body');
  for(const match of html.matchAll(/<([\w-]+)[^>]*\bid="([^"]+)"[^>]*>/g)){
    const e=new Element(match[1]);e.id=match[2];ids[e.id]=e;body.appendChild(e);
  }
  const extras={};
  const document={body,activeElement:null,getElementById:id=>ids[id]||body.querySelector('#'+id),createElement:tag=>new Element(tag),createElementNS:(ns,tag)=>{const e=new Element(tag);e.namespaceURI=ns;return e;},createTextNode:text=>{const e=new Element('#text');e.nodeType=3;e.textContent=text;return e;},addEventListener(){},querySelector:selector=>extras[selector]||body.querySelector(selector),querySelectorAll:selector=>body.querySelectorAll(selector)};
  return {document,ids,extras,Element};
}
function required(ids,id){assert.ok(ids[id],`Missing HTML element ${id}`);return ids[id];}
module.exports={Element,createDOM,required};
