"use strict";(()=>{var L=`
:host { all: initial; }
.backdrop { position: fixed; inset: 0; background: rgba(0,0,0,.45); display: flex; align-items: center; justify-content: center; z-index: 2147483647; font: 15px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
.box { background: #fff; color: #1a1a1a; border-radius: 10px; padding: 20px; width: min(360px, calc(100vw - 32px)); box-shadow: 0 10px 40px rgba(0,0,0,.3); }
h2 { margin: 0 0 6px; font-size: 18px; }
p { margin: 0 0 12px; color: #444; }
img { display: block; width: 100%; height: auto; border: 1px solid #ccc; border-radius: 6px; background: #f4f4f4; }
.row { display: flex; gap: 8px; margin: 10px 0; flex-wrap: wrap; }
button { font: inherit; padding: 8px 12px; border-radius: 6px; border: 1px solid #888; background: #f6f6f6; color: #1a1a1a; cursor: pointer; min-height: 40px; }
button.primary { background: #1f4fd6; border-color: #1f4fd6; color: #fff; }
button:focus-visible, input:focus-visible, a:focus-visible { outline: 3px solid #f0a500; outline-offset: 2px; }
label { display: block; font-weight: 600; margin: 8px 0 4px; }
input { font: inherit; font-size: 20px; letter-spacing: 4px; text-transform: uppercase; width: 100%; box-sizing: border-box; padding: 8px 10px; border: 1px solid #888; border-radius: 6px; }
.err { color: #b00020; min-height: 1.4em; margin: 6px 0 0; }
.foot { margin-top: 12px; font-size: 13px; }
a { color: #1f4fd6; }
@media (forced-colors: active) { .box { border: 2px solid CanvasText; } button.primary { forced-color-adjust: auto; } }
@media (prefers-color-scheme: dark) { .box { background: #1e1e1e; color: #eee; } p { color: #bbb; } button { background: #2b2b2b; color: #eee; } input { background: #111; color: #eee; } a { color: #8fb0ff; } .err { color: #ff8a8a; } }
@media (prefers-reduced-motion: no-preference) { .box { animation: in .15s ease-out; } @keyframes in { from { transform: translateY(6px); opacity: 0; } } }
`;function T(o){return new Promise((k,p)=>{let i=document.createElement("div"),s=i.attachShadow({mode:"open"});i.setAttribute("data-doorkeep-challenge","");let v=document.activeElement,n=t=>"dk-"+t;s.innerHTML=`<style>${L}</style>
<div class="backdrop">
  <div class="box" role="dialog" aria-modal="true" aria-labelledby="${n("t")}" aria-describedby="${n("d")}">
    <h2 id="${n("t")}">Quick check</h2>
    <p id="${n("d")}">Type the ${o.length} characters shown below, or listen to them. Letters are not case-sensitive.</p>
    <img alt="Characters to type. If you cannot see them, use the Listen button." />
    <div class="row">
      <button type="button" data-a="listen">Listen</button>
      <button type="button" data-a="slow">Listen slowly</button>
    </div>
    <label for="${n("i")}">Characters</label>
    <input id="${n("i")}" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="${o.length+4}" inputmode="text" />
    <p class="err" role="status" aria-live="polite"></p>
    <div class="row">
      <button type="button" class="primary" data-a="submit">Continue</button>
      <button type="button" data-a="cancel">Cancel</button>
    </div>
    ${o.accessibilityUrl?`<p class="foot">Having trouble? <a href="${encodeURI(o.accessibilityUrl)}" target="_blank" rel="noopener">Use another way to continue</a>.</p>`:""}
  </div>
</div>`;let l=t=>s.querySelector(t),b=l("img"),a=l("input"),r=l(".err"),m=l("[role=dialog]"),g=o.audio,w=o.audioSlow;b.src=o.image;let c=null,x=t=>{c?.pause(),c=new Audio(t),c.play().catch(()=>{r.textContent="Audio could not play. Check that sound is allowed."})},d=()=>{c?.pause(),document.removeEventListener("keydown",y,!0),i.remove(),v?.focus?.()},f=!1,h=async()=>{let t=a.value.trim();if(!f){if(t.length<o.length){r.textContent=`Please type all ${o.length} characters.`,a.focus();return}f=!0,r.textContent="Checking\u2026";try{let e=await o.submit(t);if(e.ok){d(),k(e.token);return}if(e.exhausted){d(),p(new Error("doorkeep: challenge exhausted"));return}e.image&&(b.src=e.image),e.audio&&(g=e.audio),r.textContent=`That did not match. ${e.attemptsLeft??""} ${e.attemptsLeft===1?"try":"tries"} left.`.replace("  "," "),a.value="",a.focus()}catch{r.textContent="Something went wrong. Please try again."}finally{f=!1}}},y=t=>{if(t.key==="Escape"){t.preventDefault(),d(),p(new Error("doorkeep: challenge cancelled"));return}if(t.key==="Enter"&&s.activeElement===a){t.preventDefault(),h();return}if(t.key==="Tab"){let e=Array.from(m.querySelectorAll("button, input, a[href]")),u=e.indexOf(s.activeElement),E=t.shiftKey?u<=0?e.length-1:u-1:u===e.length-1?0:u+1;t.preventDefault(),e[E].focus()}};m.addEventListener("click",t=>{let e=t.target.closest("button")?.dataset.a;e==="listen"?x(g):e==="slow"?x(w):e==="submit"?h():e==="cancel"&&(d(),p(new Error("doorkeep: challenge cancelled")))}),document.addEventListener("keydown",y,!0),document.body.appendChild(i),a.focus()})}window.__doorkeepUI={open:T};})();
