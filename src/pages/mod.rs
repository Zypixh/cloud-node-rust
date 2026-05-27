pub mod challenges;
pub mod lang;

pub use lang::Lang;

/// Top safety page wrapping `<html>` — UAM challenge family.
pub fn uam_challenge_page(
    body_html: &str,
    script: &str,
    lang: Lang,
    request_id: &str,
) -> String {
    let t = lang::text(lang);
    let css = shared_css();
    let i18n = browser_i18n_script();
    format!(
        r#"<!doctype html><html lang="{lang_attr}" data-i18n-document-title="title"><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{title}</title><style>{css}</style><script>{i18n}</script></head><body>{lang_bar}<main class="card"><div class="mark waf"></div>{body_html}</main>{script}</body></html>"#,
        lang_attr = lang.html_attr(),
        title    = t.title,
        css      = css,
        i18n     = i18n,
        lang_bar = lang_bar_html(lang, request_id),
        body_html = body_html,
        script   = script,
    )
}

/// WAF slider challenge full page.
pub fn waf_slider_page(
    lang: Lang,
    request_id: &str,
    slider_html: &str,
    script: &str,
) -> String {
    let t = lang::text(lang);
    let css = shared_css();
    let i18n = browser_i18n_script();
    format!(
        r#"<!doctype html><html lang="{lang_attr}" data-i18n-document-title="title"><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{title}</title><style>{css}</style><script>{i18n}</script></head><body>{lang_bar}{slider_html}<noscript><p class="error" data-i18n="no_js">{nojs}</p></noscript>{script}</body></html>"#,
        lang_attr = lang.html_attr(),
        title    = t.title,
        css      = css,
        i18n     = i18n,
        lang_bar = lang_bar_html(lang, request_id),
        slider_html = slider_html,
        nojs    = t.no_js,
        script  = script,
    )
}

/// WAF / CC block page.
pub fn block_page(
    lang: Lang,
    status: u16,
    reason: &str,
    request_id: &str,
    body_extra: &str,
) -> String {
    let t = lang::text(lang);
    let css = format!("{}{}", shared_css(), block_page_css());
    let i18n = browser_i18n_script();
    let status_text = t.access_denied;
    format!(
        r#"<!doctype html><html lang="{lang_attr}" data-i18n-document-title="block_title" data-i18n-args='{{"status":"{status}"}}'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>{status} {status_text}</title><style>{css}</style><script>{i18n}</script></head><body class="block-page">{lang_bar}<main class="block-panel" role="alert"><section class="block-head"><div class="mark block" aria-hidden="true"></div><div class="block-summary"><div class="block-label" data-i18n="security_notice">Security notice</div><h1><span class="block-code">{status}</span> <span data-i18n="access_denied">{status_text}</span></h1></div></section><section class="block-content"><p class="block-reason" data-i18n="block_reason">{reason}</p><div class="block-extra">{body_extra}</div><div class="block-info"><div class="block-info-row"><span data-i18n="request_id">Request</span><code>#{request_id}</code></div></div><div class="block-footer" data-i18n="footer">{footer}</div></section></main></body></html>"#,
        lang_attr = lang.html_attr(),
        css      = css,
        i18n     = i18n,
        lang_bar = lang_bar_html(lang, request_id),
        status   = status,
        status_text = status_text,
        reason   = reason,
        body_extra = body_extra,
        footer   = t.footer,
        request_id = request_id,
    )
}

pub fn verification_failed_page() -> String {
    let css = shared_css();
    let i18n = browser_i18n_script();
    format!(
        r#"<!doctype html><html lang="en" data-i18n-document-title="title"><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Security Verification</title><style>{css}</style><script>{i18n}</script></head><body><main class="card"><div class="mark block"></div><h1 data-i18n="verify_failed_title">Security verification failed</h1><p data-i18n="verify_failed_body">Please go back and try again.</p></main></body></html>"#,
        css = css,
        i18n = i18n,
    )
}

// ── internal helpers ──────────────────────────────────────────

pub(crate) fn lang_bar_html(lang: Lang, request_id: &str) -> String {
    let (title, label) = match lang {
        Lang::ZhCn => ("Switch to English", "English"),
        Lang::En => ("切换到中文", "中文"),
    };
    format!(
        r#"<nav class="lang-bar"><span class="lang-req">#{request_id}</span><button class="lang-btn" type="button" data-i18n-lang-toggle onclick="window.cloudNodeSetLang&&window.cloudNodeSetLang(window.__cloudNodeLang==='zh'?'en':'zh')" title="{title}">{label}</button></nav>"#,
        request_id = request_id,
        title   = title,
        label   = label,
    )
}

pub(crate) fn browser_i18n_script() -> &'static str {
    r#"(function(){
var D={
 en:{
	  title:"Security Verification",no_js:"JavaScript is required for this security check.",
  access_denied:"Access Denied",footer:"Protected by Cloud Node Security",security_notice:"Security notice",request_id:"Request",block_title:"{status} Access Denied",block_reason:"This request was blocked by the security policy.",
  switch_label:"中文",switch_title:"切换到中文",
  checking:"Checking your browser",checking_sub:"Please wait while we verify your browser capability.",
  computing_pow:"Computing proof of work ({difficulty})",pow_preparing:"Preparing proof of work...",
  pow_status_computing:"Computing proof...",pow_status_done:"Proof complete, finishing browser check...",pow_difficulty:"difficulty",
  slide_prompt:"Slide to complete the browser check.",slide_status:"Slide the handle to the highlighted zone",
  slide_retry:"Not quite there, please try again",verifying:"Verifying...",verifying_browser:"Verifying browser...",
  verify_failed:"Verification failed, please retry",verify_failed_title:"Security verification failed",verify_failed_body:"Please go back and try again.",
  click_instr:"Click the RED characters in numbered order",click_hint:"Ignore grey - click only red",click_done:"All correct",
  captcha_prompt:"Enter the BLACK characters (ignore grey)",captcha_hint:"Only enter the black characters - grey are decoys",
  captcha_placeholder:"Enter code",captcha_btn:"Verify",captcha_refresh:"Click to refresh",
  js_heading:"Checking your browser",js_sub:"Please wait while JavaScript, cookies, and browser signals are verified.",
  js_runtime:"JavaScript runtime",js_cookie:"Cookie roundtrip",js_fingerprint:"Browser signals",js_submit:"Submitting check",
  js_initializing:"Initializing browser check...",js_check_runtime:"Checking JavaScript runtime...",
  js_check_cookie:"Checking cookie roundtrip...",js_collect:"Collecting browser signals...",js_submitting:"Submitting browser check...",
  js_failed:"Browser verification failed. Please refresh and try again.",js_min_display:"Minimum display time: {seconds}s",
  slider_puzzle_prompt:"Drag the puzzle piece to the gap"
 },
 zh:{
	  title:"安全验证",no_js:"此安全验证需要启用 JavaScript。",
  access_denied:"访问被拒绝",footer:"由 Cloud Node 安全防护提供",security_notice:"安全拦截",request_id:"请求编号",block_title:"{status} 访问被拒绝",block_reason:"此请求已被安全策略拦截。",
  switch_label:"English",switch_title:"Switch to English",
  checking:"正在检查您的浏览器",checking_sub:"请稍候，我们正在验证您的浏览器能力。",
  computing_pow:"正在计算工作量证明 ({difficulty})",pow_preparing:"正在准备工作量证明...",
  pow_status_computing:"正在计算证明...",pow_status_done:"证明完成，正在完成浏览器检查...",pow_difficulty:"难度",
  slide_prompt:"请完成滑块验证以继续。",slide_status:"将滑块拖拽到高亮区域",
  slide_retry:"位置未对准，请重试",verifying:"验证中...",verifying_browser:"正在验证浏览器...",
  verify_failed:"验证失败，请重试",verify_failed_title:"安全验证失败",verify_failed_body:"请返回上一页后重试。",
  click_instr:"请按序号点击红色字符",click_hint:"忽略灰色字符，只点红色",click_done:"全部正确",
  captcha_prompt:"请输入黑色字符（忽略灰色小字）",captcha_hint:"只输入黑色大字，灰色小字是干扰项",
  captcha_placeholder:"输入验证码",captcha_btn:"验证",captcha_refresh:"点击刷新",
  js_heading:"正在检查浏览器",js_sub:"请稍候，正在验证 JavaScript、Cookie 与浏览器环境。",
  js_runtime:"JavaScript 运行时",js_cookie:"Cookie 回写",js_fingerprint:"浏览器环境",js_submit:"提交校验",
  js_initializing:"正在初始化浏览器检查...",js_check_runtime:"正在检查 JavaScript 运行时...",
  js_check_cookie:"正在检查 Cookie 回写...",js_collect:"正在采集浏览器环境...",js_submitting:"正在提交浏览器检查...",
  js_failed:"浏览器校验失败，请刷新后重试。",js_min_display:"最短显示时间：{seconds} 秒",
  slider_puzzle_prompt:"拖动拼图块到缺口位置"
 }
};
function norm(v){v=(v||"").toLowerCase();if(v.indexOf("zh")===0)return"zh";if(v.indexOf("en")===0)return"en";return""}
function stored(){try{return norm(localStorage.getItem("cloudNodeChallengeLang"))}catch(e){return""}}
function query(){try{return norm(new URLSearchParams(location.search).get("lang"))}catch(e){return""}}
function browser(){var xs=(navigator.languages&&navigator.languages.length)?navigator.languages:[navigator.language||navigator.userLanguage||""];for(var i=0;i<xs.length;i++){var n=norm(xs[i]);if(n)return n}return"en"}
function parseArgs(el){try{return JSON.parse(el.getAttribute("data-i18n-args")||"{}")}catch(e){return{}}}
function fmt(s,a){return String(s||"").replace(/\{([a-zA-Z0-9_]+)\}/g,function(_,k){return a&&a[k]!=null?a[k]:""})}
function text(k,a){var l=window.__cloudNodeLang||"en";return fmt((D[l]&&D[l][k])||D.en[k]||"",a||{})}
function skip(el){return !!(el&&el.closest&&el.closest("[data-i18n-ignore]"))}
function setAttr(sel,attr){var xs=document.querySelectorAll(sel);for(var i=0;i<xs.length;i++){var el=xs[i];if(skip(el))continue;var key=el.getAttribute(sel.slice(1,-1));if(key)el.setAttribute(attr,text(key,parseArgs(el)))}}
function apply(lang){lang=norm(lang)||browser();window.__cloudNodeLang=lang;document.documentElement.lang=lang==="zh"?"zh-CN":"en";document.documentElement.setAttribute("data-lang",lang);var tk=document.documentElement.getAttribute("data-i18n-document-title");if(tk)document.title=text(tk,parseArgs(document.documentElement));
 var xs=document.querySelectorAll("[data-i18n]");for(var i=0;i<xs.length;i++){var el=xs[i];if(skip(el))continue;el.textContent=text(el.getAttribute("data-i18n"),parseArgs(el))}
 setAttr("[data-i18n-placeholder]","placeholder");setAttr("[data-i18n-title]","title");setAttr("[data-i18n-aria-label]","aria-label");
 var bs=document.querySelectorAll("[data-i18n-lang-toggle]");for(var j=0;j<bs.length;j++){bs[j].textContent=text("switch_label");bs[j].setAttribute("title",text("switch_title"))}}
window.cloudNodeText=text;
window.cloudNodeSetLang=function(lang){lang=norm(lang)||"en";try{localStorage.setItem("cloudNodeChallengeLang",lang)}catch(e){}apply(lang)};
window.__cloudNodeLang=stored()||query()||browser();
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",function(){apply(window.__cloudNodeLang)});else apply(window.__cloudNodeLang);
})();"#
}

pub(crate) fn shared_css() -> &'static str {
    r#":root{color-scheme:light dark;--bg:linear-gradient(135deg,#f6f8fb,#e8ecf1);--card-bg:rgba(255,255,255,.96);--card-border:rgba(15,23,42,.08);--text:#1f2937;--muted:#667085;--dim:#98a2b3;--green:#22c55e;--blue:#0ea5e9;--red:#dc2626;--waf:linear-gradient(135deg,#6366f1,#38bdf8);--block:linear-gradient(135deg,#ef4444,#f97316);--shadow:0 20px 60px rgba(15,23,42,.1);--lang-bg:rgba(15,23,42,.04)}@media(prefers-color-scheme:dark){:root{--bg:linear-gradient(135deg,#0f172a,#111827 55%,#1e293b);--card-bg:rgba(24,34,48,.94);--card-border:rgba(255,255,255,.1);--text:#f9fafb;--muted:#aeb8c7;--dim:#667085;--shadow:0 20px 60px rgba(0,0,0,.4);--lang-bg:rgba(255,255,255,.06)}}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans SC',sans-serif;background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased}.lang-bar{position:fixed;top:14px;right:16px;display:flex;align-items:center;gap:10px;z-index:10}.lang-req{font-size:11px;color:var(--dim);font-family:ui-monospace,'SF Mono',monospace;background:var(--lang-bg);padding:4px 10px;border-radius:999px}.lang-btn{font-size:13px;font-weight:600;color:var(--text);background:var(--lang-bg);border:1px solid var(--card-border);padding:5px 14px;border-radius:999px;cursor:pointer;transition:all .15s}.lang-btn:hover{background:var(--text);color:#fff}.card{width:min(92vw,460px);padding:40px 34px;border-radius:20px;background:var(--card-bg);border:1px solid var(--card-border);box-shadow:var(--shadow);text-align:center}.mark{width:58px;height:58px;margin:0 auto 22px;border-radius:18px;box-shadow:0 14px 34px rgba(99,102,241,.3)}.mark.waf{background:var(--waf)}.mark.block{background:var(--block)}h1{margin:0 0 10px;font-size:23px;font-weight:700}p{margin:0 0 24px;color:var(--muted);line-height:1.65;font-size:15px}.progress,.track{height:46px;border-radius:999px;background:rgba(148,163,184,.18);overflow:hidden;position:relative}.progress span{display:block;width:42%;height:100%;border-radius:999px;background:linear-gradient(90deg,var(--green),var(--blue));animation:pulse 1.3s ease-in-out infinite}.track{touch-action:none;cursor:pointer;border:1px solid var(--card-border)}.track:before{content:'';position:absolute;inset:0;background:repeating-linear-gradient(110deg,transparent 0 13px,rgba(148,163,184,.12) 14px 16px);border-radius:999px}.fill{position:absolute;inset:0 auto 0 0;width:0;background:linear-gradient(90deg,var(--green),var(--blue));border-radius:999px}.handle{position:absolute;top:3px;left:3px;width:40px;height:40px;border-radius:50%;display:grid;place-items:center;background:#fff;color:#0f172a;font-weight:800;box-shadow:0 6px 20px rgba(0,0,0,.22);user-select:none}.status{margin-top:14px;font-size:14px;color:var(--muted)}.error{color:var(--red)}.meta{margin-top:18px;font-size:12px;color:var(--dim)}@keyframes pulse{0%,100%{transform:translateX(-18%)}50%{transform:translateX(150%)}}"#
}

fn block_page_css() -> &'static str {
    r#"body.block-page{padding:76px 18px 32px;align-items:center}.block-panel{width:min(94vw,560px);overflow:hidden;text-align:left;border-radius:22px;background:var(--card-bg);border:1px solid var(--card-border);box-shadow:var(--shadow)}.block-head{display:flex;align-items:flex-start;gap:18px;padding:28px 30px 24px;background:linear-gradient(135deg,rgba(239,68,68,.13),rgba(249,115,22,.08));border-bottom:1px solid var(--card-border)}.block-page .mark.block{position:relative;flex:0 0 58px;margin:0;box-shadow:0 16px 36px rgba(239,68,68,.24)}.block-page .mark.block:before{content:'';position:absolute;left:18px;right:18px;top:13px;bottom:14px;border:2px solid rgba(255,255,255,.92);border-top-width:8px;border-radius:4px 4px 12px 12px}.block-summary{min-width:0;flex:1}.block-label{display:inline-flex;align-items:center;gap:8px;margin:0 0 12px;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.08em;color:var(--red)}.block-label:before{content:'';width:7px;height:7px;border-radius:999px;background:var(--red);box-shadow:0 0 0 4px rgba(220,38,38,.12)}.block-panel h1{margin:0;font-size:clamp(24px,3.4vw,34px);line-height:1.12;letter-spacing:0}.block-code{font-variant-numeric:tabular-nums}.block-content{padding:26px 30px 28px}.block-reason{margin:0;color:var(--muted);font-size:16px;line-height:1.7}.block-extra{margin-top:18px}.block-extra:empty{display:none}.block-info{margin-top:24px;display:grid;gap:10px}.block-info-row{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:12px 14px;border:1px solid var(--card-border);border-radius:12px;background:rgba(148,163,184,.08)}.block-info-row span{font-size:12px;color:var(--dim);font-weight:800;text-transform:uppercase;letter-spacing:.08em}.block-info-row code{font-family:ui-monospace,'SF Mono',monospace;color:var(--text);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:70%}.block-footer{margin-top:18px;color:var(--dim);font-size:12px;text-align:center}@media(max-width:560px){body.block-page{padding:76px 12px 24px}.block-head{padding:24px 22px;gap:14px}.block-content{padding:22px}.block-page .mark.block{width:50px;height:50px;flex-basis:50px;border-radius:16px}.block-page .mark.block:before{left:15px;right:15px;top:12px;bottom:12px}.block-panel h1{font-size:25px}.block-info-row{align-items:flex-start;flex-direction:column;gap:6px}.block-info-row code{max-width:100%;white-space:normal;overflow-wrap:anywhere}}"#
}

/// Determine the preferred language from query param (`?lang=zh` / `?lang=en`)
/// or Accept-Language header, falling back to English.
pub fn detect_lang(
    query_lang: Option<&str>,
    accept_language: Option<&str>,
) -> Lang {
    if let Some(q) = query_lang {
        let q = q.trim().to_lowercase();
        if q.starts_with("zh") { return Lang::ZhCn; }
        if q.starts_with("en") { return Lang::En; }
    }
    if let Some(al) = accept_language {
        let al = al.to_lowercase();
        if al.contains("zh") { return Lang::ZhCn; }
    }
    Lang::En
}
