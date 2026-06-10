use base64::Engine;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UamMode {
    JsCookie,
    Pow,
    Captcha,
    Slider,
}

impl UamMode {
    pub fn from_str(s: &str) -> Self {
        let normalized = s
            .trim()
            .to_ascii_lowercase()
            .chars()
            .filter(|ch| !matches!(ch, '-' | '_' | ' '))
            .collect::<String>();
        match normalized.as_str() {
            "pow" | "proofofwork" => Self::Pow,
            "captcha" => Self::Pow,
            "slider" | "slide" => Self::Pow,
            "jscookie" | "cookie" | "js" | "javascriptcookie" => Self::Pow,
            _ => Self::Pow,
        }
    }
}

pub struct UamIssueCtx<'a> {
    pub token: &'a str,
    pub challenge_life_seconds: i64,
    pub pow_difficulty: u8,
    pub verify_route: &'a str,
    pub return_path: &'a str,
    pub slider_target: u32,
}

pub trait UamChallenge {
    fn issue_html(&self, ctx: &UamIssueCtx) -> String;
}

pub struct JsCookieChallenge;

impl UamChallenge for JsCookieChallenge {
    fn issue_html(&self, ctx: &UamIssueCtx) -> String {
        let script = get_js_cookie_script(ctx.token, ctx.verify_route, ctx.return_path);
        format!(
            "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Security Verification</title><style>{}</style><script>{}</script></head><body><main class='sl-card'><div class='sl-logo'>${{product.name}}</div><h1 data-i18n='checking'>Checking your browser</h1><p data-i18n='checking_sub'>Please wait while we verify your browser capability.</p><div class='sl-progress'><span></span></div><div class='sl-meta'>Request ${{requestId}}</div></main><script>{}</script></body></html>",
            cloud_challenge_css(),
            crate::pages::browser_i18n_script(),
            script
        )
    }
}

pub struct PowChallenge;

impl UamChallenge for PowChallenge {
    fn issue_html(&self, ctx: &UamIssueCtx) -> String {
        let difficulty = ctx.pow_difficulty.clamp(5, 8) as u32;
        let pow_script = get_pow_script(
            ctx.token,
            difficulty,
            ctx.challenge_life_seconds,
            ctx.verify_route,
            ctx.return_path,
        );
        format!(
            "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Security Verification</title><style>{}{}</style><script>{}</script></head><body><main class='sl-card'><div class='sl-logo'>${{product.name}}</div><h1 data-i18n='checking'>Checking your browser</h1><p data-i18n='computing_pow' data-i18n-args='{{\"difficulty\":\"{difficulty}\"}}'>Please wait while we compute proof of work ({difficulty}).</p><div class='sl-progress'><span id='slPowBar'></span></div><div id='slPowStatus' class='sl-status' data-i18n='pow_preparing'>Preparing proof of work...</div><div class='sl-meta'>Request ${{requestId}}</div></main><script>{pow_script}</script></body></html>",
            cloud_challenge_css(),
            pow_progress_css(),
            crate::pages::browser_i18n_script()
        )
    }
}

pub struct CaptchaChallenge;

impl UamChallenge for CaptchaChallenge {
    fn issue_html(&self, ctx: &UamIssueCtx) -> String {
        cloud_slider_html(ctx)
    }
}

pub struct SliderChallenge;

impl UamChallenge for SliderChallenge {
    fn issue_html(&self, ctx: &UamIssueCtx) -> String {
        cloud_slider_html(ctx)
    }
}

pub fn dispatch(mode: UamMode) -> Box<dyn UamChallenge + Send + Sync> {
    match mode {
        UamMode::JsCookie => Box::new(JsCookieChallenge),
        UamMode::Pow => Box::new(PowChallenge),
        UamMode::Captcha => Box::new(CaptchaChallenge),
        UamMode::Slider => Box::new(SliderChallenge),
    }
}

fn get_pow_script(
    challenge: &str,
    difficulty: u32,
    life_seconds: i64,
    verify_route: &str,
    return_path: &str,
) -> String {
    let challenge = serde_json::to_string(challenge).unwrap_or_else(|_| "\"\"".to_string());
    let route = serde_json::to_string(verify_route).unwrap_or_else(|_| "\"/\"".to_string());
    let ret = serde_json::to_string(return_path).unwrap_or_else(|_| "\"/\"".to_string());
    let timeout_ms = life_seconds.max(1) * 1000;
    let inner = format!(
        r#"(function(){{
	const C={challenge},D={difficulty},R={route},RET={ret},T={timeout_ms},MIN=5000;
	const P="0".repeat(D),E=new TextEncoder(),S=Date.now(),B=64;
	let n=0,last=0,done=false;
	const $=id=>document.getElementById(id),bar=$("slPowBar"),st=$("slPowStatus");
	function msg(k){{return window.cloudNodeText?window.cloudNodeText(k):({{pow_status_computing:"Computing proof...",pow_status_done:"Proof complete, finishing browser check...",pow_difficulty:"difficulty"}}[k]||k);}}
	function setPct(p){{if(bar)bar.style.width=Math.max(3,Math.min(100,p)).toFixed(2)+"%";}}
	function tick(){{
	 const dt=Math.max(1,Date.now()-S), rate=Math.floor(n*1000/dt);
	 const timePct=Math.min(88,3+(Date.now()-S)/Math.max(MIN,T)*85);
	 const workPct=Math.min(88,3+(n/Math.pow(16,D))*85);
	 setPct(Math.max(timePct,workPct));
	 if(st)st.textContent=msg("pow_status_computing")+" nonce "+n.toLocaleString()+" | "+rate.toLocaleString()+"/s | "+msg("pow_difficulty")+" "+D;
	}}
	async function h(x){{const b=new Uint8Array(await crypto.subtle.digest("SHA-256",E.encode(C+x)));return Array.from(b).map(v=>v.toString(16).padStart(2,"0")).join("")}}
	async function batch(start){{
	 const jobs=[];
	 for(let i=0;i<B;i++)jobs.push(h(start+i));
	 const hashes=await Promise.all(jobs);
	 for(let i=0;i<hashes.length;i++)if(hashes[i].startsWith(P))return start+i;
	 return -1;
	}}
	async function run(){{
	 while(!done){{
	  if(Date.now()-S>T){{location.reload();return;}}
	  const found=await batch(n);
	  if(found>=0){{
	   done=true;
	   const finishMs=Math.max(600,MIN-(Date.now()-S));
	   setPct(92);
	   if(st)st.textContent=msg("pow_status_done");
	   const go=()=>{{setPct(100);const q=new URLSearchParams({{__waf_token:C,__waf_pow:String(found),__waf_return:RET,__waf_uam:"1"}});location.replace(R+"?"+q.toString());}};
	   const finStart=Date.now();
	   const fin=setInterval(()=>setPct(92+Math.min(8,(Date.now()-finStart)/Math.max(1,finishMs)*8)),120);
	   setTimeout(()=>{{clearInterval(fin);go();}},finishMs);return;
	  }}
	  n+=B;
	  if(n-last>=512){{last=n;tick();await new Promise(r=>setTimeout(r,0));}}
	 }}
	}}
tick();run();
}})();"#
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
    format!("eval(atob('{}'))", encoded)
}

/// Obfuscated JS cookie verification script.
///
/// Uses eval(atob("...")) wrapping with dynamic base64 encoding to harden
/// against trivial source-reading bypass. The inner core performs multi-layer
/// browser integrity checks:
///   1. setTimeout random delay (100-400 ms)
///   2. Screen dimension / webdriver flag detection
///   3. WebGL renderer fingerprinting via canvas
///   4. Only on success: location.replace with __waf_uam=1 marker
fn get_js_cookie_script(challenge: &str, verify_route: &str, return_path: &str) -> String {
    // Escape for safe embedding in JS single-quoted strings
    let esc = |s: &str| s.replace('\\', "\\\\").replace('\'', "\\'");
    let token_js = esc(challenge);
    let route_js = esc(verify_route);
    let ret_js = esc(return_path);
    let inner = format!(
        r#"(function(){{
var t0=Date.now();
setTimeout(function(){{
 var w=screen.width,h=screen.height;
 if(w<10||h<10||navigator.webdriver){{return;}}
 var c=document.createElement('canvas');
 var g=c.getContext('webgl')||c.getContext('experimental-webgl');
 if(!g){{return;}}
 var d=g.getExtension('WEBGL_debug_renderer_info');
 var r=d?g.getParameter(d.UNMASKED_RENDERER_WEBGL):'';
 var qs='__waf_token='+encodeURIComponent('{token_js}')+'&__waf_return='+encodeURIComponent('{ret_js}')+'&__waf_uam=1&__waf_fp='+encodeURIComponent(r)+'&__waf_ts='+(Date.now()-t0);
 location.replace('{route_js}'+'?'+qs);
}},100+Math.floor(Math.random()*300));
}})();"#,
        token_js = token_js,
        ret_js = ret_js,
        route_js = route_js,
    );
    // base64 编码外层包装
    let encoded = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
    format!("eval(atob('{}'))", encoded)
}

/// Derives an UAM-specific key using SHA256.
///
/// Uses `SHA256("cloud-node-uam-v3:" + secret)` to produce a scoped key,
/// separating UAM key space from WAF / other subsystems. UAM uses a
/// different key prefix so a WAF-challenge pass cookie cannot satisfy
/// a UAM challenge, and vice versa.
pub fn uam_hmac_key(secret: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"cloud-node-uam-v3:");
    h.update(secret);
    h.finalize().to_vec()
}

/// Deterministically selects a challenge mode based on the token seed.
///
/// Returns 0 -> slider, 1 -> captcha, 2 -> click.
/// Same `token_seed` always returns the same mode (no true randomness).
pub fn random_challenge_mode(secret: &[u8], token_seed: u64) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(b"geetest-mode:");
    hasher.update(token_seed.to_le_bytes());
    let digest = hasher.finalize();
    digest[0] % 3
}

fn cloud_challenge_css() -> &'static str {
    r#":root{color-scheme:light dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f6f8fb;color:#1f2937}.sl-card{width:min(92vw,430px);padding:36px 32px;border-radius:16px;background:#fff;border:1px solid #e5e7eb;box-shadow:0 18px 50px rgba(15,23,42,.12);text-align:center}.sl-logo{display:inline-flex;align-items:center;justify-content:center;height:34px;padding:0 14px;border-radius:999px;background:#16a34a;color:#fff;font-weight:700;margin-bottom:22px}h1{margin:0 0 12px;font-size:24px;font-weight:700}p{margin:0 0 24px;color:#667085;line-height:1.6}.sl-progress,.sl-track{height:44px;border-radius:999px;background:#eef2f7;overflow:hidden;position:relative}.sl-progress span{display:block;width:38%;height:100%;border-radius:999px;background:linear-gradient(90deg,#22c55e,#0ea5e9);animation:slPulse 1.25s ease-in-out infinite}.sl-track{touch-action:none;cursor:pointer;border:1px solid #d8dee8}.sl-fill{position:absolute;inset:0 auto 0 0;width:0;background:linear-gradient(90deg,#22c55e,#0ea5e9);border-radius:999px}.sl-handle{position:absolute;top:3px;left:3px;width:38px;height:38px;border-radius:50%;display:grid;place-items:center;background:#fff;color:#16a34a;font-weight:800;box-shadow:0 4px 14px rgba(15,23,42,.2);user-select:none}.sl-status{margin-top:14px;font-size:14px;color:#667085}.sl-meta{margin-top:18px;font-size:12px;color:#98a2b3}.sl-error{color:#dc2626}@keyframes slPulse{0%,100%{transform:translateX(-22%)}50%{transform:translateX(180%)}}@media (prefers-color-scheme:dark){body{background:#111827;color:#f9fafb}.sl-card{background:#182230;border-color:#263244}.sl-progress,.sl-track{background:#263244}p,.sl-status{color:#aeb8c7}.sl-meta{color:#667085}}"#
}

fn pow_progress_css() -> &'static str {
    r#"#slPowBar{width:3%;animation:none;position:relative;overflow:hidden;transition:width .22s linear}#slPowBar:after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.42),transparent);transform:translateX(-100%);animation:slPowShine 1.1s linear infinite}#slPowStatus{min-height:40px;display:flex;align-items:center;justify-content:center;font-variant-numeric:tabular-nums;line-height:1.35}@keyframes slPowShine{to{transform:translateX(100%)}}"#
}

fn cloud_slider_html(ctx: &UamIssueCtx) -> String {
    let token_js = serde_json::to_string(ctx.token).unwrap_or_else(|_| "\"\"".to_string());
    let ret_js = serde_json::to_string(ctx.return_path).unwrap_or_else(|_| "\"/\"".to_string());
    let route_js = serde_json::to_string(ctx.verify_route).unwrap_or_else(|_| "\"/\"".to_string());
    let prefix_js = serde_json::to_string(&"0".repeat(ctx.pow_difficulty.clamp(5, 8) as usize))
        .unwrap_or_else(|_| "\"0000\"".to_string());
    let target = ctx.slider_target.min(260);
    let body = format!(
        r#"<main class="sl-card"><div class="sl-logo">${{product.name}}</div><h1 data-i18n="title">Security verification</h1><p data-i18n="slide_prompt">Slide to complete the browser check.</p><div id="slTrack" class="sl-track" data-i18n-aria-label="slide_prompt" aria-label="Slide to verify"><div id="slFill" class="sl-fill"></div><div id="slHandle" class="sl-handle">&rsaquo;</div></div><div id="slStatus" class="sl-status" data-i18n="slide_status">Slide the handle to the highlighted zone</div><div class="sl-meta">Request ${{requestId}}</div><noscript><p class="sl-error" data-i18n="no_js">JavaScript is required for this verification.</p></noscript></main><script>(function(){{function msg(k){{return window.cloudNodeText?window.cloudNodeText(k):({{slide_retry:"Not quite there, please try again",verifying_browser:"Verifying browser...",verify_failed:"Verification failed, please retry"}}[k]||k)}}const token={token_js};const ret={ret_js};const route={route_js};const target={target};const prefix={prefix_js};const track=document.getElementById('slTrack');const handle=document.getElementById('slHandle');const fill=document.getElementById('slFill');const status=document.getElementById('slStatus');const zone=document.createElement('div');zone.style.cssText='position:absolute;top:4px;height:36px;width:28px;border-radius:999px;background:rgba(34,197,94,.25);box-shadow:0 0 0 1px rgba(34,197,94,.38) inset;left:'+(target+9)+'px';';track.appendChild(zone);const enc=new TextEncoder();let dragging=false,startX=0,current=0,start=Date.now(),trace=[];async function pow(){{let n=0;while(true){{const h=await crypto.subtle.digest('SHA-256',enc.encode(token+n));const x=Array.from(new Uint8Array(h)).map(b=>b.toString(16).padStart(2,'0')).join('');if(x.startsWith(prefix))return String(n);n++;if(n%200===0)await new Promise(r=>setTimeout(r,0));}}}}function setX(x){{current=Math.max(0,Math.min(260,x));handle.style.left=(current+3)+'px';fill.style.width=(current+42)+'px';trace.push(Math.round(current)+','+(Date.now()-start));}}track.addEventListener('pointerdown',e=>{{dragging=true;startX=e.clientX-current;track.setPointerCapture(e.pointerId);}});track.addEventListener('pointermove',e=>{{if(dragging)setX(e.clientX-startX);}});track.addEventListener('pointerup',async e=>{{if(!dragging)return;dragging=false;setX(e.clientX-startX);if(Math.abs(current-target)>16){{status.textContent=msg('slide_retry');status.className='sl-status sl-error';return;}}status.textContent=msg('verifying_browser');try{{const nonce=await pow();const qs=new URLSearchParams({{__waf_token:token,__waf_pow:nonce,__waf_elapsed:String(Date.now()-start),__waf_x:String(Math.round(current)),__waf_trace:trace.slice(-80).join(';'),__waf_return:ret,__waf_uam:'1'}});location.href=route+'?'+qs.toString();}}catch(_){{status.textContent=msg('verify_failed');status.className='sl-status sl-error';}}}});}})();</script>"#
    );
    format!(
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Security Verification</title><style>{}</style><script>{}</script></head><body>{}</body></html>",
        cloud_challenge_css(),
        crate::pages::browser_i18n_script(),
        body
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue_ctx() -> UamIssueCtx<'static> {
        UamIssueCtx {
            token: "uam-token",
            challenge_life_seconds: 60,
            pow_difficulty: 5,
            verify_route: "/.well-known/cloud-node/waf-verify",
            return_path: "/",
            slider_target: 120,
        }
    }

    #[test]
    fn challenge_brand_uses_product_name_template_variable() {
        let ctx = issue_ctx();
        let js_cookie = JsCookieChallenge.issue_html(&ctx);
        let pow = PowChallenge.issue_html(&ctx);
        let slider = cloud_slider_html(&ctx);

        assert!(js_cookie.contains("${product.name}"));
        assert!(pow.contains("${product.name}"));
        assert!(slider.contains("${product.name}"));
        assert!(!js_cookie.contains(">Cloud</div>"));
        assert!(!pow.contains(">Cloud</div>"));
        assert!(!slider.contains(">Cloud</div>"));
    }
}
