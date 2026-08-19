use crate::pages::challenges::{
    decode_challenge_token, encode_challenge_token, is_token_expired, random_suffix,
};
use crate::pages::lang::Lang;
use base64::{Engine as _, engine::general_purpose};
use rand::RngExt;
use serde_json::json;
use sha2::{Digest, Sha256};

const MIN_DELAY_MS: u64 = 3_000;
const MAX_DELAY_MS: u64 = 120_000;
const TEMP_COOKIE_MAX_AGE: u64 = 90;

pub fn issue_html(
    lang: Lang,
    waf_token: &str,
    verify_route: &str,
    return_path: &str,
    secret: &[u8],
    expiry: u64,
    secure_cookie: bool,
) -> String {
    let sfx = random_suffix();
    let seed = general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 18]>());
    let cookie_name = format!(
        "WAF-JS-{}",
        &hex_digest(&format!("{waf_token}|{seed}"))[..14]
    );
    let issued_ms = now_millis();
    let display_ms = rand::rng().random_range(3_000..=5_000);
    let token_hash = hex_digest(waf_token);

    let payload = json!({
        "t": "jscookie",
        "p": {
            "v": 1,
            "wth": token_hash,
            "cn": cookie_name,
            "s": seed,
            "i": issued_ms,
            "min": display_ms,
            "max": MAX_DELAY_MS,
        },
        "e": expiry,
        "n": general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 12]>()),
    });
    let challenge_token = encode_challenge_token(&payload, secret);

    let route_json = serde_json::to_string(verify_route).unwrap_or_else(|_| "\"/\"".to_string());
    let return_json = serde_json::to_string(return_path).unwrap_or_else(|_| "\"/\"".to_string());
    let waf_token_json = serde_json::to_string(waf_token).unwrap_or_else(|_| "\"\"".to_string());
    let challenge_token_json =
        serde_json::to_string(&challenge_token).unwrap_or_else(|_| "\"\"".to_string());
    let cookie_name_json =
        serde_json::to_string(&cookie_name).unwrap_or_else(|_| "\"WAF-JS\"".to_string());
    let seed_json = serde_json::to_string(&seed).unwrap_or_else(|_| "\"\"".to_string());
    let secure = if secure_cookie { "; Secure" } else { "" };

    let (heading, sub, runtime, cookie, fingerprint, submit, failed) = match lang {
        Lang::ZhCn => (
            "正在检查浏览器",
            "请稍候，正在验证 JavaScript、Cookie 与浏览器环境。",
            "JavaScript 运行时",
            "Cookie 回写",
            "浏览器环境",
            "提交校验",
            "浏览器校验失败，请刷新后重试。",
        ),
        Lang::En => (
            "Checking your browser",
            "Please wait while JavaScript, cookies, and browser signals are verified.",
            "JavaScript runtime",
            "Cookie roundtrip",
            "Browser signals",
            "Submitting check",
            "Browser verification failed. Please refresh and try again.",
        ),
    };
    let failed_json = serde_json::to_string(failed).unwrap_or_else(|_| {
        "\"Browser verification failed. Please refresh and try again.\"".to_string()
    });
    let display_seconds = ((display_ms as f64) / 1000.0 * 10.0).round() / 10.0;
    let display_seconds = if display_seconds.fract() == 0.0 {
        format!("{display_seconds:.0}")
    } else {
        format!("{display_seconds:.1}")
    };

    format!(
        r##"<div id="jsck_{sfx}" class="jsck">
<h1 data-i18n="js_heading">{heading}</h1>
<p data-i18n="js_sub">{sub}</p>
<div class="jsck-steps">
  <div id="jsck_s1_{sfx}" class="jsck-step"><span></span><b data-i18n="js_runtime">{runtime}</b></div>
  <div id="jsck_s2_{sfx}" class="jsck-step"><span></span><b data-i18n="js_cookie">{cookie}</b></div>
  <div id="jsck_s3_{sfx}" class="jsck-step"><span></span><b data-i18n="js_fingerprint">{fingerprint}</b></div>
  <div id="jsck_s4_{sfx}" class="jsck-step"><span></span><b data-i18n="js_submit">{submit}</b></div>
</div>
<p id="jsck_status_{sfx}" class="status" data-i18n="js_initializing">Initializing browser check...</p>
<div class="progress jsck-progress"><span id="jsck_bar_{sfx}"></span></div>
<p class="meta" data-i18n="js_min_display" data-i18n-args='{{"seconds":"{display_seconds}"}}'>Minimum display time: {display_seconds}s</p>
<div class="meta">Request #{sfx}</div>
<style>
#jsck_{sfx}.jsck{{text-align:left}}
#jsck_{sfx} h1,#jsck_{sfx} p{{text-align:center}}
#jsck_{sfx} .jsck-steps{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:20px 0 10px}}
#jsck_{sfx} .jsck-step{{min-height:46px;display:flex;align-items:center;gap:9px;border:1px solid var(--card-border);border-radius:10px;padding:10px 11px;color:var(--muted);font-size:13px;background:rgba(148,163,184,.08)}}
#jsck_{sfx} .jsck-step b{{font:inherit;font-weight:500}}
#jsck_{sfx} .jsck-step span{{width:10px;height:10px;border-radius:50%;background:var(--dim);box-shadow:0 0 0 0 rgba(14,165,233,.28)}}
#jsck_{sfx} .jsck-step.on span{{background:var(--blue);animation:jsckPulse_{sfx} 1s ease-in-out infinite}}
#jsck_{sfx} .jsck-step.ok span{{background:var(--green);animation:none}}
#jsck_status_{sfx}{{min-height:22px;text-align:center;font-variant-numeric:tabular-nums}}
#jsck_{sfx} .jsck-progress{{height:12px;margin:4px 0 10px}}
#jsck_bar_{sfx}{{width:3%;animation:none;transition:width .18s linear}}
@keyframes jsckPulse_{sfx}{{0%,100%{{box-shadow:0 0 0 0 rgba(14,165,233,.3)}}50%{{box-shadow:0 0 0 7px rgba(14,165,233,0)}}}}
@media(max-width:420px){{#jsck_{sfx} .jsck-steps{{grid-template-columns:1fr}}}}
</style>
<script>
(function(){{
function msg(k){{return window.cloudNodeText?window.cloudNodeText(k):({{js_check_runtime:"Checking JavaScript runtime...",js_check_cookie:"Checking cookie roundtrip...",js_collect:"Collecting browser signals...",js_submitting:"Submitting browser check...",js_failed:{failed_json}}}[k]||k)}}
var sf="{sfx}",wt={waf_token_json},ct={challenge_token_json},cn={cookie_name_json},seed={seed_json};
var route={route_json},ret={return_json},min={display_ms},max={MAX_DELAY_MS},secure="{secure}";
var enc=new TextEncoder(),t0=Date.now(),p0=(performance&&performance.now)?performance.now():0;
function el(id){{return document.getElementById(id+"_"+sf)}}
function step(n,cls){{var x=el("jsck_s"+n);if(!x)return;x.className="jsck-step "+cls;if(cls==="ok"){{var b=x.querySelector("b");if(b&&b.textContent.indexOf("✓")<0)b.textContent="✓ "+b.textContent}}}}
function status(s){{var x=el("jsck_status");if(x)x.textContent=s}}
function setBar(p){{var x=el("jsck_bar");if(x)x.style.width=Math.max(3,Math.min(100,p)).toFixed(1)+"%"}}
function sleep(ms){{return new Promise(function(r){{setTimeout(r,ms)}})}}
function hex(buf){{return Array.from(new Uint8Array(buf)).map(function(b){{return b.toString(16).padStart(2,"0")}}).join("")}}
function digest(s){{return crypto.subtle.digest("SHA-256",enc.encode(s)).then(hex)}}
function getCookie(name){{var parts=document.cookie?document.cookie.split("; "):[];for(var i=0;i<parts.length;i++){{var p=parts[i],j=p.indexOf("=");if(j>0&&p.slice(0,j)===name)return decodeURIComponent(p.slice(j+1))}}return ""}}
function storage(kind){{try{{var k="__waf_js_"+sf+"_"+kind,s=window[kind];s.setItem(k,seed);var ok=s.getItem(k)===seed;s.removeItem(k);return ok?"1":"0"}}catch(e){{return "0"}}}}
function canvasSignal(){{try{{var c=document.createElement("canvas"),x=c.getContext("2d");c.width=96;c.height=32;x.fillStyle="#123";x.fillRect(0,0,96,32);x.fillStyle="#fff";x.font="13px sans-serif";x.fillText(seed.slice(0,10),4,20);return c.toDataURL().slice(-96)}}catch(e){{return "na"}}}}
function webglSignal(){{try{{var c=document.createElement("canvas"),g=c.getContext("webgl")||c.getContext("experimental-webgl");if(!g)return "none";var e=g.getExtension("WEBGL_debug_renderer_info");return e?[g.getParameter(e.UNMASKED_VENDOR_WEBGL),g.getParameter(e.UNMASKED_RENDERER_WEBGL)].join("/"):"webgl"}}catch(e){{return "err"}}}}
function fp(){{var n=navigator||{{}},s=screen||{{}},tz="";try{{tz=Intl.DateTimeFormat().resolvedOptions().timeZone||""}}catch(e){{}}var ua=n.userAgentData?n.userAgentData.platform||"":"";return [
 "ce="+(n.cookieEnabled?"1":"0"),
 "wd="+(n.webdriver?"1":"0"),
 "lg="+(n.languages?n.languages.join(","):(n.language||"")),
 "pf="+(n.platform||ua||""),
 "hc="+(n.hardwareConcurrency||0),
 "dm="+(n.deviceMemory||0),
 "tz="+tz,
 "sc="+[s.width||0,s.height||0,s.colorDepth||0,window.devicePixelRatio||0].join("x"),
 "ls="+storage("localStorage"),
 "ss="+storage("sessionStorage"),
 "cv="+canvasSignal(),
 "gl="+webglSignal()
].join("|").slice(0,1200)}}
async function run(){{
 try{{
  var timer=setInterval(function(){{var e=((performance&&performance.now)?performance.now()-p0:Date.now()-t0);setBar(Math.min(96,3+e/min*93))}},120);
  step(1,"on");status(msg("js_check_runtime"));
  if(!crypto||!crypto.subtle||!window.TextEncoder)throw new Error("crypto");
  var cv=(await digest("waf-js-cookie|"+wt+"|"+seed)).slice(0,40);
  step(1,"ok");step(2,"on");status(msg("js_check_cookie"));
  document.cookie=cn+"="+encodeURIComponent(cv)+"; Path=/; Max-Age={TEMP_COOKIE_MAX_AGE}; SameSite=Lax"+secure;
  await sleep(80);
  if(getCookie(cn)!==cv)throw new Error("cookie");
  step(2,"ok");step(3,"on");status(msg("js_collect"));
  var signals=fp();
  if(signals.length<24)throw new Error("signals");
  step(3,"ok");
  var elapsed=Math.round(((performance&&performance.now)?performance.now()-p0:Date.now()-t0));
  if(elapsed<min)await sleep(min-elapsed);
  elapsed=Math.round(((performance&&performance.now)?performance.now()-p0:Date.now()-t0));
  if(elapsed>max)throw new Error("timeout");
  clearInterval(timer);setBar(100);
  step(4,"on");status((window.cloudNodeText?window.cloudNodeText('js_submitting'):"Submitting")+" ("+Math.round(elapsed/100)/10+"s)");
  var dg=await digest("waf-js-digest|"+wt+"|"+ct+"|"+cv+"|"+signals+"|"+elapsed+"|"+seed);
  var qs=new URLSearchParams({{__waf_token:wt,__waf_challenge_token:ct,__waf_challenge_type:"jscookie",__waf_js_elapsed:String(elapsed),__waf_js_fp:signals,__waf_js_digest:dg,__waf_return:ret}});
  step(4,"ok");location.replace(route+"?"+qs.toString());
 }}catch(e){{
  status(msg("js_failed"));
  var rl=document.createElement("a");rl.href="javascript:location.reload()";
  rl.style="display:block;margin-top:10px;font-size:13px;color:var(--blue);text-decoration:none;cursor:pointer";
  rl.textContent=window.cloudNodeText?window.cloudNodeText('slide_retry'):"Retry";
  var sb=el("jsck_status");if(sb&&sb.parentNode)sb.parentNode.insertBefore(rl,sb.nextSibling);
 }}
}}
run();
}})();
</script>
</div>"##,
        sfx = sfx,
        heading = heading,
        sub = sub,
        runtime = runtime,
        cookie = cookie,
        fingerprint = fingerprint,
        submit = submit,
        failed_json = failed_json,
        display_ms = display_ms,
        display_seconds = display_seconds,
        waf_token_json = waf_token_json,
        challenge_token_json = challenge_token_json,
        cookie_name_json = cookie_name_json,
        seed_json = seed_json,
        route_json = route_json,
        return_json = return_json,
        secure = secure,
    )
}

pub fn verify(
    challenge_token: &str,
    waf_token: &str,
    cookie_header: &str,
    elapsed_ms: u64,
    fingerprint: &str,
    digest: &str,
    secret: &[u8],
) -> Option<String> {
    if challenge_token.is_empty()
        || waf_token.is_empty()
        || fingerprint.len() < 24
        || fingerprint.len() > 1400
        || digest.len() != 64
    {
        return None;
    }

    let payload = decode_challenge_token(challenge_token, secret)?;
    if is_token_expired(&payload) {
        return None;
    }
    if payload.get("t").and_then(|v| v.as_str()) != Some("jscookie") {
        return None;
    }

    let p = payload.get("p").and_then(|v| v.as_object())?;
    if p.get("wth").and_then(|v| v.as_str())? != hex_digest(waf_token) {
        return None;
    }
    let cookie_name = p.get("cn").and_then(|v| v.as_str())?;
    if !valid_cookie_name(cookie_name) {
        return None;
    }
    let seed = p.get("s").and_then(|v| v.as_str())?;
    if seed.len() < 16 || seed.len() > 64 {
        return None;
    }
    let min_delay = p
        .get("min")
        .and_then(|v| v.as_u64())
        .unwrap_or(MIN_DELAY_MS)
        .clamp(100, 10_000);
    let max_delay = p
        .get("max")
        .and_then(|v| v.as_u64())
        .unwrap_or(MAX_DELAY_MS)
        .clamp(min_delay + 1, 300_000);
    let issued_ms = p.get("i").and_then(|v| v.as_u64()).unwrap_or(0);
    let now = now_millis();
    if issued_ms == 0
        || now.saturating_add(2_000) < issued_ms
        || now.saturating_sub(issued_ms) < min_delay
        || now.saturating_sub(issued_ms) > max_delay
        || elapsed_ms < min_delay
        || elapsed_ms > max_delay
    {
        return None;
    }

    let cookie_value = cookie_value(cookie_header, cookie_name)?;
    let expected_cookie = derive_cookie_value(waf_token, seed);
    if !constant_time_eq(cookie_value.as_bytes(), expected_cookie.as_bytes()) {
        return None;
    }

    let expected_digest = hex_digest(&format!(
        "waf-js-digest|{waf_token}|{challenge_token}|{expected_cookie}|{fingerprint}|{elapsed_ms}|{seed}"
    ));
    if !constant_time_eq(digest.as_bytes(), expected_digest.as_bytes()) {
        return None;
    }

    Some(cookie_name.to_string())
}

fn derive_cookie_value(waf_token: &str, seed: &str) -> String {
    hex_digest(&format!("waf-js-cookie|{waf_token}|{seed}"))[..40].to_string()
}

fn cookie_value<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    cookies.split(';').find_map(|part| {
        let part = part.trim();
        let (key, value) = part.split_once('=')?;
        (key == name).then_some(value)
    })
}

fn valid_cookie_name(name: &str) -> bool {
    (8..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn hex_digest(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_signed_js_cookie_roundtrip() {
        let secret = b"secret";
        let waf_token = "waf-token";
        let seed = "seed-value-for-test";
        let cookie_name = "WAF-JS-test";
        let issued_ms = now_millis().saturating_sub(800);
        let challenge_token = encode_challenge_token(
            &json!({
                "t": "jscookie",
                "p": {
                    "v": 1,
                    "wth": hex_digest(waf_token),
                    "cn": cookie_name,
                    "s": seed,
                    "i": issued_ms,
                    "min": 550,
                    "max": 120000,
                },
                "e": (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + 60),
                "n": "nonce",
            }),
            secret,
        );
        let cookie = derive_cookie_value(waf_token, seed);
        let fp = "ce=1|wd=0|lg=en|pf=test|hc=8|tz=UTC";
        let elapsed = 700;
        let digest = hex_digest(&format!(
            "waf-js-digest|{waf_token}|{challenge_token}|{cookie}|{fp}|{elapsed}|{seed}"
        ));
        let cookie_header = format!("{cookie_name}={cookie}");

        assert_eq!(
            verify(
                &challenge_token,
                waf_token,
                &cookie_header,
                elapsed,
                fp,
                &digest,
                secret,
            ),
            Some(cookie_name.to_string())
        );
    }

    #[test]
    fn rejects_missing_cookie_roundtrip() {
        let secret = b"secret";
        let waf_token = "waf-token";
        let seed = "seed-value-for-test";
        let cookie_name = "WAF-JS-test";
        let issued_ms = now_millis().saturating_sub(800);
        let challenge_token = encode_challenge_token(
            &json!({
                "t": "jscookie",
                "p": {
                    "v": 1,
                    "wth": hex_digest(waf_token),
                    "cn": cookie_name,
                    "s": seed,
                    "i": issued_ms,
                    "min": 550,
                    "max": 120000,
                },
                "e": (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + 60),
                "n": "nonce",
            }),
            secret,
        );
        let fp = "ce=1|wd=0|lg=en|pf=test|hc=8|tz=UTC";
        let elapsed = 700;
        let digest = hex_digest("wrong");

        assert_eq!(
            verify(
                &challenge_token,
                waf_token,
                "",
                elapsed,
                fp,
                &digest,
                secret
            ),
            None
        );
    }
}
