use crate::pages::challenges::{encode_challenge_token, is_token_expired, random_suffix};
use crate::pages::lang::Lang;
use rand::Rng;
use serde_json::json;
use sha2::{Digest, Sha256};

/// Generate a server-side captcha with maximum anti-OCR rendering.
/// Every character uses an independently random colour, font size, rotation,
/// stroke style, and ghost offset.  The answer is never sent in plaintext.
pub fn issue_html(
    lang: Lang,
    waf_token: &str,
    verify_route: &str,
    return_path: &str,
    secret: &[u8],
    expiry: u64,
) -> String {
    let sfx = random_suffix();
    let mut rng = rand::thread_rng();

    const ALPHANUM: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let captcha_text: String = (0..6)
        .map(|_| ALPHANUM[rng.r#gen_range(0..ALPHANUM.len())] as char)
        .collect();
    let answer_hash = hex::encode(Sha256::digest(captcha_text.as_bytes()));

    let pl = json!({
        "t": "captcha",
        "p": {"ah": answer_hash},
        "e": expiry,
        "n": hex::encode(rand::random::<u64>().to_be_bytes()),
    });
    let enc_token = encode_challenge_token(&pl, secret);

    let chars_json_str: String = {
        let items: Vec<String> = captcha_text.chars().map(|c| format!("\"{}\"", c)).collect();
        format!("[{}]", items.join(","))
    };

    let (prompt, ph, btn, refresh, hint) = match lang {
        Lang::ZhCn => (
            "请输入黑色字符（忽略灰色小字）",
            "输入验证码",
            "验证",
            "点击刷新",
            "只输入黑色大字，灰色小字是干扰项",
        ),
        Lang::En => (
            "Enter the BLACK characters (ignore grey)",
            "Enter code",
            "Verify",
            "Click to refresh",
            "Only enter the black characters — grey are decoys",
        ),
    };

    format!(
        r#"<div class="cp" id="cp_{sfx}">
<p data-i18n="captcha_prompt" style="margin:0 0 6px;font-size:14px;color:var(--muted)">{prompt}</p>
<p data-i18n="captcha_hint" style="margin:0 0 8px;font-size:11px;color:var(--dim)">{hint}</p>
<div style="margin:0 auto 12px;display:flex;justify-content:center">
<canvas id="ca_{sfx}" width="310" height="110" style="width:290px;height:103px;border-radius:10px;border:1px solid var(--card-border);cursor:pointer" data-i18n-title="captcha_refresh" title="{refresh}"></canvas>
</div>
<div style="display:flex;gap:8px;justify-content:center;margin-bottom:10px">
<input id="ci_{sfx}" type="text" autocomplete="off" autocorrect="off" spellcheck="false" maxlength="6" style="width:150px;padding:10px 14px;border-radius:10px;border:2px solid var(--card-border);background:var(--card-bg);color:var(--text);font-size:20px;font-family:ui-monospace,'SF Mono',monospace;letter-spacing:5px;text-align:center;outline:none" data-i18n-placeholder="captcha_placeholder" placeholder="{ph}">
<button id="cb_{sfx}" data-i18n="captcha_btn" style="padding:10px 22px;border-radius:10px;border:none;background:linear-gradient(135deg,#6366f1,#38bdf8);color:#fff;font-size:15px;font-weight:600;cursor:pointer">{btn}</button>
</div>
<p class="status" id="cs_{sfx}" style="font-size:13px">&#160;</p>
<style>
#ci_{sfx}:focus{{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.2)}}
#cb_{sfx}:hover{{opacity:.9}}#cb_{sfx}:disabled{{opacity:.6;cursor:default}}
</style>
<script>
(function(){{
var sf="{sfx}",chars={cjson},canvas=document.getElementById('ca_'+sf);
var input=document.getElementById('ci_'+sf),btn=document.getElementById('cb_'+sf),st=document.getElementById('cs_'+sf);
function renderCaptcha(c,can){{
 var w=310,h=110,ctx=can.getContext('2d');
 // Chaotic background — horizontal colour bands + noise
 var bgClrs=['#f0f1f5','#eef0f4','#f2f3f7','#eceef3','#f1f2f6','#edf0f5'];
 for(var r=0;r<h;r+=11){{
  ctx.fillStyle=bgClrs[Math.floor(Math.random()*bgClrs.length)];
  ctx.fillRect(0,r,w,11+Math.random()*3);
 }}
 // Dense dot grid
 for(var x=6;x<w;x+=6)for(var y=6;y<h;y+=6){{
  ctx.fillStyle='rgba(0,0,0,'+(.03+Math.random()*.04)+')';
  ctx.beginPath();ctx.arc(x+(Math.random()-.5)*3,y+(Math.random()-.5)*3,.6+Math.random()*.8,0,Math.PI*2);ctx.fill();
 }}
 // Random filled circles
 for(var i=0;i<20;i++){{
  ctx.fillStyle='rgba(0,0,0,'+(.02+Math.random()*.04)+')';
  ctx.beginPath();ctx.arc(Math.random()*w,Math.random()*h,1+Math.random()*5,0,Math.PI*2);ctx.fill();
 }}
 // ── Six different colour palettes, one per character ──
 // ── Rotate colour scheme each render ──
 var palettes=[
  ['#0f172a','#1e293b'],['#7f1d1d','#991b1b'],['#1e3a5f','#1e40af'],
  ['#4c1d95','#6d28d9'],['#064e3b','#065f46'],['#78350f','#92400e']
 ];
 // ── Decoy characters — small, grey, scattered randomly ──────
 var dcyList="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
 for(var di=0;di<8;di++){{
  ctx.save();
  var dch=dcyList[Math.floor(Math.random()*dcyList.length)];
  var dcx=15+Math.random()*270,dcy=15+Math.random()*80;
  ctx.translate(dcx,dcy);ctx.rotate((Math.random()-.5)*.6);
  ctx.fillStyle="rgba(156,163,175,"+(.18+Math.random()*.12)+")";
  ctx.font=(11+Math.random()*5).toFixed(0)+"px sans-serif";
  ctx.textAlign="center";ctx.textBaseline="middle";
  ctx.fillText(dch,0,0);ctx.restore();
 }}
 // Per-character distortion: random horizontal sine-wave warp on each character
 for(var i=0;i<c.length;i++){{
  ctx.save();
  var cx=22+i*45+(Math.random()-.5)*6,cy=55+(Math.random()-.5)*18;
  ctx.translate(cx,cy);
  ctx.rotate((Math.random()-.5)*.8); // ±22deg
  var fs=22+Math.random()*16; // 22-38px
  // Stroke — thick, random colour
  ctx.strokeStyle='rgba(0,0,0,'+(.12+Math.random()*.1)+')';ctx.lineWidth=2.5+Math.random()*3;
  ctx.font='bold '+fs.toFixed(0)+'px "Noto Sans SC","PingFang SC","Microsoft YaHei",sans-serif';
  ctx.textAlign='center';ctx.textBaseline='middle';
  ctx.strokeText(c[i],0,0);
  // Fill — from this char's palette
  var pal=palettes[i];ctx.fillStyle=pal[Math.floor(Math.random()*pal.length)];
  ctx.globalAlpha=.7+Math.random()*.3;
  ctx.fillText(c[i],0,0);
  // Deliberate ghost copy — slightly offset, lighter
  ctx.globalAlpha=.1+Math.random()*.08;
  ctx.fillText(c[i],-2+Math.random()*3,-2+Math.random()*3);
  ctx.globalAlpha=1;
  ctx.restore();
 }}
 // ── Heavy interference layer ──
 // Thick Bezier curves
 for(var i=0;i<7;i++){{
  ctx.strokeStyle='rgba('+[Math.floor(Math.random()*100),Math.floor(Math.random()*100),Math.floor(Math.random()*100)].join(',')+','+(.06+Math.random()*.08)+')';
  ctx.lineWidth=1.2+Math.random()*2.2;
  ctx.beginPath();ctx.moveTo(0,Math.random()*h);
  ctx.bezierCurveTo(w*.25,Math.random()*h,w*.5,Math.random()*h,w*.75,Math.random()*h);
  ctx.bezierCurveTo(w*.85,Math.random()*h,w*.95,Math.random()*h,w,Math.random()*h);
  ctx.stroke();
 }}
 // Vertical squiggles
 for(var i=0;i<4;i++){{
  ctx.strokeStyle='rgba(0,0,0,'+(.04+Math.random()*.05)+')';ctx.lineWidth=1+Math.random();
  ctx.beginPath();ctx.moveTo(40+i*70,0);
  for(var y=0;y<h;y+=8)ctx.lineTo(40+i*70+Math.sin(y*.08)*8,y);
  ctx.stroke();
 }}
 // Heavy noise dots
 for(var i=0;i<100;i++){{
  ctx.fillStyle='rgba(0,0,0,'+(.06+Math.random()*.1)+')';
  ctx.fillRect(Math.random()*w,Math.random()*h,1+Math.random()*3,1+Math.random()*3);
 }}
 // Diagonal lines
 ctx.strokeStyle='rgba(0,0,0,.025)';ctx.lineWidth=.5;
 for(var i=0;i<w+h;i+=12){{ctx.beginPath();ctx.moveTo(i,0);ctx.lineTo(i-h,h);ctx.stroke()}}
}}
renderCaptcha(chars,canvas);
canvas.onclick=function(){{renderCaptcha(chars,canvas)}};
btn.onclick=function(){{
 btn.disabled=!0;
 var val=input.value.trim().toUpperCase().replace(/\s+/g,'');
 crypto.subtle.digest('SHA-256',new TextEncoder().encode(val)).then(function(hashBuffer){{
  var h=Array.from(new Uint8Array(hashBuffer)).map(b=>b.toString(16).padStart(2,'0')).join('');
	  var f=document.createElement('form');f.method='GET';f.action='{route}';
	  f.innerHTML='<input type="hidden" name="__waf_token" value="{wtok}"><input type="hidden" name="__waf_challenge_token" value="{tok}"><input type="hidden" name="__waf_challenge_type" value="captcha"><input type="hidden" name="__waf_captcha_hash" value="'+h+'"><input type="hidden" name="__waf_return" value="{rp}">';
  document.body.appendChild(f);f.submit();
 }}).catch(function(){{btn.disabled=!1}});
}};
}})();
</script>
</div>"#,
        sfx = sfx,
        prompt = prompt,
        hint = hint,
        ph = ph,
        btn = btn,
        refresh = refresh,
        route = verify_route,
        rp = return_path,
        wtok = waf_token,
        tok = enc_token,
        cjson = chars_json_str,
    )
}

pub fn verify(token: &str, answer_hash: &str, secret: &[u8]) -> bool {
    let payload = match crate::pages::challenges::decode_challenge_token(token, secret) {
        Some(p) => p,
        None => return false,
    };
    if is_token_expired(&payload) {
        return false;
    }
    let stored = match payload
        .get("p")
        .and_then(|v| v.get("ah"))
        .and_then(|v| v.as_str())
    {
        Some(s) => s,
        None => return false,
    };
    stored.len() == 64 && answer_hash.len() == 64 && stored == answer_hash
}
