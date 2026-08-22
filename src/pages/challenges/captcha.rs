use crate::pages::challenges::{encode_challenge_token, is_token_expired, random_suffix};
use crate::pages::lang::Lang;
use rand::RngExt;
use serde_json::json;
use sha2::{Digest, Sha256};

pub fn issue_html(
    lang: Lang,
    waf_token: &str,
    verify_route: &str,
    return_path: &str,
    secret: &[u8],
    expiry: u64,
) -> String {
    let sfx = random_suffix();
    let mut rng = rand::rng();

    const ALPHANUM: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let captcha_text: String = (0..6)
        .map(|_| ALPHANUM[rng.random_range(0..ALPHANUM.len())] as char)
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
    let rp_js = serde_json::to_string(return_path).unwrap_or_else(|_| "\"/\"".to_string());

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
#ci_{sfx}:focus{{border-color:#6366f1;animation:capFocus .9s ease-in-out infinite}}
#cb_{sfx}:hover{{opacity:.9}}#cb_{sfx}:disabled{{opacity:.6;cursor:default}}
</style>
<script>
(function(){{
var msg=function(k){{return window.cloudNodeText?window.cloudNodeText(k):({{captcha_wrong:"Incorrect, please try again",captcha_verifying:"Verifying...",captcha_refreshed:"New code generated"}}[k]||k)}};
var sf="{sfx}",chars={cjson},canvas=document.getElementById('ca_'+sf);
var input=document.getElementById('ci_'+sf),btn=document.getElementById('cb_'+sf),st=document.getElementById('cs_'+sf);
function renderCaptcha(c,can){{
 var w=310,h=110,ctx=can.getContext('2d');
 var bgClrs=['#f0f1f5','#eef0f4','#f2f3f7','#eceef3','#f1f2f6','#edf0f5'];
 for(var r=0;r<h;r+=11){{ctx.fillStyle=bgClrs[Math.floor(Math.random()*bgClrs.length)];ctx.fillRect(0,r,w,11+Math.random()*3)}}
 for(var x=6;x<w;x+=6)for(var y=6;y<h;y+=6){{ctx.fillStyle='rgba(0,0,0,'+(.03+Math.random()*.04)+')';ctx.beginPath();ctx.arc(x+(Math.random()-.5)*3,y+(Math.random()-.5)*3,.6+Math.random()*.8,0,Math.PI*2);ctx.fill()}}
 for(var i=0;i<20;i++){{ctx.fillStyle='rgba(0,0,0,'+(.02+Math.random()*.04)+')';ctx.beginPath();ctx.arc(Math.random()*w,Math.random()*h,1+Math.random()*5,0,Math.PI*2);ctx.fill()}}
 var palettes=[['#0f172a','#1e293b'],['#7f1d1d','#991b1b'],['#1e3a5f','#1e40af'],['#4c1d95','#6d28d9'],['#064e3b','#065f46'],['#78350f','#92400e']];
 var dcyList="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
 for(var di=0;di<8;di++){{ctx.save();var dch=dcyList[Math.floor(Math.random()*dcyList.length)],dcx=15+Math.random()*270,dcy=15+Math.random()*80;ctx.translate(dcx,dcy);ctx.rotate((Math.random()-.5)*.6);ctx.fillStyle="rgba(156,163,175,"+(.18+Math.random()*.12)+")";ctx.font=(11+Math.random()*5).toFixed(0)+"px sans-serif";ctx.textAlign="center";ctx.textBaseline="middle";ctx.fillText(dch,0,0);ctx.restore()}}
 for(var i=0;i<c.length;i++){{ctx.save();var cx=22+i*45+(Math.random()-.5)*6,cy=55+(Math.random()-.5)*18;ctx.translate(cx,cy);ctx.rotate((Math.random()-.5)*.8);var fs=22+Math.random()*16;ctx.strokeStyle='rgba(0,0,0,'+(.12+Math.random()*.1)+')';ctx.lineWidth=2.5+Math.random()*3;ctx.font='bold '+fs.toFixed(0)+'px "Noto Sans SC","PingFang SC","Microsoft YaHei",sans-serif';ctx.textAlign='center';ctx.textBaseline='middle';ctx.strokeText(c[i],0,0);var pal=palettes[i];ctx.fillStyle=pal[Math.floor(Math.random()*pal.length)];ctx.globalAlpha=.7+Math.random()*.3;ctx.fillText(c[i],0,0);ctx.globalAlpha=.1+Math.random()*.08;ctx.fillText(c[i],-2+Math.random()*3,-2+Math.random()*3);ctx.globalAlpha=1;ctx.restore()}}
 for(var i=0;i<7;i++){{ctx.strokeStyle='rgba('+[Math.floor(Math.random()*100),Math.floor(Math.random()*100),Math.floor(Math.random()*100)].join(',')+','+(.06+Math.random()*.08)+')';ctx.lineWidth=1.2+Math.random()*2.2;ctx.beginPath();ctx.moveTo(0,Math.random()*h);ctx.bezierCurveTo(w*.25,Math.random()*h,w*.5,Math.random()*h,w*.75,Math.random()*h);ctx.bezierCurveTo(w*.85,Math.random()*h,w*.95,Math.random()*h,w,Math.random()*h);ctx.stroke()}}
 for(var i=0;i<4;i++){{ctx.strokeStyle='rgba(0,0,0,'+(.04+Math.random()*.05)+')';ctx.lineWidth=1+Math.random();ctx.beginPath();ctx.moveTo(40+i*70,0);for(var y=0;y<h;y+=8)ctx.lineTo(40+i*70+Math.sin(y*.08)*8,y);ctx.stroke()}}
 for(var i=0;i<100;i++){{ctx.fillStyle='rgba(0,0,0,'+(.06+Math.random()*.1)+')';ctx.fillRect(Math.random()*w,Math.random()*h,1+Math.random()*3,1+Math.random()*3)}}
 ctx.strokeStyle='rgba(0,0,0,.025)';ctx.lineWidth=.5;for(var i=0;i<w+h;i+=12){{ctx.beginPath();ctx.moveTo(i,0);ctx.lineTo(i-h,h);ctx.stroke()}}
}}
renderCaptcha(chars,canvas);
canvas.onclick=function(){{renderCaptcha(chars,canvas)}};
input.addEventListener('input',function(){{
 input.value=input.value.toUpperCase().replace(/[^A-Z2-9]/g,'');
 var rem=6-input.value.length;
 if(rem>0&&rem<6){{st.textContent=rem+(window.__cloudNodeLang==='zh'?' 个字符':' more');st.style.color='var(--dim)'}}
 else{{st.textContent='';st.style.color=''}}
}});
input.addEventListener('keydown',function(e){{if(e.key==='Enter')btn.click()}});
btn.onclick=function(){{
 btn.disabled=!0;
 var val=input.value.trim().toUpperCase().replace(/\s+/g,'');
 crypto.subtle.digest('SHA-256',new TextEncoder().encode(val)).then(function(buf){{
  var h=Array.from(new Uint8Array(buf)).map(function(b){{return b.toString(16).padStart(2,'0')}}).join('');
  var url='{route}?__waf_token={wtok}&__waf_challenge_token={tok}&__waf_challenge_type=captcha&__waf_captcha_hash='+h+'&__waf_return='+encodeURIComponent({rp_js});
  st.textContent=msg('captcha_verifying');st.style.color='var(--muted)';
  fetch(url,{{redirect:'manual'}}).then(function(r){{
   if(r.type==='opaqueredirect'||r.ok||(r.status>=300&&r.status<400)){{location.href=url;}}
   else{{
    st.textContent=msg('captcha_wrong');st.style.color='var(--red)';
    input.value='';input.focus();
    renderCaptcha(chars,canvas);
    btn.disabled=!1;
   }}
  }}).catch(function(){{location.href=url;}});
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
        rp_js = rp_js,
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
