use crate::pages::challenges::{encode_challenge_token, is_token_expired, random_suffix};
use crate::pages::lang::Lang;
use rand::Rng;

/// Canvas click challenge — two colour groups.
/// The target group (e.g. red) must be clicked in numbered order while
/// decoy characters (grey) are scattered as distractors.  Simple OCR
/// alone cannot distinguish which group is the target because the
/// instruction text tells the user which colour to follow.
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

    let pool: Vec<char> = match lang {
        Lang::ZhCn => "天地玄黄宇宙洪荒日月盈昃辰宿列张寒来暑往秋收冬藏"
            .chars()
            .collect(),
        Lang::En => "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect(),
    };

    // Pick 5 target chars + 5 decoy chars (all unique)
    let mut chosen: Vec<char> = Vec::with_capacity(10);
    let mut used = std::collections::HashSet::new();
    while chosen.len() < 10 {
        let c = pool[rng.r#gen_range(0..pool.len())];
        if used.insert(c) {
            chosen.push(c);
        }
    }
    let targets: Vec<char> = chosen[..5].to_vec();
    let decoys: Vec<char> = chosen[5..].to_vec();

    let mut target_order: Vec<usize> = (0..5).collect();
    for i in (1..5).rev() {
        target_order.swap(i, rng.r#gen_range(0..=i));
    }

    // Scatter all 10 positions with minimum spacing
    let positions: Vec<(u32, u32)> = {
        let mut pos = Vec::with_capacity(10);
        for _ in 0..10 {
            loop {
                let x = rng.r#gen_range(30u32..390u32);
                let y = rng.r#gen_range(40u32..220u32);
                if pos.iter().all(|(px, py)| {
                    let dx = *px as i32 - x as i32;
                    let dy = *py as i32 - y as i32;
                    dx * dx + dy * dy > 2500
                }) {
                    pos.push((x, y));
                    break;
                }
            }
        }
        pos
    };

    let pl = serde_json::json!({
        "t": "click",
        "p": {"to": target_order, "ch": targets},
        "e": expiry,
        "n": hex::encode(rand::random::<u64>().to_be_bytes()),
    });
    let enc_token = encode_challenge_token(&pl, secret);

    let targets_json: String = {
        let items: Vec<String> = targets.iter().map(|c| format!("\"{}\"", c)).collect();
        format!("[{}]", items.join(","))
    };
    let decoys_json: String = {
        let items: Vec<String> = decoys.iter().map(|c| format!("\"{}\"", c)).collect();
        format!("[{}]", items.join(","))
    };
    let pos_json: String = {
        let items: Vec<String> = positions
            .iter()
            .map(|(x, y)| format!("[{},{}]", x, y))
            .collect();
        format!("[{}]", items.join(","))
    };
    let order_json: String = {
        let items: Vec<String> = target_order.iter().map(|i| i.to_string()).collect();
        format!("[{}]", items.join(","))
    };

    let (instr, hint) = match lang {
        Lang::ZhCn => ("请按序号点击红色字符", "忽略灰色字符，只点红色"),
        Lang::En => (
            "Click the RED characters in numbered order",
            "Ignore grey — click only red",
        ),
    };

    format!(
        r#"<div id="clk_{sfx}">
<p data-i18n="click_instr" style="margin:0 0 6px;font-size:14px;color:var(--muted)">{instr}</p>
<p data-i18n="click_hint" style="margin:0 0 6px;font-size:11px;color:var(--dim)">{hint}</p>
<canvas id="cv_{sfx}" width="420" height="260" style="display:block;width:100%;max-width:420px;height:auto;margin:0 auto 10px;border-radius:14px;border:1px solid var(--card-border);cursor:crosshair;touch-action:none"></canvas>
<p class="status" id="st_{sfx}" style="font-size:14px">&#160;</p>
<div id="bf_{sfx}" style="display:none"></div>
<script>
(function(){{
var msg=function(k){{return window.cloudNodeText?window.cloudNodeText(k):({{click_done:"All correct"}}[k]||k)}};
var sf="{sfx}",tgts={targets_json},dcy={decoys_json},order={order_json},pos={pos_json};
var clicked=Array(5).fill(!1),next=0,lastClick=0,t0=Date.now();
var cv=document.getElementById('cv_'+sf),st=document.getElementById('st_'+sf),bf=document.getElementById('bf_'+sf);
var ctx=cv.getContext('2d'),w=420,h=260;
function draw(){{
 ctx.fillStyle='#e8ebf2';ctx.fillRect(0,0,w,h);
 // Grid
 ctx.strokeStyle='rgba(0,0,0,.04)';ctx.lineWidth=.5;
 for(var x=0;x<w;x+=10){{ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,h);ctx.stroke()}}
 for(var y=0;y<h;y+=10){{ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke()}}
 // Random blobs
 for(var i=0;i<14;i++){{ctx.fillStyle='rgba(0,0,0,'+(.02+Math.random()*.04)+')';ctx.beginPath();ctx.arc(Math.random()*w,Math.random()*h,3+Math.random()*18,0,Math.PI*2);ctx.fill()}}
 // Confetti
 var clrs=['#6366f1','#38bdf8','#22c55e','#f97316'];
 for(var i=0;i<20;i++){{ctx.fillStyle=clrs[i%4];ctx.globalAlpha=.05+Math.random()*.05;ctx.fillRect(Math.random()*w,Math.random()*h,2+Math.random()*3,2+Math.random()*3)}}
 ctx.globalAlpha=1;
 for(var i=0;i<4;i++){{ctx.strokeStyle='rgba(0,0,0,'+(.06+Math.random()*.08)+')';ctx.lineWidth=1+Math.random()*2;ctx.beginPath();ctx.moveTo(0,Math.random()*h);ctx.bezierCurveTo(w*.3,Math.random()*h,w*.6,Math.random()*h,w,Math.random()*h);ctx.stroke()}}
 // Decoys first (grey) — positions 5..9
 for(var i=0;i<5;i++){{
  var p=pos[5+i],x=p[0],y=p[1];
  ctx.save();ctx.translate(x,y);
  ctx.rotate((Math.random()-.5)*.4);
  ctx.fillStyle='#9ca3af';ctx.globalAlpha=.5+Math.random()*.2;
  ctx.font='bold 32px "Noto Sans SC","PingFang SC",sans-serif';
  ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(dcy[i],0,0);
  ctx.globalAlpha=1;ctx.restore();
 }}
 // Targets (red) — positions 0..4
 for(var i=0;i<5;i++){{
  var idx=order[i],p=pos[idx],x=p[0],y=p[1];
  ctx.save();ctx.translate(x,y);
  ctx.rotate((Math.random()-.5)*.5);
  ctx.strokeStyle='rgba(0,0,0,.2)';ctx.lineWidth=4;
  ctx.font='bold 36px "Noto Sans SC","PingFang SC",sans-serif';
  ctx.textAlign='center';ctx.textBaseline='middle';ctx.strokeText(tgts[idx],0,0);
  ctx.fillStyle='#dc2626';ctx.globalAlpha=.8+Math.random()*.2;
  ctx.fillText(tgts[idx],0,0);
  ctx.globalAlpha=.1;ctx.fillText(tgts[idx],-1.5+Math.random()*2,-1.5+Math.random()*2);
  ctx.globalAlpha=1;
  // Number badge
  ctx.beginPath();ctx.arc(-22,-18,13,0,Math.PI*2);
  ctx.fillStyle='#dc2626';ctx.fill();ctx.fillStyle='#fff';
  ctx.font='bold 11px sans-serif';ctx.fillText(i+1,-22,-17);
  ctx.restore();
 }}
}}
draw();
cv.addEventListener('click',function(e){{
 var t=Date.now();if(t-lastClick<400)return;lastClick=t;
 var rect=cv.getBoundingClientRect();
 var mx=(e.clientX-rect.left)*w/rect.width,my=(e.clientY-rect.top)*h/rect.height;
 var best=-1,bd=1e9;
 for(var i=0;i<5;i++){{ // only check targets (indices 0-4)
  var p=pos[i],dx=mx-p[0],dy=my-p[1],d=dx*dx+dy*dy;
  if(d<1225&&d<bd){{bd=d;best=i}}
 }}
 if(best<0||clicked[best])return;
 if(order[next]===best){{
  clicked[best]=!0;next++;
  ctx.fillStyle='rgba(34,197,94,.35)';
  ctx.beginPath();ctx.arc(pos[best][0],pos[best][1],22,0,Math.PI*2);ctx.fill();
  ctx.fillStyle='#fff';ctx.font='bold 14px sans-serif';ctx.textAlign='center';ctx.textBaseline='middle';
  ctx.fillText('✓',pos[best][0],pos[best][1]);
  if(next===5){{
   st.textContent='✓ '+msg('click_done');st.style.color='var(--green)';
   var el=Date.now()-t0;
   var f=document.createElement('form');f.method='GET';f.action='{route}';
   f.innerHTML='<input type="hidden" name="__waf_token" value="{wtok}"><input type="hidden" name="__waf_challenge_token" value="{tok}"><input type="hidden" name="__waf_challenge_type" value="click"><input type="hidden" name="__waf_click_seq" value=""><input type="hidden" name="__waf_elapsed" value="'+el+'"><input type="hidden" name="__waf_return" value="{rp}">';
   f.querySelector('[name=__waf_click_seq]').value=order.join(',');
   bf.appendChild(f);f.submit();
  }}
 }}else{{
  st.textContent='✗';st.style.color='var(--red)';
  setTimeout(function(){{st.textContent='';st.style.color=''}},600);
 }}
}});
}})();
</script>
</div>"#,
        sfx = sfx,
        targets_json = targets_json,
        decoys_json = decoys_json,
        order_json = order_json,
        pos_json = pos_json,
        instr = instr,
        hint = hint,
        route = verify_route,
        rp = return_path,
        wtok = waf_token,
        tok = enc_token,
    )
}

pub fn verify(token: &str, sequence: &[usize], elapsed_ms: u64, secret: &[u8]) -> bool {
    let payload = match crate::pages::challenges::decode_challenge_token(token, secret) {
        Some(p) => p,
        None => return false,
    };
    if is_token_expired(&payload) {
        return false;
    }
    let p = match payload.get("p").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return false,
    };
    let target: Vec<usize> = match p.get("to").and_then(|v| v.as_array()) {
        Some(a) => a
            .iter()
            .filter_map(|v| v.as_u64().map(|x| x as usize))
            .collect(),
        None => return false,
    };
    if target.len() != 5 || sequence.len() != 5 {
        return false;
    }
    if elapsed_ms < 2000 {
        return false;
    }
    sequence == target
}
