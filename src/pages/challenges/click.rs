use crate::pages::challenges::{encode_challenge_token, is_token_expired, random_suffix};
use crate::pages::lang::Lang;
use rand::RngExt;

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

    let pool: Vec<char> = match lang {
        Lang::ZhCn => {
            "天地玄黄宇宙洪荒日月盈昃辰宿列张寒来暑往秋收冬藏金木水火土山川风云雷电雨雪霜"
                .chars()
                .collect()
        }
        Lang::En => "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect(),
    };

    let mut chosen: Vec<char> = Vec::with_capacity(10);
    let mut used = std::collections::HashSet::new();
    while chosen.len() < 10 {
        let c = pool[rng.random_range(0..pool.len())];
        if used.insert(c) {
            chosen.push(c);
        }
    }
    let targets: Vec<char> = chosen[..5].to_vec();
    let decoys: Vec<char> = chosen[5..].to_vec();

    let mut target_order: Vec<usize> = (0..5).collect();
    for i in (1..5).rev() {
        target_order.swap(i, rng.random_range(0..=i));
    }

    // Positions — 10 slots, minimum spacing 57px
    let positions: Vec<(u32, u32)> = {
        let mut pos = Vec::with_capacity(10);
        for _ in 0..10 {
            loop {
                let x = rng.random_range(34u32..386u32);
                let y = rng.random_range(44u32..216u32);
                if pos.iter().all(|(px, py): &(u32, u32)| {
                    let dx = *px as i32 - x as i32;
                    let dy = *py as i32 - y as i32;
                    dx * dx + dy * dy > 3200
                }) {
                    pos.push((x, y));
                    break;
                }
            }
        }
        pos
    };

    // Per-target: color + font (randomised per render)
    let font_templates = [
        "bold {s}px \"Noto Sans SC\",\"PingFang SC\",sans-serif",
        "bold italic {s}px \"Microsoft YaHei\",\"Hiragino Sans GB\",sans-serif",
        "{s}px \"STHeiti\",\"SimHei\",sans-serif",
        "900 {s}px \"Noto Serif SC\",\"SimSun\",serif",
    ];
    let red_variants = ["#dc2626", "#e11d48", "#c2410c", "#b91c1c", "#be123c"];

    let target_colors: Vec<&str> = (0..5)
        .map(|_| red_variants[rng.random_range(0..red_variants.len())])
        .collect();
    let target_fonts: Vec<String> = (0..5)
        .map(|_| {
            font_templates[rng.random_range(0..font_templates.len())]
                .replace("{s}", &rng.random_range(32u32..44).to_string())
        })
        .collect();
    let decoy_fonts: Vec<String> = (0..5)
        .map(|_| {
            font_templates[rng.random_range(0..font_templates.len())]
                .replace("{s}", &rng.random_range(18u32..36).to_string())
        })
        .collect();
    let decoy_ops: Vec<f64> = (0..5)
        .map(|_| rng.random_range(28u32..60) as f64 / 100.0)
        .collect();
    let decoy_flip: Vec<bool> = (0..5).map(|_| rng.random_bool(0.3)).collect();

    // Ghost chars — faint tiny misleading chars scattered across canvas
    let ghost_pool: Vec<char> = if matches!(lang, Lang::ZhCn) {
        "的了是在不这个有人来到时大地为中你说生国年就那和要出得里后以会家可过去能对小多然心学都好看发当没成只事把还用样道想作开总从情面最女现前同日手行意动方头长儿回位分爱"
            .chars()
            .collect()
    } else {
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".chars().collect()
    };
    let ghost_chars: Vec<char> = (0..7)
        .map(|_| ghost_pool[rng.random_range(0..ghost_pool.len())])
        .collect();
    let ghost_x: Vec<u32> = (0..7).map(|_| rng.random_range(10u32..410)).collect();
    let ghost_y: Vec<u32> = (0..7).map(|_| rng.random_range(10u32..250)).collect();
    let ghost_sz: Vec<u32> = (0..7).map(|_| rng.random_range(9u32..20)).collect();

    // Serialise to JS literals
    let js_char_arr = |v: &[char]| {
        format!(
            "[{}]",
            v.iter()
                .map(|c| format!("\"{}\"", c))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let js_str_arr = |v: &[String]| {
        format!(
            "[{}]",
            v.iter()
                .map(|s| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string()))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let js_u32_arr = |v: &[u32]| {
        format!(
            "[{}]",
            v.iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let js_f64_arr = |v: &[f64]| {
        format!(
            "[{}]",
            v.iter()
                .map(|n| format!("{:.2}", n))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let js_bool_arr = |v: &[bool]| {
        format!(
            "[{}]",
            v.iter()
                .map(|b| if *b { "true" } else { "false" })
                .collect::<Vec<_>>()
                .join(",")
        )
    };

    let targets_json = js_char_arr(&targets);
    let decoys_json = js_char_arr(&decoys);
    let pos_json = format!(
        "[{}]",
        positions
            .iter()
            .map(|(x, y)| format!("[{},{}]", x, y))
            .collect::<Vec<_>>()
            .join(",")
    );
    let order_json = format!(
        "[{}]",
        target_order
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    let tcolors_js = format!(
        "[{}]",
        target_colors
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(",")
    );
    let tfonts_js = js_str_arr(&target_fonts);
    let dfonts_js = js_str_arr(&decoy_fonts);
    let dops_js = js_f64_arr(&decoy_ops);
    let dflip_js = js_bool_arr(&decoy_flip);
    let ghost_json = js_char_arr(&ghost_chars);
    let ghost_x_json = js_u32_arr(&ghost_x);
    let ghost_y_json = js_u32_arr(&ghost_y);
    let ghost_sz_json = js_u32_arr(&ghost_sz);

    let pl = serde_json::json!({
        "t": "click",
        "p": {"to": target_order, "ch": targets},
        "e": expiry,
        "n": hex::encode(rand::random::<u64>().to_be_bytes()),
    });
    let enc_token = encode_challenge_token(&pl, secret);

    let (instr, hint) = match lang {
        Lang::ZhCn => ("请按序号点击红色字符", "忽略灰色字符，只点红色"),
        Lang::En => (
            "Click the RED characters in numbered order",
            "Ignore grey — click only red",
        ),
    };
    let rp_js = serde_json::to_string(return_path).unwrap_or_else(|_| "\"/\"".to_string());

    format!(
        r#"<div id="clk_{sfx}" style="text-align:center">
<p data-i18n="click_instr" style="margin:0 0 5px;font-size:14px;font-weight:600;color:var(--text)">{instr}</p>
<p data-i18n="click_hint" style="margin:0 0 10px;font-size:11px;color:var(--dim)">{hint}</p>
<div style="display:inline-block;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.22);overflow:hidden">
<canvas id="cv_{sfx}" width="420" height="260" style="display:block;width:100%;max-width:420px;height:auto;cursor:crosshair;touch-action:none"></canvas>
</div>
<p class="status" id="st_{sfx}" style="margin-top:10px;font-size:14px;min-height:20px">&#160;</p>
<script>
(function(){{
var msg=function(k){{return window.cloudNodeText?window.cloudNodeText(k):({{click_done:"All correct",click_wrong:"Wrong order",click_verifying:"Verifying..."}}[k]||k)}};
var sf="{sfx}",tgts={targets_json},dcy={decoys_json},order={order_json},pos={pos_json};
var tclr={tcolors_js},tfnt={tfonts_js},dfnt={dfonts_js},dop={dops_js},dflp={dflip_js};
var gh={ghost_json},ghx={ghost_x_json},ghy={ghost_y_json},ghs={ghost_sz_json};
var clicked=Array(5).fill(!1),next=0,lastClick=0,t0=Date.now();
var cv=document.getElementById('cv_'+sf),st=document.getElementById('st_'+sf);
var ctx=cv.getContext('2d'),w=420,h=260;
function draw(){{
 // Evening sky
 var gd=ctx.createLinearGradient(0,0,0,h);
 gd.addColorStop(0,'#1a237e');gd.addColorStop(.38,'#7b1fa2');gd.addColorStop(.65,'#e65100');gd.addColorStop(1,'#3e2723');
 ctx.fillStyle=gd;ctx.fillRect(0,0,w,h);
 // Stars
 for(var i=0;i<55;i++){{ctx.fillStyle='rgba(255,255,255,'+(.4+Math.random()*.6)+')';ctx.beginPath();ctx.arc(Math.random()*w,Math.random()*h*.58,.3+Math.random()*.9,0,Math.PI*2);ctx.fill()}}
 // Moon + shadow
 ctx.fillStyle='rgba(255,248,200,.94)';ctx.beginPath();ctx.arc(w*.82,h*.14,20,0,Math.PI*2);ctx.fill();
 ctx.fillStyle='rgba(90,50,10,.22)';ctx.beginPath();ctx.arc(w*.82+8,h*.14-5,15,0,Math.PI*2);ctx.fill();
 // Mountain silhouette
 ctx.fillStyle='rgba(30,15,50,.75)';ctx.beginPath();
 ctx.moveTo(0,h*.72);ctx.lineTo(55,h*.41);ctx.lineTo(120,h*.62);ctx.lineTo(195,h*.36);ctx.lineTo(275,h*.58);ctx.lineTo(355,h*.34);ctx.lineTo(w,h*.56);ctx.lineTo(w,h);ctx.lineTo(0,h);ctx.fill();
 // Ground
 var fg=ctx.createLinearGradient(0,h*.74,0,h);fg.addColorStop(0,'#1b5e20');fg.addColorStop(1,'#0a2e0d');
 ctx.fillStyle=fg;ctx.fillRect(0,h*.74,w,h*.26);
 // Light beams
 for(var i=0;i<3;i++){{ctx.save();ctx.globalAlpha=.03+Math.random()*.03;var bx=w*(.18+i*.32);var br=ctx.createRadialGradient(bx,0,0,bx,h,h);br.addColorStop(0,'rgba(255,220,100,.9)');br.addColorStop(1,'transparent');ctx.fillStyle=br;ctx.beginPath();ctx.moveTo(bx-25,0);ctx.lineTo(bx-75,h);ctx.lineTo(bx+75,h);ctx.lineTo(bx+25,0);ctx.fill();ctx.restore()}}
 // Ghost trap chars — faint, tiny
 for(var i=0;i<gh.length;i++){{ctx.save();ctx.translate(ghx[i],ghy[i]);ctx.rotate((Math.random()-.5)*.6);ctx.fillStyle='rgba(255,255,255,'+(.06+Math.random()*.09)+')';ctx.font='italic '+ghs[i]+'px sans-serif';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText(gh[i],0,0);ctx.restore()}}
 // Decoys — grey, varied fonts/sizes, some mirrored
 for(var i=0;i<dcy.length;i++){{ctx.save();ctx.translate(pos[5+i][0],pos[5+i][1]);ctx.rotate((Math.random()-.5)*.55);if(dflp[i])ctx.scale(-1,1);ctx.font=dfnt[i];ctx.textAlign='center';ctx.textBaseline='middle';ctx.shadowColor='rgba(0,0,0,.4)';ctx.shadowBlur=2;ctx.fillStyle='rgba(170,170,190,'+dop[i]+')';ctx.fillText(dcy[i],0,0);if(i%2===0){{ctx.strokeStyle='rgba(130,130,150,'+dop[i]*.35+')';ctx.lineWidth=.7;ctx.strokeText(dcy[i],0,0)}}ctx.shadowBlur=0;ctx.restore()}}
 // Targets — vivid, multi-layer, numbered badge
 for(var i=0;i<5;i++){{var idx=order[i],px=pos[idx][0],py=pos[idx][1];ctx.save();ctx.translate(px,py);ctx.rotate((Math.random()-.5)*.32);ctx.font=tfnt[idx];ctx.textAlign='center';ctx.textBaseline='middle';
  ctx.shadowColor=tclr[idx];ctx.shadowBlur=16;
  ctx.strokeStyle='rgba(0,0,0,.6)';ctx.lineWidth=5;ctx.strokeText(tgts[idx],0,0);
  ctx.fillStyle=tclr[idx];ctx.globalAlpha=.9+Math.random()*.1;ctx.fillText(tgts[idx],0,0);
  ctx.globalAlpha=.15;ctx.fillStyle='#fff';ctx.fillText(tgts[idx],-1,-2);
  ctx.globalAlpha=1;ctx.shadowBlur=0;
  // Badge
  ctx.shadowColor='rgba(0,0,0,.7)';ctx.shadowBlur=9;ctx.shadowOffsetY=2;
  var bg=ctx.createRadialGradient(-24,-22,0,-24,-20,14);bg.addColorStop(0,'#ff6b6b');bg.addColorStop(1,tclr[idx]);
  ctx.beginPath();ctx.arc(-24,-20,14,0,Math.PI*2);ctx.fillStyle=bg;ctx.fill();
  ctx.shadowBlur=0;ctx.shadowOffsetY=0;
  ctx.strokeStyle='rgba(255,255,255,.55)';ctx.lineWidth=1.5;ctx.stroke();
  ctx.fillStyle='#fff';ctx.font='bold 11px sans-serif';ctx.fillText(i+1,-24,-19);
  ctx.restore()}}
}}
draw();
cv.addEventListener('click',function(e){{
 var t=Date.now();if(t-lastClick<380)return;lastClick=t;
 var rect=cv.getBoundingClientRect(),mx=(e.clientX-rect.left)*w/rect.width,my=(e.clientY-rect.top)*h/rect.height;
 var best=-1,bd=1e9;
 for(var i=0;i<5;i++){{var p=pos[i],dx=mx-p[0],dy=my-p[1],d=dx*dx+dy*dy;if(d<1600&&d<bd){{bd=d;best=i}}}}
 if(best<0||clicked[best])return;
 if(order[next]===best){{
  clicked[best]=!0;next++;
  var rg=ctx.createRadialGradient(pos[best][0],pos[best][1],0,pos[best][0],pos[best][1],28);rg.addColorStop(0,'rgba(34,197,94,.75)');rg.addColorStop(1,'rgba(34,197,94,0)');ctx.fillStyle=rg;ctx.beginPath();ctx.arc(pos[best][0],pos[best][1],28,0,Math.PI*2);ctx.fill();
  ctx.fillStyle='rgba(255,255,255,.92)';ctx.font='bold 16px sans-serif';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('✓',pos[best][0],pos[best][1]);
  cv.style.transition='filter .12s';cv.style.filter='drop-shadow(0 0 8px rgba(34,197,94,.8))';
  setTimeout(function(){{cv.style.filter='';cv.style.transition=''}},240);
  if(next===5){{
   st.textContent=msg('click_verifying');st.style.color='var(--muted)';
   var el=Date.now()-t0;
   var url='{route}?__waf_token={wtok}&__waf_challenge_token={tok}&__waf_challenge_type=click&__waf_click_seq='+order.join(',')+'&__waf_elapsed='+el+'&__waf_return='+encodeURIComponent({rp_js});
   fetch(url,{{redirect:'manual'}}).then(function(r){{if(r.type==='opaqueredirect'||r.ok||(r.status>=300&&r.status<400))location.href=url;else{{st.textContent='✗';st.style.color='var(--red)'}}}}). catch(function(){{location.href=url}});
  }}
 }}else{{
  ctx.save();ctx.globalAlpha=.28;var rr=ctx.createRadialGradient(mx,my,0,mx,my,32);rr.addColorStop(0,'rgba(220,38,38,.9)');rr.addColorStop(1,'rgba(220,38,38,0)');ctx.fillStyle=rr;ctx.beginPath();ctx.arc(mx,my,32,0,Math.PI*2);ctx.fill();ctx.restore();
  st.textContent=msg('click_wrong');st.style.color='var(--red)';
  cv.style.transition='transform .08s';cv.style.transform='translateX(7px)';
  setTimeout(function(){{cv.style.transform='translateX(-6px)'}},80);
  setTimeout(function(){{cv.style.transform='translateX(3px)'}},160);
  setTimeout(function(){{cv.style.transform='';cv.style.transition='';st.textContent='';st.style.color=''}},260);
 }}
}});
cv.addEventListener('touchend',function(e){{e.preventDefault();var t=e.changedTouches[0];cv.dispatchEvent(new MouseEvent('click',{{clientX:t.clientX,clientY:t.clientY,bubbles:!0}}))}},{{passive:!1}});
}})();
</script>
</div>"#,
        sfx = sfx,
        targets_json = targets_json,
        decoys_json = decoys_json,
        order_json = order_json,
        pos_json = pos_json,
        tcolors_js = tcolors_js,
        tfonts_js = tfonts_js,
        dfonts_js = dfonts_js,
        dops_js = dops_js,
        dflip_js = dflip_js,
        ghost_json = ghost_json,
        ghost_x_json = ghost_x_json,
        ghost_y_json = ghost_y_json,
        ghost_sz_json = ghost_sz_json,
        instr = instr,
        hint = hint,
        route = verify_route,
        rp_js = rp_js,
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
    if target.len() != 5 || sequence.len() != 5 || elapsed_ms < 2000 {
        return false;
    }
    sequence == target
}
