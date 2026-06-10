use crate::pages::Lang;
use crate::pages::challenges::encode_challenge_token;
use rand::Rng;
use serde_json::json;

const PIECE_SIZE: f64 = 40.0;
const PIECE_HALF: f64 = PIECE_SIZE / 2.0;

pub fn issue_html(
    lang: Lang,
    waf_token: &str,
    verify_route: &str,
    return_path: &str,
    target_anchor: u32,
    secret: &[u8],
    expiry: u64,
) -> String {
    let tx = (target_anchor % 260) as f64;
    let ty = (target_anchor.wrapping_mul(17) % 160) as f64;
    issue_html_with_target(
        lang,
        waf_token,
        verify_route,
        return_path,
        tx,
        ty,
        secret,
        expiry,
    )
}

pub fn issue_html_with_target(
    lang: Lang,
    waf_token: &str,
    verify_route: &str,
    return_path: &str,
    target_x: f64,
    target_y: f64,
    secret: &[u8],
    expiry: u64,
) -> String {
    let sfx = random_js_id();
    let mut rng = rand::thread_rng();

    let off_x = (target_x + rng.gen_range(80.0f64..180.0)).clamp(0.0, 280.0);
    let off_y = (target_y + rng.gen_range(-40.0f64..40.0)).clamp(0.0, 160.0);
    let polygon = generate_puzzle_polygon(&mut rng);
    let target_center_x = target_x + PIECE_HALF;
    let target_center_y = target_y + PIECE_HALF;
    let challenge_token =
        encode_slider_challenge_token(target_center_x, target_center_y, secret, expiry);

    let prompt = match lang {
        Lang::ZhCn => "拖动拼图块到缺口位置",
        Lang::En => "Drag the puzzle piece to the gap",
    };
    let rp_js = serde_json::to_string(return_path).unwrap_or_else(|_| "\"/\"".to_string());
    let route_js = serde_json::to_string(verify_route).unwrap_or_else(|_| "\"/\"".to_string());

    format!(
        r#"<div class="pzl" id="pzl_{sfx}">
<div class="pzl-bg" style="position:relative;width:320px;height:200px;margin:0 auto 14px;border-radius:12px;overflow:hidden">
<canvas id="bg_{sfx}" width="320" height="200" style="display:block;width:320px;height:200px"></canvas>
<div id="hl_{sfx}" class="pzl-hole" style="position:absolute;left:{tx:.0}px;top:{ty:.0}px;width:40px;height:40px;clip-path:{poly};background:rgba(0,0,0,.22);box-shadow:inset 0 0 0 2px rgba(0,0,0,.35),0 0 12px rgba(0,0,0,.25);pointer-events:none;border-radius:2px"></div>
<div id="pc_{sfx}" class="pzl-piece" style="position:absolute;left:{ox:.0}px;top:{oy:.0}px;width:40px;height:40px;clip-path:{poly};background:linear-gradient(135deg,rgba(99,102,241,.85),rgba(56,189,248,.85));cursor:grab;border-radius:2px;z-index:2;box-shadow:0 4px 12px rgba(0,0,0,.3)"></div>
</div>
<p class="status" id="st_{sfx}" data-i18n="slider_puzzle_prompt">{prompt}</p>
<script>
(function(){{
var sf="{sfx}";var d=!1,sx=0,sy=0,px={ox:.0},py={oy:.0},tr=[],t0=Date.now();
var pc=document.getElementById('pc_'+sf),bg=document.getElementById('bg_'+sf),st=document.getElementById('st_'+sf);
function dr(){{
var c=bg.getContext('2d'),w=320,h=200;
var g=c.createLinearGradient(0,0,0,h*.65);g.addColorStop(0,'#5b9bd5');g.addColorStop(1,'#c8e6f5');
c.fillStyle=g;c.fillRect(0,0,w,h*.65);
c.fillStyle='#5a8a3c';c.fillRect(0,h*.65,w,h*.35);
c.fillStyle='#4a7a2c';
c.beginPath();c.moveTo(0,h*.75);c.bezierCurveTo(60,h*.5,120,h*.55,180,h*.7);c.bezierCurveTo(230,h*.6,280,h*.65,w,h*.7);c.lineTo(w,h);c.lineTo(0,h);c.fill();
c.fillStyle='#FFD700';c.beginPath();c.arc(w*.82,h*.18,16,0,Math.PI*2);c.fill();
function cloud(cx,cy){{c.fillStyle='rgba(255,255,255,.82)';[[-12,0,14],[0,-4,18],[12,0,14]].forEach(function(p){{c.beginPath();c.arc(cx+p[0],cy+p[1],p[2]/2,0,Math.PI*2);c.fill()}})}}
cloud(70,38);cloud(190,28);cloud(260,45);
for(var i=0;i<30;i++){{c.fillStyle='rgba(255,255,255,'+(.03+Math.random()*.05)+')';c.fillRect(Math.random()*w,Math.random()*h,1+Math.random()*3,1+Math.random()*3)}}
}}
function ds(e){{d=!0;var p=e.touches?e.touches[0]:e;sx=p.clientX;sy=p.clientY;px=parseFloat(pc.style.left)||px;py=parseFloat(pc.style.top)||py;pc.style.cursor='grabbing'}}
function dm(e){{if(!d)return;e.preventDefault();var p=e.touches?e.touches[0]:e,nx=Math.max(0,Math.min(280,px+p.clientX-sx)),ny=Math.max(0,Math.min(160,py+p.clientY-sy));pc.style.left=nx+'px';pc.style.top=ny+'px';
var cx=nx+{half:.1},cy=ny+{half:.1},dist=Math.sqrt(Math.pow(cx-{tcx:.1},2)+Math.pow(cy-{tcy:.1},2));
var hl=document.getElementById('hl_'+sf);
if(dist<30){{hl.style.boxShadow='inset 0 0 0 2px rgba(0,0,0,.35),0 0 18px 8px rgba(99,102,241,.75)';if(dist<15&&st)st.textContent=window.cloudNodeText?window.cloudNodeText('slider_near'):'Almost there!'}}
else{{hl.style.boxShadow='inset 0 0 0 2px rgba(0,0,0,.35),0 0 12px rgba(0,0,0,.25)'}}
}}
(function cp(){{if(d){{var l=parseFloat(pc.style.left)||px,t=parseFloat(pc.style.top)||py;tr.push(Math.round(l)+','+Math.round(t))}}setTimeout(cp,20+40*Math.random())}})();
function de(e){{
    if(!d)return;d=!1;pc.style.cursor='grab';
    var el=Date.now()-t0,l=parseFloat(pc.style.left)||px,t=parseFloat(pc.style.top)||py;
    var cx=l+{half:.1},cy=t+{half:.1};
    var q='__waf_token={wtok}&__waf_challenge_token={ctok}&__waf_challenge_type=slider&__waf_x='+cx.toFixed(1)+'&__waf_y='+cy.toFixed(1)+'&x='+l.toFixed(1)+'&y='+t.toFixed(1)+'&__waf_elapsed='+el+'&__waf_trace='+encodeURIComponent(tr.join(';'))+'&__waf_return='+encodeURIComponent({rp_js});
    if(st)st.textContent=window.cloudNodeText?window.cloudNodeText('slider_verifying'):'Verifying...';
    pc.style.pointerEvents='none';
    fetch({route_js}+'?'+q,{{redirect:'manual'}}).then(function(r){{
  if(r.type==='opaqueredirect'||r.ok){{
    pc.style.transition='left .18s ease,top .18s ease';
    pc.style.left='{tx:.0}px';pc.style.top='{ty:.0}px';
    setTimeout(function(){{location.href={route_js}+'?'+q}},200);
  }}else{{
    if(st)st.textContent=window.cloudNodeText?window.cloudNodeText('slider_retry'):'Please try again';
    pc.style.left={ox:.0}+'px';pc.style.top={oy:.0}+'px';
    px={ox:.0};py={oy:.0};pc.style.pointerEvents='';pc.style.transition='';
    tr=[];t0=Date.now();
    document.getElementById('hl_'+sf).style.boxShadow='inset 0 0 0 2px rgba(0,0,0,.35),0 0 12px rgba(0,0,0,.25)';
  }}
}}).catch(function(){{location.href={route_js}+'?'+q}});
}}
dr();
pc.addEventListener('mousedown',ds);document.addEventListener('mousemove',dm);document.addEventListener('mouseup',de);
pc.addEventListener('touchstart',ds,{{passive:!0}});document.addEventListener('touchmove',dm,{{passive:!1}});document.addEventListener('touchend',de);
}})();
</script>
</div>"#,
        sfx = sfx,
        tx = target_x,
        ty = target_y,
        tcx = target_center_x,
        tcy = target_center_y,
        half = PIECE_HALF,
        ox = off_x,
        oy = off_y,
        poly = polygon,
        prompt = prompt,
        wtok = waf_token,
        ctok = challenge_token,
        rp_js = rp_js,
        route_js = route_js,
    )
}

// ── Verification ─────────────────────────────────────────────────

const TOLERANCE: f64 = 6.0;
const MIN_ELAPSED_MS: u64 = 1200;

fn encode_slider_challenge_token(
    target_center_x: f64,
    target_center_y: f64,
    secret: &[u8],
    expiry: u64,
) -> String {
    let payload = json!({
        "t": "slider",
        "p": {
            "cx": target_center_x,
            "cy": target_center_y,
        },
        "e": expiry,
        "n": hex::encode(rand::random::<u64>().to_be_bytes()),
    });
    encode_challenge_token(&payload, secret)
}

pub fn verify_anchor(
    target_anchor: u32,
    user_x: f64,
    user_y: f64,
    elapsed_ms: u64,
    trace: &str,
) -> bool {
    let tx = (target_anchor % 260) as f64;
    let ty = (target_anchor.wrapping_mul(17) % 160) as f64;
    (user_x - tx).abs() <= TOLERANCE
        && (user_y - ty).abs() <= TOLERANCE
        && elapsed_ms >= MIN_ELAPSED_MS
        && verify_trace(trace)
}

pub fn verify_explicit(
    token: &str,
    user_x: f64,
    user_y: f64,
    elapsed_ms: u64,
    trace: &str,
    secret: &[u8],
) -> bool {
    let payload = match crate::pages::challenges::decode_challenge_token(token, secret) {
        Some(p) => p,
        None => return false,
    };
    if crate::pages::challenges::is_token_expired(&payload) {
        return false;
    }
    if payload.get("t").and_then(|v| v.as_str()) != Some("slider") {
        return false;
    }
    let p = match payload.get("p").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return false,
    };
    let (cx, cy) = match (
        p.get("cx").and_then(|v| v.as_f64()),
        p.get("cy").and_then(|v| v.as_f64()),
    ) {
        (Some(x), Some(y)) => (x, y),
        _ => return false,
    };
    (user_x - cx).abs() <= TOLERANCE
        && (user_y - cy).abs() <= TOLERANCE
        && elapsed_ms >= MIN_ELAPSED_MS
        && verify_trace(trace)
}

// ── Helpers ──────────────────────────────────────────────────────

fn random_js_id() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..8)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

fn generate_puzzle_polygon(rng: &mut impl Rng) -> String {
    let tab_side: u8 = rng.gen_range(0..4u8);
    let notch_side: u8 = (tab_side + 2) % 4;
    let tab_pos: f64 = rng.gen_range(35.0f64..65.0);
    let tab_r: f64 = rng.gen_range(20.0f64..28.0);

    // (x%, y%) for a point on `edge` at `along`% with `perp`% outward offset
    let edge_pt = |edge: u8, along: f64, perp: f64| -> (f64, f64) {
        match edge {
            0 => (along, -perp),
            1 => (100.0 + perp, along),
            2 => (100.0 - along, 100.0 + perp),
            _ => (-perp, 100.0 - along),
        }
    };

    let mut pts: Vec<String> = Vec::new();
    let bump_start = tab_pos - tab_r;
    let bump_end = tab_pos + tab_r;

    for edge in 0u8..4 {
        if edge == 0 {
            let (x, y) = edge_pt(0, 0.0, 0.0);
            pts.push(format!(
                "{:.1}% {:.1}%",
                x.clamp(0.0, 100.0),
                y.clamp(0.0, 100.0)
            ));
        }

        if edge == tab_side || edge == notch_side {
            let sign: f64 = if edge == tab_side { 1.0 } else { -1.0 };
            let (x, y) = edge_pt(edge, bump_start, 0.0);
            pts.push(format!(
                "{:.1}% {:.1}%",
                x.clamp(0.0, 100.0),
                y.clamp(0.0, 100.0)
            ));
            for i in 0..=4usize {
                let a = std::f64::consts::PI * i as f64 / 4.0;
                let (x, y) = edge_pt(edge, tab_pos + tab_r * a.cos(), sign * tab_r * a.sin());
                pts.push(format!(
                    "{:.1}% {:.1}%",
                    x.clamp(0.0, 100.0),
                    y.clamp(0.0, 100.0)
                ));
            }
            let (x, y) = edge_pt(edge, bump_end, 0.0);
            pts.push(format!(
                "{:.1}% {:.1}%",
                x.clamp(0.0, 100.0),
                y.clamp(0.0, 100.0)
            ));
        }

        let (x, y) = edge_pt(edge, 100.0, 0.0);
        pts.push(format!(
            "{:.1}% {:.1}%",
            x.clamp(0.0, 100.0),
            y.clamp(0.0, 100.0)
        ));
    }
    format!("polygon({})", pts.join(","))
}

fn verify_trace(trace: &str) -> bool {
    let points: Vec<(f64, f64)> = trace
        .split(';')
        .filter_map(|s| {
            let mut p = s.split(',');
            let x = p.next()?.parse().ok()?;
            let y = p.next()?.parse().ok()?;
            Some((x, y))
        })
        .collect();
    if points.len() < 8 {
        return false;
    }
    let (x1, y1) = points[0];
    let (x2, y2) = points[points.len() - 1];
    let dx = x2 - x1;
    let dy = y2 - y1;
    let line_len = (dx * dx + dy * dy).sqrt();
    if line_len < 10.0 {
        return false;
    }
    // Velocity variation: ≥2 adjacent segment pairs where speed differs >15%
    let dists: Vec<f64> = points
        .windows(2)
        .map(|w| {
            let ddx = w[1].0 - w[0].0;
            let ddy = w[1].1 - w[0].1;
            (ddx * ddx + ddy * ddy).sqrt()
        })
        .collect();
    let vel_var = dists
        .windows(2)
        .filter(|w| {
            let lg = w[0].max(w[1]);
            let sm = w[0].min(w[1]);
            lg > 0.1 && (lg - sm) / lg > 0.15
        })
        .count();
    if vel_var < 2 {
        return false;
    }
    // At least one micro-correction (small x reversal <8px — human tremor)
    let has_micro = points.windows(3).any(|w| {
        let dx1 = w[1].0 - w[0].0;
        let dx2 = w[2].0 - w[1].0;
        dx1 * dx2 < 0.0 && dx2.abs() < 8.0
    });
    if !has_micro {
        return false;
    }
    // Non-straight line
    let max_dev = points
        .iter()
        .map(|(x, y)| ((x - x1) * dy - (y - y1) * dx).abs() / line_len)
        .fold(0.0f64, f64::max);
    max_dev > 2.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn future_expiry() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60
    }

    fn valid_trace() -> &'static str {
        "0,0;20,2;45,9;43,12;70,20;100,18;125,25;130,31"
    }

    #[test]
    fn explicit_slider_token_verifies_signed_center_coordinates() {
        let secret = b"slider-secret";
        let token = encode_slider_challenge_token(150.0, 51.0, secret, future_expiry());

        assert!(verify_explicit(
            &token,
            150.0,
            51.0,
            MIN_ELAPSED_MS,
            valid_trace(),
            secret,
        ));
        assert!(!verify_explicit(
            &token,
            123.0,
            111.0,
            MIN_ELAPSED_MS,
            valid_trace(),
            secret,
        ));
    }

    #[test]
    fn explicit_slider_token_rejects_wrong_type() {
        let secret = b"slider-secret";
        let token = crate::pages::challenges::encode_challenge_token(
            &json!({
                "t": "captcha",
                "p": {"cx": 150.0, "cy": 51.0},
                "e": future_expiry(),
            }),
            secret,
        );

        assert!(!verify_explicit(
            &token,
            150.0,
            51.0,
            MIN_ELAPSED_MS,
            valid_trace(),
            secret,
        ));
    }
}
