use crate::pages::Lang;
use rand::RngExt;

pub fn issue_html(
    lang: Lang,
    waf_token: &str,
    verify_route: &str,
    return_path: &str,
    target_anchor: u32,
    _secret: &[u8],
    _expiry: u64,
) -> String {
    let tx = (target_anchor % 260) as f64;
    let ty = (target_anchor.wrapping_mul(17) % 160) as f64;
    issue_html_with_target(lang, waf_token, verify_route, return_path, tx, ty)
}

pub fn issue_html_with_target(
    lang: Lang,
    waf_token: &str,
    verify_route: &str,
    return_path: &str,
    target_x: f64,
    target_y: f64,
) -> String {
    let sfx = random_js_id();
    let mut rng = rand::rng();
    let target_x = target_x.clamp(0.0, 280.0);
    let target_y = target_y.clamp(0.0, 160.0);

    let offset = rng.random_range(60.0f64..150.0);
    let left_start = target_x - offset;
    let right_start = target_x + offset;
    let left_ok = (0.0..=280.0).contains(&left_start);
    let right_ok = (0.0..=280.0).contains(&right_start);
    let handle_start = match (left_ok, right_ok) {
        (true, true) if rng.random_bool(0.5) => left_start,
        (true, true) => right_start,
        (true, false) => left_start,
        (false, true) => right_start,
        (false, false) => target_x,
    };

    let polygon = generate_puzzle_polygon(&mut rng);

    // Decoy hole: visually similar but clearly displaced (>55px away in x)
    let decoy_x: f64 = {
        let mut dx;
        loop {
            dx = rng.random_range(10.0f64..270.0);
            if (dx - target_x).abs() > 55.0 {
                break;
            }
        }
        dx
    };
    let decoy_y = (target_y + rng.random_range(-50.0f64..50.0)).clamp(0.0, 155.0);

    let (prompt, near_text) = match lang {
        Lang::ZhCn => ("拖动下方滑块对齐缺口", "快到了！"),
        Lang::En => ("Slide the handle to align the piece", "Almost there!"),
    };
    let rp_js = serde_json::to_string(return_path).unwrap_or_else(|_| "\"/\"".to_string());
    let route_js = serde_json::to_string(verify_route).unwrap_or_else(|_| "\"/\"".to_string());

    format!(
        r#"<div class="pzl" id="pzl_{sfx}" style="user-select:none">
<div class="pzl-bg" style="position:relative;width:320px;height:200px;margin:0 auto 10px;border-radius:12px;overflow:hidden">
<canvas id="bg_{sfx}" width="320" height="200" style="display:block;width:320px;height:200px"></canvas>
<div id="dc_{sfx}" style="position:absolute;left:{dx:.0}px;top:{dy:.0}px;width:40px;height:40px;clip-path:{poly};background:rgba(0,0,0,.07);box-shadow:inset 0 0 0 1.5px rgba(120,120,120,.3);pointer-events:none"></div>
<div id="hl_{sfx}" style="position:absolute;left:{tx:.0}px;top:{ty:.0}px;width:40px;height:40px;clip-path:{poly};background:rgba(0,0,0,.22);box-shadow:inset 0 0 0 2px rgba(0,0,0,.35),0 0 10px rgba(0,0,0,.2);pointer-events:none"></div>
<div id="pc_{sfx}" style="position:absolute;left:{hx:.0}px;top:{ty:.0}px;width:40px;height:40px;clip-path:{poly};background:linear-gradient(135deg,rgba(99,102,241,.9),rgba(56,189,248,.9));pointer-events:none;box-shadow:0 3px 10px rgba(0,0,0,.28)"></div>
</div>
<p class="status" id="st_{sfx}" style="margin:4px 0 8px;font-size:13px;color:var(--muted)">{prompt}</p>
<div style="position:relative;width:320px;margin:0 auto 4px;height:44px">
  <div style="position:absolute;top:50%;left:20px;right:20px;height:6px;margin-top:-3px;border-radius:3px;background:rgba(148,163,184,.25);overflow:hidden">
    <div id="fill_{sfx}" style="position:absolute;inset:0 auto 0 0;width:{hpct:.1}%;background:linear-gradient(90deg,#6366f1,#38bdf8);border-radius:3px;transition:width .02s linear"></div>
  </div>
  <div id="hd_{sfx}" style="position:absolute;top:50%;left:{hdleft:.1}px;width:36px;height:36px;margin-top:-18px;border-radius:50%;background:#fff;box-shadow:0 4px 14px rgba(0,0,0,.22);cursor:grab;display:flex;align-items:center;justify-content:center;touch-action:none">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M3 7h8M8 4l3 3-3 3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
  </div>
</div>
<script>
(function(){{
var sf="{sfx}",TARGET={tx:.1},TRACK_W=280,TRACK_LEFT=20;
var dragging=!1,startX=0,hdPos={hx:.1},tr=[],t0=Date.now();
var hd=document.getElementById('hd_'+sf),pc=document.getElementById('pc_'+sf);
var fill=document.getElementById('fill_'+sf),st=document.getElementById('st_'+sf);
var hl=document.getElementById('hl_'+sf);
function setPos(x){{
  x=Math.max(0,Math.min(TRACK_W,x));
  hdPos=x;
  hd.style.left=(TRACK_LEFT+x-18)+'px';
  fill.style.width=(x/TRACK_W*100).toFixed(1)+'%';
  pc.style.left=x+'px';
  var dist=Math.abs(x-TARGET);
  if(dist<30){{hl.style.boxShadow='inset 0 0 0 2px rgba(0,0,0,.35),0 0 16px 6px rgba(99,102,241,.7)';
    if(dist<14&&st)st.textContent='{near_text}';
  }}else{{hl.style.boxShadow='inset 0 0 0 2px rgba(0,0,0,.35),0 0 10px rgba(0,0,0,.2)'}}
}}
function start(e){{dragging=!0;hd.style.cursor='grabbing';var p=e.touches?e.touches[0]:e;startX=p.clientX-hdPos;}}
function move(e){{if(!dragging)return;e.preventDefault();var p=e.touches?e.touches[0]:e;setPos(p.clientX-startX);tr.push(Math.round(hdPos));}}
function end(){{
  if(!dragging)return;dragging=!1;hd.style.cursor='grab';
  var el=Date.now()-t0;
  var q='__waf_token={wtok}&__waf_challenge_type=slider&x='+hdPos.toFixed(1)+'&y={ty:.1}&__waf_elapsed='+el+'&__waf_trace='+encodeURIComponent(tr.join(';'))+'&__waf_return='+encodeURIComponent({rp_js});
  if(st)st.textContent=window.cloudNodeText?window.cloudNodeText('slider_verifying'):'Verifying...';
  hd.style.pointerEvents='none';
  fetch({route_js}+'?'+q,{{redirect:'manual'}}).then(function(r){{
    if(r.type==='opaqueredirect'||r.ok){{
      pc.style.transition='left .2s ease';pc.style.left=TARGET+'px';
      setTimeout(function(){{location.href={route_js}+'?'+q}},220);
    }}else{{
      if(st)st.textContent=window.cloudNodeText?window.cloudNodeText('slider_retry'):'Please try again';
      hd.style.pointerEvents='';setPos({hx:.1});tr=[];t0=Date.now();
    }}
  }}).catch(function(){{location.href={route_js}+'?'+q}});
}}
hd.addEventListener('mousedown',start);document.addEventListener('mousemove',move);document.addEventListener('mouseup',end);
hd.addEventListener('touchstart',start,{{passive:!0}});document.addEventListener('touchmove',move,{{passive:!1}});document.addEventListener('touchend',end);
(function(){{
var c=document.getElementById('bg_'+sf).getContext('2d'),w=320,h=200;
var g=c.createLinearGradient(0,0,0,h*.65);g.addColorStop(0,'#5b9bd5');g.addColorStop(1,'#c8e6f5');
c.fillStyle=g;c.fillRect(0,0,w,h*.65);
c.fillStyle='#5a8a3c';c.fillRect(0,h*.65,w,h*.35);
c.fillStyle='#4a7a2c';c.beginPath();c.moveTo(0,h*.75);c.bezierCurveTo(60,h*.5,120,h*.55,180,h*.7);c.bezierCurveTo(230,h*.6,280,h*.65,w,h*.7);c.lineTo(w,h);c.lineTo(0,h);c.fill();
c.fillStyle='#FFD700';c.beginPath();c.arc(w*.82,h*.18,16,0,Math.PI*2);c.fill();
[[70,38],[190,28],[260,45]].forEach(function(p){{[[-12,0,14],[0,-4,18],[12,0,14]].forEach(function(q){{c.fillStyle='rgba(255,255,255,.82)';c.beginPath();c.arc(p[0]+q[0],p[1]+q[1],q[2]/2,0,Math.PI*2);c.fill()}})}});
for(var i=0;i<25;i++){{c.fillStyle='rgba(255,255,255,'+(.03+Math.random()*.05)+')';c.fillRect(Math.random()*w,Math.random()*h,1+Math.random()*3,1+Math.random()*2)}}
}})();
}})();
</script>
</div>"#,
        sfx = sfx,
        tx = target_x,
        ty = target_y,
        dx = decoy_x,
        dy = decoy_y,
        hx = handle_start,
        hdleft = 20.0 + handle_start - 18.0,
        hpct = handle_start / 280.0 * 100.0,
        poly = polygon,
        prompt = prompt,
        near_text = near_text,
        wtok = waf_token,
        rp_js = rp_js,
        route_js = route_js,
    )
}

// ── Verification ─────────────────────────────────────────────────

const TOLERANCE: f64 = 8.0;
const MIN_ELAPSED_MS: u64 = 300;
const MIN_TRACE_POINTS: usize = 5;

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
    let (tx, ty) = if let (Some(x), Some(y)) = (
        p.get("tx").and_then(|v| v.as_f64()),
        p.get("ty").and_then(|v| v.as_f64()),
    ) {
        (x, y)
    } else if let (Some(x), Some(y)) = (
        p.get("cx").and_then(|v| v.as_f64()),
        p.get("cy").and_then(|v| v.as_f64()),
    ) {
        (x, y)
    } else {
        return false;
    };
    (user_x - tx).abs() <= TOLERANCE
        && (user_y - ty).abs() <= TOLERANCE
        && elapsed_ms >= MIN_ELAPSED_MS
        && verify_trace(trace)
}

// ── Helpers ──────────────────────────────────────────────────────

fn random_js_id() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    (0..8)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect()
}

fn generate_puzzle_polygon(rng: &mut impl RngExt) -> String {
    let tab_side: u8 = rng.random_range(0..4u8);
    let notch_side: u8 = (tab_side + 2) % 4;
    let tab_pos: f64 = rng.random_range(35.0f64..65.0);
    let tab_r: f64 = rng.random_range(20.0f64..28.0);

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
    let positions: Vec<f64> = trace.split(';').filter_map(|s| s.parse().ok()).collect();

    let mut moving_positions: Vec<f64> = Vec::with_capacity(positions.len());
    for x in positions {
        if moving_positions
            .last()
            .is_none_or(|last| (x - last).abs() >= 0.1)
        {
            moving_positions.push(x);
        }
    }

    if moving_positions.len() < MIN_TRACE_POINTS {
        return false;
    }

    let start = moving_positions[0];
    let end = moving_positions[moving_positions.len() - 1];
    if (end - start).abs() < 8.0 {
        return false;
    }

    let deltas: Vec<f64> = moving_positions.windows(2).map(|w| w[1] - w[0]).collect();
    let speed_var = deltas.windows(2).any(|w| {
        let prev = w[0].abs();
        let next = w[1].abs();
        let lg = prev.max(next);
        let sm = prev.min(next);
        lg > 0.1 && (lg - sm) / lg > 0.12
    });

    let has_nonmonotonic = deltas.windows(2).any(|w| w[0] * w[1] < 0.0);

    speed_var || has_nonmonotonic
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

    fn slider_token(payload: serde_json::Value) -> String {
        crate::pages::challenges::encode_challenge_token(&payload, b"slider-secret")
    }

    #[test]
    fn slider_html_uses_anchor_verification_without_explicit_token() {
        let html = issue_html(
            Lang::En,
            "waf-token",
            "/.well-known/cloud-node/waf-verify",
            "/return",
            120,
            b"slider-secret",
            future_expiry(),
        );

        assert!(html.contains("__waf_challenge_type=slider"));
        assert!(!html.contains("__waf_challenge_token="));
    }

    #[test]
    fn anchor_slider_accepts_human_like_horizontal_trace() {
        assert!(verify_anchor(
            150,
            150.0,
            150.0,
            MIN_ELAPSED_MS,
            "70;84;103;126;141;149;152;151;150",
        ));
    }

    #[test]
    fn anchor_slider_rejects_fast_or_linear_trace() {
        assert!(!verify_anchor(
            150,
            150.0,
            150.0,
            MIN_ELAPSED_MS - 1,
            "70;84;103;126;141;149;152;151;150",
        ));
        assert!(!verify_anchor(
            150,
            150.0,
            150.0,
            MIN_ELAPSED_MS,
            "70;80;90;100;110;120;130;140;150",
        ));
    }

    #[test]
    fn explicit_slider_token_verifies_type_and_coordinates() {
        let token = slider_token(json!({
            "t": "slider",
            "p": {"tx": 150.0, "ty": 51.0},
            "e": future_expiry(),
        }));

        assert!(verify_explicit(
            &token,
            150.0,
            51.0,
            MIN_ELAPSED_MS,
            "70;84;103;126;141;149;152;151;150",
            b"slider-secret",
        ));

        let wrong_type = slider_token(json!({
            "t": "captcha",
            "p": {"tx": 150.0, "ty": 51.0},
            "e": future_expiry(),
        }));
        assert!(!verify_explicit(
            &wrong_type,
            150.0,
            51.0,
            MIN_ELAPSED_MS,
            "70;84;103;126;141;149;152;151;150",
            b"slider-secret",
        ));
    }

    #[test]
    fn explicit_slider_token_accepts_legacy_center_coordinates() {
        let token = slider_token(json!({
            "t": "slider",
            "p": {"cx": 150.0, "cy": 51.0},
            "e": future_expiry(),
        }));

        assert!(verify_explicit(
            &token,
            150.0,
            51.0,
            MIN_ELAPSED_MS,
            "70;84;103;126;141;149;152;151;150",
            b"slider-secret",
        ));
    }
}
